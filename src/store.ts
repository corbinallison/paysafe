/**
 * Lightweight JSON-file-backed store. Zero dependencies.
 * Suitable for a single-instance advisory service; swap for Redis/Postgres at scale
 * (the interface is intentionally tiny).
 *
 * Hardening (audit H-3/H-4/M-1):
 *  - every unbounded Map is size-capped with oldest-first eviction, swept on a timer
 *  - nonce TTL pruning runs on the timer, NOT on the per-request hot path
 *  - reports are indexed by address so lookups are O(bucket), not O(all reports)
 *  - snapshot flush writes to a temp file then renames (atomic, no torn reads)
 */
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ReputationDispute, ReputationReport } from "./types.ts";
import type { AuditLog } from "./auditlog.ts";

/** API keys are stored hashed at rest (audit M-3): disk/backup disclosure of
 * the store never reveals a usable key. The raw key is shown once, on issue. */
export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

export interface NonceRecord {
  first_seen: string;
  times_seen: number;
  scan_id: string;
}

export interface KeyRecord {
  created_at: string;
  agent_id?: string;
  calls_used: number;
  /** Active plan id (see plans.ts); absent = starter/default tier */
  plan?: string;
  /** ISO expiry of the plan; expired plans fall back to default silently */
  plan_expires_at?: string;
  /** Aggregate verdict counts for this key's scans (dashboard stats; no PII) */
  scans?: { total: number; allow: number; flag: number; block: number };
  /** ISO timestamp of the most recent scan on this key */
  last_used_at?: string;
}

/**
 * Tombstone for a key SECRET that is no longer valid. The account (KeyRecord)
 * is the identity; the psk_ secret is just a credential pointing at it.
 * Rotation moves the record to a new hash and leaves a tombstone at the old
 * one (optionally honoring a grace window via `successor`); revocation leaves
 * a tombstone with no successor. Tombstones persist so dead keys keep failing
 * closed with an explanatory reason instead of decaying into "unknown key".
 */
export interface RevokedKeyRecord {
  revoked_at: string;
  reason: "rotated" | "revoked";
  /** Rotation only: old secret keeps resolving to the successor until this ISO time */
  grace_until?: string;
  /** Rotation only: hash the account now lives under (never a raw key) */
  successor?: string;
}

/** Result of resolving a presented API key against live keys + tombstones. */
export interface ResolvedKey {
  /** The account record, when the key (or its in-grace predecessor) is valid */
  rec: KeyRecord | null;
  /** Hash the record lives under (the successor's hash when resolved via grace) */
  hash: string | null;
  /** True when an old, rotated secret resolved through its grace window */
  viaGrace: boolean;
  /** Set when the key is dead: rotated (grace over) or revoked. Null = unknown key. */
  dead: "rotated" | "revoked" | null;
}

/** Per-key human-in-the-loop approvals config. `secret` signs outbound webhook
 * payloads (HMAC-SHA256) so the receiver can authenticate them. Storing it is
 * a DOCUMENTED EXCEPTION to keys-hashed-at-rest: it must be recoverable to
 * sign each delivery, and it grants no access to PaySafe itself. */
export interface ApprovalConfig {
  webhook_url: string;
  format: "json" | "slack";
  secret: string;
  created_at: string;
}

export interface ApprovalFacts {
  pay_to: string;
  amount?: string;
  amount_usd?: number;
  network?: string;
  asset?: string;
  resource_url?: string;
  description?: string;
  agent_id?: string;
  risk_score: number;
  fired: string[];
}

/** A pending/decided human approval for one flagged scan. token_hash is the
 * sha256 of the one-time decide token (bearer credential, delivered only via
 * the operator's webhook — never stored raw). */
export interface ApprovalRecord {
  approval_id: string;
  token_hash: string;
  key_hash: string;
  scan_id: string;
  direction: "outgoing" | "incoming";
  /** Verdict captured at creation. Decide-time asserts this is exactly "flag" —
   * approvability is never derived from mutable state. */
  original_verdict: string;
  payment_commitment: string;
  facts: ApprovalFacts;
  status: "pending" | "approved" | "denied" | "expired";
  created_at: string;
  expires_at: string;
  decided_at?: string;
  /** Scan-shaped override object (verdict "override:allow" + attestation), set on approve. */
  override?: unknown;
}

/** Rolling index of recent scans: lets an outcome report be VERIFIED against a
 * scan PaySafe actually performed (scan_id + commitment must both match), and
 * enforces one outcome per scan. Size-capped; outcomes must be reported while
 * the entry is retained. */
export interface ScanIndexEntry {
  commitment: string;
  pay_to: string; // lowercased; "" when the scan had none
  /** Resource domain at scan time (lowercased hostname). Only recorded for
   * non-blocked scans: a blocked scan (e.g. a pin mismatch claiming someone
   * else's domain) must not be able to write outcome history under that
   * domain. */
  domain?: string;
  verdict: string;
  /** Hash of the key that made the scan (absent for anonymous scans). When
   * present, only that account may report the outcome. */
  key_hash?: string;
  at: string;
  /** Consumed marker: the single outcome reported for this scan. */
  outcome?: string;
}

/** Aggregated delivery outcomes for one counterparty (keyed by pay_to). Counts
 * only commitment-bound outcomes — each corresponds to a scan we performed. */
export interface CounterpartyOutcomes {
  delivered: number;
  not_delivered: number;
  partial: number;
  wrong_content: number;
  /** Distinct reporter tokens (key hashes, or "anon"), capped — enough to
   * distinguish one noisy reporter from many independent ones. */
  reporters: string[];
  first_at: string;
  last_at: string;
}

/** Domain-joined delivery outcomes: the same counters keyed by the resource
 * domain recorded at scan time, plus the distinct pay_to addresses the history
 * was earned under. This joins the outcome ledger to the pinning layer's
 * stable identity, so rotating the pay_to address does not reset a seller's
 * delivery record (rotation-laundering resistance). */
export interface DomainOutcomes extends CounterpartyOutcomes {
  pay_tos: string[];
}

export interface VelocityEvent {
  t: number;   // epoch ms
  usd: number; // scanned payment value (0 if unknown)
}

export interface PinRecord {
  pay_to: string;
  first_seen: string;
  times_seen: number;
  /** Result of the optional async CDP Bazaar cross-check */
  cdp_status: "unchecked" | "verified" | "mismatch";
}

/** Cached ScoutScore trust rating for a merchant domain (external signal). */
export interface ScoutScoreRecord {
  /** null while unavailable (endpoint down / paid-only / parse failure) */
  score: number | null;
  level: "HIGH" | "MEDIUM" | "LOW" | "VERY_LOW" | "unavailable";
  flags: string[];
  checked_at: string;
}

interface Snapshot {
  nonces: Record<string, NonceRecord>;
  reports: ReputationReport[];
  disputes?: Record<string, ReputationDispute[]>;
  keys: Record<string, KeyRecord>;
  revoked?: Record<string, RevokedKeyRecord>;
  approval_configs?: Record<string, ApprovalConfig>;
  approvals?: Record<string, ApprovalRecord>;
  scan_index?: Record<string, ScanIndexEntry>;
  outcomes?: Record<string, CounterpartyOutcomes>;
  outcomes_by_domain?: Record<string, DomainOutcomes>;
  velocity: Record<string, VelocityEvent[]>;
  counterparties: Record<string, string[]>;
  pins: Record<string, PinRecord>;
  scout_scores?: Record<string, ScoutScoreRecord>;
}

export interface StoreLimits {
  nonceTtlHours: number;
  maxEntries: number; // per-Map cap
}

export class Store {
  nonces: Map<string, NonceRecord> = new Map();
  reports: ReputationReport[] = [];
  reportsByAddress: Map<string, ReputationReport[]> = new Map();
  /** Signed rebuttals, keyed by disputed address (verified before insert). */
  disputes: Map<string, ReputationDispute[]> = new Map();
  keys: Map<string, KeyRecord> = new Map();
  revoked: Map<string, RevokedKeyRecord> = new Map();
  approvalConfigs: Map<string, ApprovalConfig> = new Map();
  approvals: Map<string, ApprovalRecord> = new Map();
  scanIndex: Map<string, ScanIndexEntry> = new Map();
  outcomes: Map<string, CounterpartyOutcomes> = new Map();
  outcomesByDomain: Map<string, DomainOutcomes> = new Map();
  velocity: Map<string, VelocityEvent[]> = new Map();
  counterparties: Map<string, string[]> = new Map();
  pins: Map<string, PinRecord> = new Map();
  scoutScores: Map<string, ScoutScoreRecord> = new Map();
  badlist: Set<string> = new Set();

  /** Attached by the server; every scan decision is appended here. */
  auditLog: AuditLog | null = null;

  private file: string | null = null;
  private dirty = false;
  private timer: ReturnType<typeof setInterval> | null = null;
  private limits: StoreLimits = { nonceTtlHours: 24, maxEntries: 100_000 };

  /** In-memory only (tests / ephemeral) when dataDir is null. */
  constructor(dataDir: string | null, limits?: Partial<StoreLimits>) {
    if (limits) this.limits = { ...this.limits, ...limits };
    if (dataDir) {
      mkdirSync(dataDir, { recursive: true });
      this.file = join(dataDir, "paysafe-store.json");
      this.load();
      this.timer = setInterval(() => this.maintain(), 5000);
      this.timer.unref?.();
    }
  }

  private load(): void {
    if (!this.file || !existsSync(this.file)) return;
    try {
      const snap = JSON.parse(readFileSync(this.file, "utf8")) as Partial<Snapshot>;
      this.nonces = new Map(Object.entries(snap.nonces ?? {}));
      this.reports = snap.reports ?? [];
      this.disputes = new Map(Object.entries(snap.disputes ?? {}));
      this.keys = new Map(Object.entries(snap.keys ?? {}));
      this.revoked = new Map(Object.entries(snap.revoked ?? {}));
      this.approvalConfigs = new Map(Object.entries(snap.approval_configs ?? {}));
      this.approvals = new Map(Object.entries(snap.approvals ?? {}));
      this.scanIndex = new Map(Object.entries(snap.scan_index ?? {}));
      this.outcomes = new Map(Object.entries(snap.outcomes ?? {}));
      this.outcomesByDomain = new Map(Object.entries(snap.outcomes_by_domain ?? {}));
      this.velocity = new Map(Object.entries(snap.velocity ?? {}));
      this.counterparties = new Map(Object.entries(snap.counterparties ?? {}));
      this.pins = new Map(Object.entries(snap.pins ?? {}));
      this.scoutScores = new Map(Object.entries(snap.scout_scores ?? {}));
      this.reindexReports();
    } catch {
      // Corrupt snapshot: start fresh rather than crash an advisory service.
    }
  }

  private reindexReports(): void {
    this.reportsByAddress = new Map();
    for (const r of this.reports) {
      const list = this.reportsByAddress.get(r.address) ?? [];
      list.push(r);
      this.reportsByAddress.set(r.address, list);
    }
  }

  /** Load a JSON array of known-bad addresses. Missing file = empty list. */
  loadBadlist(path: string): number {
    try {
      if (!existsSync(path)) return 0;
      const arr = JSON.parse(readFileSync(path, "utf8"));
      if (Array.isArray(arr)) {
        this.badlist = new Set(arr.filter((a) => typeof a === "string").map((a) => a.toLowerCase()));
      }
      return this.badlist.size;
    } catch {
      return 0;
    }
  }

  markDirty(): void {
    this.dirty = true;
  }

  /**
   * Resolve a presented API key to its account. Single source of truth for
   * key auth: live keys first, then tombstones. A rotated secret inside its
   * grace window resolves to the successor's record (same account — usage,
   * free quota, and plan carry over), marked viaGrace so security-sensitive
   * operations (rotate/revoke/admin) can refuse it: a leaked OLD secret must
   * never be able to take over the account during grace.
   */
  resolveKey(raw: string | undefined): ResolvedKey {
    const none: ResolvedKey = { rec: null, hash: null, viaGrace: false, dead: null };
    if (!raw) return none;
    const h = hashApiKey(raw);
    const rec = this.keys.get(h);
    if (rec) return { rec, hash: h, viaGrace: false, dead: null };
    const tomb = this.revoked.get(h);
    if (!tomb) return none;
    if (
      tomb.reason === "rotated" &&
      tomb.successor &&
      tomb.grace_until &&
      Date.parse(tomb.grace_until) > Date.now()
    ) {
      const successor = this.keys.get(tomb.successor);
      // One hop only: if the successor was itself rotated/revoked, the old
      // secret is dead — grace never chains through multiple rotations.
      if (successor) return { rec: successor, hash: tomb.successor, viaGrace: true, dead: null };
    }
    return { ...none, dead: tomb.reason };
  }

  /** Timer job: prune, cap, flush. Keeps all of this off the request path. */
  private maintain(): void {
    this.pruneNonces(this.limits.nonceTtlHours);
    this.pruneApprovals();
    this.capMaps(this.limits.maxEntries);
    this.flush();
  }

  /** Timer job: expire overdue pending approvals; drop decided/expired records
   * after 24h (long past both the pending TTL and the override TTL). */
  pruneApprovals(): void {
    const now = Date.now();
    let changed = false;
    for (const [id, a] of this.approvals) {
      if (a.status === "pending" && Date.parse(a.expires_at) <= now) {
        a.status = "expired";
        changed = true;
      }
      if (a.status !== "pending" && now - Date.parse(a.created_at) > 24 * 3600_000) {
        this.approvals.delete(id);
        changed = true;
      }
    }
    if (changed) this.markDirty();
  }

  private static evict<K, V>(map: Map<K, V>, max: number): void {
    if (map.size <= max) return;
    let toRemove = map.size - max;
    for (const k of map.keys()) {
      if (toRemove-- <= 0) break;
      map.delete(k); // Maps iterate in insertion order → oldest first
    }
  }

  /** Bound every attacker-keyable Map so no client can exhaust memory/disk. */
  capMaps(max: number): void {
    Store.evict(this.nonces, max);
    Store.evict(this.velocity, max);
    Store.evict(this.counterparties, max);
    Store.evict(this.pins, max);
    Store.evict(this.scoutScores, max);
    Store.evict(this.keys, max);
    Store.evict(this.revoked, max);
    Store.evict(this.approvalConfigs, max);
    Store.evict(this.scanIndex, max);
    Store.evict(this.outcomes, max);
    Store.evict(this.outcomesByDomain, max);
    Store.evict(this.disputes, max);
    // approvals are NOT evicted here: dropping an in-flight approval would
    // orphan a legitimately-approved override. Creation refuses when full
    // (fail-closed) and pruneApprovals() expires stale pendings on the timer.
    if (this.reports.length > max) {
      this.reports = this.reports.slice(this.reports.length - max);
      this.reindexReports();
    }
    this.markDirty();
  }

  flush(): void {
    if (!this.file || !this.dirty) return;
    const snap: Snapshot = {
      nonces: Object.fromEntries(this.nonces),
      reports: this.reports,
      disputes: Object.fromEntries(this.disputes),
      keys: Object.fromEntries(this.keys),
      revoked: Object.fromEntries(this.revoked),
      approval_configs: Object.fromEntries(this.approvalConfigs),
      approvals: Object.fromEntries(this.approvals),
      scan_index: Object.fromEntries(this.scanIndex),
      outcomes: Object.fromEntries(this.outcomes),
      outcomes_by_domain: Object.fromEntries(this.outcomesByDomain),
      velocity: Object.fromEntries(this.velocity),
      counterparties: Object.fromEntries(this.counterparties),
      pins: Object.fromEntries(this.pins),
      scout_scores: Object.fromEntries(this.scoutScores),
    };
    try {
      const tmp = `${this.file}.tmp`;
      writeFileSync(tmp, JSON.stringify(snap));
      renameSync(tmp, this.file); // atomic replace
      this.dirty = false;
    } catch {
      // best-effort persistence
    }
  }

  /** Remove nonce records older than ttlHours. Called on the timer. */
  pruneNonces(ttlHours: number): void {
    const cutoff = Date.now() - ttlHours * 3600_000;
    let changed = false;
    for (const [k, v] of this.nonces) {
      if (Date.parse(v.first_seen) < cutoff) {
        this.nonces.delete(k);
        changed = true;
      }
    }
    if (changed) this.markDirty();
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.flush();
  }
}

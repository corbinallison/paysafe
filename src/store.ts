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
import type { ReputationReport } from "./types.ts";
import type { AuditLog } from "./auditlog.ts";

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

interface Snapshot {
  nonces: Record<string, NonceRecord>;
  reports: ReputationReport[];
  keys: Record<string, KeyRecord>;
  velocity: Record<string, VelocityEvent[]>;
  counterparties: Record<string, string[]>;
  pins: Record<string, PinRecord>;
}

export interface StoreLimits {
  nonceTtlHours: number;
  maxEntries: number; // per-Map cap
}

export class Store {
  nonces: Map<string, NonceRecord> = new Map();
  reports: ReputationReport[] = [];
  reportsByAddress: Map<string, ReputationReport[]> = new Map();
  keys: Map<string, KeyRecord> = new Map();
  velocity: Map<string, VelocityEvent[]> = new Map();
  counterparties: Map<string, string[]> = new Map();
  pins: Map<string, PinRecord> = new Map();
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
      this.keys = new Map(Object.entries(snap.keys ?? {}));
      this.velocity = new Map(Object.entries(snap.velocity ?? {}));
      this.counterparties = new Map(Object.entries(snap.counterparties ?? {}));
      this.pins = new Map(Object.entries(snap.pins ?? {}));
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

  /** Timer job: prune, cap, flush. Keeps all of this off the request path. */
  private maintain(): void {
    this.pruneNonces(this.limits.nonceTtlHours);
    this.capMaps(this.limits.maxEntries);
    this.flush();
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
    Store.evict(this.keys, max);
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
      keys: Object.fromEntries(this.keys),
      velocity: Object.fromEntries(this.velocity),
      counterparties: Object.fromEntries(this.counterparties),
      pins: Object.fromEntries(this.pins),
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

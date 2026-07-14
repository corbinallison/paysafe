/**
 * Lightweight JSON-file-backed store. Zero dependencies.
 * Suitable for a single-instance advisory service; swap for Redis/Postgres at scale
 * (the interface is intentionally tiny).
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { ReputationReport } from "./types.ts";

export interface NonceRecord {
  first_seen: string;
  times_seen: number;
  scan_id: string;
}

export interface KeyRecord {
  created_at: string;
  agent_id?: string;
  calls_used: number;
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

export class Store {
  nonces: Map<string, NonceRecord> = new Map();
  reports: ReputationReport[] = [];
  keys: Map<string, KeyRecord> = new Map();
  /** agent key -> recent scan events (sliding windows for rate/spend caps) */
  velocity: Map<string, VelocityEvent[]> = new Map();
  /** agent key -> counterparty addresses it has paid before */
  counterparties: Map<string, string[]> = new Map();
  /** resource domain -> pinned pay_to (TOFU) */
  pins: Map<string, PinRecord> = new Map();
  /** known-bad addresses (loaded from badlist file; not part of the snapshot) */
  badlist: Set<string> = new Set();

  private file: string | null = null;
  private dirty = false;
  private timer: ReturnType<typeof setInterval> | null = null;

  /** In-memory only (tests / ephemeral) when dataDir is null. */
  constructor(dataDir: string | null) {
    if (dataDir) {
      mkdirSync(dataDir, { recursive: true });
      this.file = join(dataDir, "paysafe-store.json");
      this.load();
      this.timer = setInterval(() => this.flush(), 5000);
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
    } catch {
      // Corrupt snapshot: start fresh rather than crash an advisory service.
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
      writeFileSync(this.file, JSON.stringify(snap));
      this.dirty = false;
    } catch {
      // best-effort persistence
    }
  }

  /** Remove nonce records older than ttlHours. */
  pruneNonces(ttlHours: number): void {
    const cutoff = Date.now() - ttlHours * 3600_000;
    for (const [k, v] of this.nonces) {
      if (Date.parse(v.first_seen) < cutoff) this.nonces.delete(k);
    }
    this.markDirty();
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.flush();
  }
}

/**
 * Tamper-evident audit log of scan DECISIONS (not funds — PaySafe is
 * non-custodial and never moves money).
 *
 * Design goals:
 *  - Append-only JSONL, one record per scan.
 *  - Hash-chained: each record embeds the previous record's hash, so any
 *    edit, reordering, or deletion breaks the chain and is detectable.
 *  - No PII/secrets: the payment is represented only by its SHA-256 digest
 *    (see commitment.ts), never the plaintext description/reason/metadata.
 *  - Cheap to write (single synchronous append) and constant-memory
 *    (only the last hash + sequence number are held in memory).
 *
 * This gives defensible retention for dispute/regulatory review. For strong
 * legal non-repudiation, ship the file to WORM storage (e.g. S3 Object Lock)
 * and/or periodically anchor the head hash externally — see SECURITY-AUDIT.md.
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Direction, Verdict } from "./types.ts";

export interface AuditRecord {
  seq: number;
  ts: string;
  scan_id: string;
  direction: Direction;
  verdict: Verdict;
  risk_score: number;
  /** caller-supplied identifier (not authenticated) */
  agent_id?: string;
  /** SHA-256 of the full payment — proves what was scanned without storing it */
  payment_sha256: string;
  /** non-sensitive transaction facts, useful for audit queries */
  network?: string;
  pay_to?: string;
  amount_usd?: number | null;
  /** ids of checks that did not return "allow" */
  fired: string[];
  /** hex signature of the verdict attestation, if signing is enabled */
  attestation_sig?: string;
  prev_hash: string;
  entry_hash: string;
}

const GENESIS = "0".repeat(64);

function hashEntry(entryWithoutHash: Omit<AuditRecord, "entry_hash">): string {
  return createHash("sha256")
    .update(JSON.stringify(entryWithoutHash), "utf8")
    .digest("hex");
}

export class AuditLog {
  private file: string | null;
  private seq = 0;
  private lastHash = GENESIS;
  /** in-memory mirror only when there is no file (tests) */
  private mem: AuditRecord[] = [];

  constructor(file: string | null) {
    this.file = file;
    if (file) {
      mkdirSync(dirname(file), { recursive: true });
      if (existsSync(file)) this.resume(file);
    }
  }

  private resume(file: string): void {
    try {
      const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
      if (lines.length === 0) return;
      const last = JSON.parse(lines[lines.length - 1]) as AuditRecord;
      this.seq = last.seq;
      this.lastHash = last.entry_hash;
    } catch {
      // Unreadable tail: leave seq/lastHash at defaults. verify() will report.
    }
  }

  append(rec: Omit<AuditRecord, "seq" | "prev_hash" | "entry_hash">): AuditRecord {
    const base: Omit<AuditRecord, "entry_hash"> = {
      ...rec,
      seq: this.seq + 1,
      prev_hash: this.lastHash,
    };
    const entry_hash = hashEntry(base);
    const full: AuditRecord = { ...base, entry_hash };
    if (this.file) appendFileSync(this.file, JSON.stringify(full) + "\n");
    else this.mem.push(full);
    this.seq = full.seq;
    this.lastHash = entry_hash;
    return full;
  }

  /** Head hash — anchor this externally for strong non-repudiation. */
  head(): { seq: number; hash: string } {
    return { seq: this.seq, hash: this.lastHash };
  }

  /** Raw NDJSON export of the full log, for offsite/WORM backup. Auth is the API layer's job. */
  exportRaw(): string {
    if (!this.file) return this.mem.map((r) => JSON.stringify(r)).join("\n") + (this.mem.length ? "\n" : "");
    if (!existsSync(this.file)) return "";
    return readFileSync(this.file, "utf8");
  }

  private records(): AuditRecord[] {
    if (!this.file) return this.mem;
    if (!existsSync(this.file)) return [];
    return readFileSync(this.file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as AuditRecord);
  }

  /** Recompute the whole chain; returns the first break (if any). */
  verify(): { ok: boolean; count: number; brokenAt?: number; reason?: string } {
    const recs = this.records();
    let prev = GENESIS;
    for (let i = 0; i < recs.length; i++) {
      const r = recs[i];
      if (r.seq !== i + 1) {
        return { ok: false, count: recs.length, brokenAt: i + 1, reason: `seq mismatch (expected ${i + 1}, got ${r.seq})` };
      }
      if (r.prev_hash !== prev) {
        return { ok: false, count: recs.length, brokenAt: r.seq, reason: "prev_hash does not match previous entry" };
      }
      const { entry_hash, ...rest } = r;
      if (hashEntry(rest) !== entry_hash) {
        return { ok: false, count: recs.length, brokenAt: r.seq, reason: "entry_hash does not match content (record was altered)" };
      }
      prev = entry_hash;
    }
    return { ok: true, count: recs.length };
  }
}

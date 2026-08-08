// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
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
  /**
   * Approval-decision records only: ms between the approval's creation and
   * the human decision. Both timestamps are server-stamped. Omitted (never
   * null) on scan records and on decisions with an unusable created_at, so
   * existing record shapes and their entry hashes are untouched.
   */
  approval_latency_ms?: number;
  /**
   * Set (and only set) when the scanning key is operator-owned. Absent means
   * third-party. Written from the resolved KeyRecord at scan time, never from
   * request input. Omitted rather than written false so existing records and
   * their entry hashes are untouched.
   */
  first_party?: boolean;
  prev_hash: string;
  entry_hash: string;
}

/** All-time aggregates derived from the audit log (owner dashboard). */
export interface AuditStats {
  count: number;
  by_verdict: { allow: number; flag: number; block: number };
  by_direction: { outgoing: number; incoming: number };
  first_ts: string | null;
  last_ts: string | null;
  /** Per-UTC-day scan counts for the most recent N days, zero-filled. */
  daily: Array<{ date: string; total: number; block: number }>;
  /** Most frequently fired check ids, descending. */
  top_checks: Array<{ id: string; count: number }>;
  distinct_agents: number;
  /** Sum of scanned payment values (USD) where the amount was known. */
  total_scanned_usd: number;
  /**
   * The operator's own share of the numbers above, so a caller can subtract it.
   * Agent sets are counted separately rather than by subtraction, because
   * agent_id is caller-supplied and the same string can appear on both sides.
   */
  first_party: {
    count: number;
    by_verdict: { allow: number; flag: number; block: number };
    distinct_agents: number;
  };
  /** Distinct caller-supplied agent_id values seen. Owner and internal use
   * only. Public stats lift numbers derived from this list, never the list. */
  agent_ids: string[];
  third_party: {
    count: number;
    by_verdict: { allow: number; flag: number; block: number };
    distinct_agents: number;
  };
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

  /**
   * All-time aggregates for the owner dashboard. Derived from the full log,
   * so it covers every scan ever recorded — including anonymous (keyless)
   * scans that the per-key counters can't attribute. Aggregates only: no
   * agent ids, addresses, or payment digests leave this method.
   */
  stats(days = 30): AuditStats {
    const recs = this.records();
    const by_verdict = { allow: 0, flag: 0, block: 0 };
    const by_direction = { outgoing: 0, incoming: 0 };
    const checkCounts = new Map<string, number>();
    const agents = new Set<string>();
    const fpAgents = new Set<string>();
    const tpAgents = new Set<string>();
    const fp = { count: 0, by_verdict: { allow: 0, flag: 0, block: 0 } };
    const tp = { count: 0, by_verdict: { allow: 0, flag: 0, block: 0 } };
    const dayTotals = new Map<string, { total: number; block: number }>();
    let total_scanned_usd = 0;
    for (const r of recs) {
      if (r.verdict in by_verdict) by_verdict[r.verdict] += 1;
      if (r.direction in by_direction) by_direction[r.direction] += 1;
      for (const id of r.fired) checkCounts.set(id, (checkCounts.get(id) ?? 0) + 1);
      if (r.agent_id) agents.add(r.agent_id);
      const side = r.first_party ? fp : tp;
      side.count += 1;
      if (r.verdict in side.by_verdict) side.by_verdict[r.verdict] += 1;
      if (r.agent_id) (r.first_party ? fpAgents : tpAgents).add(r.agent_id);
      if (typeof r.amount_usd === "number" && Number.isFinite(r.amount_usd)) total_scanned_usd += r.amount_usd;
      const day = r.ts.slice(0, 10);
      const d = dayTotals.get(day) ?? { total: 0, block: 0 };
      d.total += 1;
      if (r.verdict === "block") d.block += 1;
      dayTotals.set(day, d);
    }
    // Last `days` UTC days including today, zero-filled so charts are gapless.
    const daily: Array<{ date: string; total: number; block: number }> = [];
    const today = Date.now();
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(today - i * 86400_000).toISOString().slice(0, 10);
      const d = dayTotals.get(date) ?? { total: 0, block: 0 };
      daily.push({ date, total: d.total, block: d.block });
    }
    const top_checks = [...checkCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([id, count]) => ({ id, count }));
    return {
      count: recs.length,
      by_verdict,
      by_direction,
      first_ts: recs.length ? recs[0].ts : null,
      last_ts: recs.length ? recs[recs.length - 1].ts : null,
      daily,
      top_checks,
      distinct_agents: agents.size,
      total_scanned_usd: Number(total_scanned_usd.toFixed(2)),
      agent_ids: [...agents].sort(),
      first_party: { ...fp, distinct_agents: fpAgents.size },
      third_party: { ...tp, distinct_agents: tpAgents.size },
    };
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

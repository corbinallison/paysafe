// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Counterparty reputation v2: shared post-hoc reporting + lookup, with
 * fairness & abuse-resistance weighting. Purely observational — a report
 * registry, not a trust score.
 *
 * SECURITY NOTE (audit H-2): reporter_agent_id is self-asserted and
 * unauthenticated, so the registry is inherently spoofable. Therefore an
 * unverified report set NEVER produces a hard "block" inside a scan — the
 * worst it yields is "flag". Hard blocks come only from the operator-curated
 * badlist. Reports are a signal for humans/agents to weigh, not a kill switch.
 *
 * v2 weighting — risk grades on `weighted_score`, not raw reporter counts:
 *   weight(reporter) = credibility(reporter) × decay(newest report age)
 *   - decay: 2^(-age/90d) half-life, so a wallet's old mistakes fade; below
 *     0.1 total the risk reads "none" (status stays "reported" for auditors).
 *   - credibility: 0.5 for a fresh anonymous reporter_agent_id, rising to 1.0
 *     with observed payment history (distinct counterparties this agent has
 *     actually been seen paying in scans). Sybil-minted fresh ids therefore
 *     count HALF, while five of them still grade high (2.5) — the v1 ladder
 *     (1 / 2 / 5 fresh reporters → low / medium / high) is preserved exactly.
 *     Credibility only scales flag confidence; it can never create a block.
 *
 * v2 disputes: a reported wallet can attach a signed rebuttal. Ownership is
 * proven by an EIP-191 personal_sign signature over the canonical dispute
 * message (below) that must recover to the disputed address. Disputes are
 * surfaced alongside reports — they never mechanically lower risk, because a
 * scammer can sign a rebuttal as easily as an honest seller; agents and
 * humans weigh both sides.
 */
import type { CheckResult, ReportCategory, ReputationDispute, ReputationReport, ReputationSummary } from "./types.ts";
import type { Store } from "./store.ts";
import { deliverySummary } from "./outcomes.ts";
import { verifyPersonalSign } from "./evmsig.ts";

const HALF_LIFE_DAYS = 90;
/** Total weighted mass below this reads as risk "none" (decayed to noise). */
const NOISE_FLOOR = 0.1;
/** Risk ladder over weighted_score — calibrated so N fresh anonymous
 * reporters grade exactly as N distinct reporters did in v1. */
const HIGH_AT = 2.5;
const MEDIUM_AT = 1.0;

const MAX_DISPUTES_PER_ADDRESS = 5;

const CATEGORIES: ReportCategory[] = [
  "scam", "non_delivery", "prompt_injection", "overcharge", "impersonation", "replay_abuse", "other",
];

export function isValidCategory(c: string): c is ReportCategory {
  return (CATEGORIES as string[]).includes(c);
}

export function addReport(
  store: Store,
  input: { address: string; category: string; reason: string; reporter_agent_id: string; evidence_url?: string },
): { ok: true; report: ReputationReport } | { ok: false; error: string } {
  const address = input.address?.trim().toLowerCase();
  if (!address || address.length < 6) return { ok: false, error: "address is required" };
  if (!isValidCategory(input.category)) {
    return { ok: false, error: `category must be one of: ${CATEGORIES.join(", ")}` };
  }
  if (!input.reporter_agent_id) return { ok: false, error: "reporter_agent_id is required" };
  if (!input.reason || input.reason.length < 10) {
    return { ok: false, error: "reason must be at least 10 characters" };
  }

  const existing = store.reportsByAddress.get(address) ?? [];

  // One report per (reporter, address, category) — dedup against the
  // per-address bucket (O(bucket), not O(all reports)).
  const dup = existing.find(
    (r) => r.category === input.category && r.reporter_agent_id === input.reporter_agent_id,
  );
  if (dup) return { ok: true, report: dup };

  const report: ReputationReport = {
    address,
    category: input.category,
    reason: input.reason.slice(0, 1000),
    reporter_agent_id: input.reporter_agent_id.slice(0, 200),
    evidence_url: input.evidence_url,
    reported_at: new Date().toISOString(),
  };
  store.reports.push(report);
  existing.push(report);
  store.reportsByAddress.set(address, existing);
  store.markDirty();
  return { ok: true, report };
}

/** 90-day half-life: 1.0 when fresh, 0.5 at 90d, ~0 after a year. */
function decay(reportedAt: string, now: number): number {
  const t = Date.parse(reportedAt);
  if (Number.isNaN(t)) return 0; // corrupt timestamp must not inflate risk
  const ageDays = Math.max(0, (now - t) / 86_400_000);
  return 2 ** (-ageDays / HALF_LIFE_DAYS);
}

/**
 * Reporter credibility ∈ [0.5, 1.0]. A fresh anonymous reporter_agent_id
 * starts at 0.5; observed payment history — distinct counterparties this
 * agent_id has been seen paying in scans (O(1) lookup) — raises it, maxing
 * at 1.0 from 10 distinct counterparties. Deliberately capped at 1.0: high
 * credibility must never let a smaller clique reach thresholds that
 * anonymous reporters couldn't (it scales confidence, it doesn't gate).
 */
function credibility(store: Store, reporterAgentId: string): number {
  const seen = store.counterparties.get(reporterAgentId)?.length ?? 0;
  return 0.5 + 0.5 * Math.min(1, seen / 10);
}

/** Sum over distinct reporters of credibility × decay of their newest report. */
export function weightedScore(store: Store, reports: ReputationReport[], now = Date.now()): number {
  const perReporter = new Map<string, number>();
  for (const r of reports) {
    const w = credibility(store, r.reporter_agent_id) * decay(r.reported_at, now);
    const prev = perReporter.get(r.reporter_agent_id) ?? 0;
    // max, not sum: one reporter filing many categories is still one voice
    if (w > prev) perReporter.set(r.reporter_agent_id, w);
  }
  let total = 0;
  for (const w of perReporter.values()) total += w;
  return total;
}

export function summarize(store: Store, addressRaw: string): ReputationSummary {
  const address = addressRaw.trim().toLowerCase();
  const reports = store.reportsByAddress.get(address) ?? [];
  const reporters = new Set(reports.map((r) => r.reporter_agent_id));
  const categories: Record<string, number> = Object.create(null);
  for (const r of reports) categories[r.category] = (categories[r.category] ?? 0) + 1;

  const score = weightedScore(store, reports);
  let risk: ReputationSummary["risk"] = "none";
  if (score >= HIGH_AT) risk = "high";
  else if (score >= MEDIUM_AT) risk = "medium";
  else if (score > NOISE_FLOOR) risk = "low";

  const times = reports.map((r) => r.reported_at).sort();
  const disputes = store.disputes.get(address);
  return {
    address,
    status: reports.length ? "reported" : "clean",
    risk,
    report_count: reports.length,
    distinct_reporters: reporters.size,
    weighted_score: Math.round(score * 100) / 100,
    categories,
    first_reported: times[0],
    last_reported: times[times.length - 1],
    ...(disputes?.length ? { disputes } : {}),
    // Measured, commitment-bound delivery history (see outcomes.ts) — a
    // categorically stronger signal than the self-asserted reports above.
    delivery: deliverySummary(store, address),
  };
}

/** Canonical message a wallet signs (EIP-191 personal_sign) to attach a
 * dispute. Binding the address into the message prevents replaying one
 * wallet's rebuttal onto another wallet's record. */
export function disputeMessage(address: string, statement: string): string {
  return `paysafe-dispute-v1|${address.trim().toLowerCase()}|${statement}`;
}

export function addDispute(
  store: Store,
  input: { address: string; statement: string; signature: string },
): { ok: true; dispute: ReputationDispute } | { ok: false; error: string } {
  const address = input.address?.trim().toLowerCase();
  if (!address || !/^0x[0-9a-f]{40}$/.test(address)) {
    return { ok: false, error: "address must be a 0x-prefixed EVM address (disputes prove key ownership, so only EVM wallets can dispute)" };
  }
  const statement = input.statement?.trim();
  if (!statement || statement.length < 10) {
    return { ok: false, error: "statement must be at least 10 characters" };
  }
  if (statement.length > 1000) {
    return { ok: false, error: "statement must be at most 1000 characters" };
  }
  if (typeof input.signature !== "string" ||
      !verifyPersonalSign(address, disputeMessage(address, statement), input.signature)) {
    return {
      ok: false,
      error: `signature must be an EIP-191 personal_sign by ${address} over: ${disputeMessage(address, "<statement>")}`,
    };
  }

  const existing = store.disputes.get(address) ?? [];
  const dup = existing.find((d) => d.statement === statement);
  if (dup) return { ok: true, dispute: dup };

  const dispute: ReputationDispute = {
    address,
    statement,
    signature: input.signature,
    disputed_at: new Date().toISOString(),
  };
  // Newest first, capped — a wallet gets a voice, not a billboard.
  const next = [dispute, ...existing].slice(0, MAX_DISPUTES_PER_ADDRESS);
  store.disputes.set(address, next);
  store.markDirty();
  return { ok: true, dispute };
}

/** Cross-check used inside scans: is the counterparty already reported? */
export function checkReputation(store: Store, payTo: string | undefined): CheckResult {
  if (!payTo) {
    return {
      id: "reputation.no_address",
      name: "Counterparty reputation",
      verdict: "allow",
      severity: "info",
      reason: "No pay_to address supplied; reputation cross-check skipped.",
    };
  }
  const s = summarize(store, payTo);
  if (s.status === "clean") {
    return {
      id: "reputation.clean",
      name: "Counterparty reputation",
      verdict: "allow",
      severity: "info",
      reason: `No reports on record for ${payTo}.`,
    };
  }
  // Time decay in action: reports exist but their weighted mass has faded to
  // noise (90-day half-life). Old mistakes don't flag a wallet forever.
  if (s.risk === "none") {
    return {
      id: "reputation.decayed",
      name: "Counterparty reputation",
      verdict: "allow",
      severity: "info",
      reason: `Counterparty ${payTo} has ${s.report_count} old report(s) whose weight has decayed below the risk floor (last reported ${s.last_reported}). History remains visible at the reputation lookup.`,
      details: { ...s },
    };
  }
  // Unverified reports cap out at "flag" (never "block"): a spoofable registry
  // must not be able to hard-block an honest counterparty. Higher weighted
  // report mass raises severity but not the verdict.
  const severity = s.risk === "high" ? "high" : s.risk === "medium" ? "medium" : "low";
  const disputeNote = s.disputes?.length
    ? ` The wallet has attached ${s.disputes.length} signed rebuttal(s) — weigh both sides via the reputation lookup.`
    : "";
  return {
    id: "reputation.reported",
    name: "Counterparty reputation",
    verdict: "flag",
    severity,
    reason: `Counterparty ${payTo} has ${s.report_count} unverified report(s) from ${s.distinct_reporters} distinct reporter(s) (weighted score ${s.weighted_score}): ${Object.entries(s.categories).map(([k, v]) => `${k}×${v}`).join(", ")}. Reports are self-asserted — verify out-of-band before deciding.${disputeNote}`,
    details: { ...s },
  };
}

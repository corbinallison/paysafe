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
import type { CheckResult, InjectionIncident, ReportCategory, ReputationDispute, ReputationReport, ReputationSummary, ScanRequest } from "./types.ts";
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

  // Grade on the 2-decimal score we report, not the raw float. The ladder is
  // calibrated on exact fresh-reporter masses (5 × 0.5 = 2.5 = HIGH_AT), and
  // milliseconds of decay between filing and lookup would otherwise land the
  // sum at 2.4999… and read as a lower grade — the displayed weighted_score
  // must never contradict the risk it graded to.
  const score = Math.round(weightedScore(store, reports) * 100) / 100;
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
    weighted_score: score,
    categories,
    first_reported: times[0],
    last_reported: times[times.length - 1],
    ...(disputes?.length ? { disputes } : {}),
    // System-observed: scans PaySafe itself blocked with this address
    // structurally implicated. Distinct from (and stronger than) the
    // self-asserted reports above, but still input-spoofable — flag-only.
    injection_history: injectionHistorySummary(store, address),
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

// ---------------------------------------------------------------------------
// Injection-incident ledger: detections feed the registry
// ---------------------------------------------------------------------------
//
// When a scan BLOCKS with a finding that structurally implicates an address
// (details.implicated_address — set only where the finding binds the address
// to attacker-authored content, never for mere tells), the address is recorded
// here automatically. One agent's detection becomes network-wide protection:
// the next scan of the same wallet flags it even with no content in context.
//
// Threat model (audit H-2 extended): scan inputs are client-supplied, so a
// Sybil can stage scans implicating an honest wallet — exactly as cheaply as
// filing fake reports. Incidents therefore reuse the same defenses: one voice
// per observer, credibility × 90-day decay weighting, and a hard cap at
// "flag" in scan verdicts. No new attack surface, strictly more coverage.

const MAX_INCIDENTS_PER_ADDRESS = 100;
/** EVM address or base58 (Solana-style) — same shapes the detectors emit. */
const IMPLICATED_SHAPE = /^0x[0-9a-f]{40}$|^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

/**
 * Harvest implicated addresses from a BLOCKED scan's findings into the ledger.
 * Call only after aggregation decided "block"; per-check filtering below still
 * requires the individual check to be a block (a flag-severity lookalike in
 * trusted-origin content must not seed incidents).
 */
export function recordInjectionIncidents(
  store: Store,
  req: ScanRequest,
  scanId: string,
  checks: CheckResult[],
): void {
  const observer = req.agent_id ?? req.payment.payer?.toLowerCase() ?? "anon";
  let changed = false;
  for (const c of checks) {
    if (c.verdict !== "block") continue;
    const raw = c.details?.implicated_address;
    if (typeof raw !== "string") continue;
    const address = raw.trim().toLowerCase();
    if (!IMPLICATED_SHAPE.test(address)) continue;
    const existing = store.injectionIncidents.get(address) ?? [];
    // One voice per (observer, address) — a single agent re-scanning the same
    // attack N times is one incident, not N (mirrors report dedup).
    if (existing.some((i) => i.observer === observer)) continue;
    const incident: InjectionIncident = {
      address,
      check_id: c.id,
      origin: req.context?.origin ?? "unknown",
      observer: observer.slice(0, 200),
      scan_id: scanId,
      at: new Date().toISOString(),
    };
    store.injectionIncidents.set(address, [...existing, incident].slice(-MAX_INCIDENTS_PER_ADDRESS));
    changed = true;
  }
  if (changed) store.markDirty();
}

/** Weighted incident history for one address; null when none recorded. */
export function injectionHistorySummary(
  store: Store,
  addressRaw: string,
  now = Date.now(),
): ReputationSummary["injection_history"] {
  const incidents = store.injectionIncidents.get(addressRaw.trim().toLowerCase());
  if (!incidents?.length) return null;
  // Same shape as weightedScore over reports: per-observer credibility × decay.
  const perObserver = new Map<string, number>();
  const checkIds: Record<string, number> = Object.create(null);
  for (const i of incidents) {
    checkIds[i.check_id] = (checkIds[i.check_id] ?? 0) + 1;
    const w = credibility(store, i.observer) * decay(i.at, now);
    const prev = perObserver.get(i.observer) ?? 0;
    if (w > prev) perObserver.set(i.observer, w);
  }
  let total = 0;
  for (const w of perObserver.values()) total += w;
  const times = incidents.map((i) => i.at).sort();
  return {
    incident_count: incidents.length,
    distinct_observers: perObserver.size,
    weighted_score: Math.round(total * 100) / 100,
    check_ids: checkIds,
    first_at: times[0],
    last_at: times[times.length - 1],
  };
}

/**
 * Scan-time cross-check: was this counterparty previously implicated in a
 * blocked injection scan? Flag-only — see the threat model above. Ladder:
 * one fresh anonymous observer (0.5) already reads medium, because "PaySafe
 * itself blocked a payment where this wallet was planted via injection" is a
 * stronger statement than one self-asserted report; ≥1.0 (two observers, or
 * one with payment history) reads high.
 */
export function checkInjectionHistory(store: Store, payTo: string | undefined): CheckResult | null {
  if (!payTo) return null;
  const h = injectionHistorySummary(store, payTo);
  if (!h || h.weighted_score <= NOISE_FLOOR) return null; // decayed to noise — history stays in lookups
  const severity = h.weighted_score >= 1.0 ? "high" : h.weighted_score >= 0.5 ? "medium" : "low";
  return {
    id: "reputation.injection_history",
    name: "Counterparty injection history",
    verdict: "flag",
    severity,
    reason:
      `Counterparty ${payTo} was structurally implicated in ${h.incident_count} previously BLOCKED scan(s) ` +
      `observed by ${h.distinct_observers} distinct agent(s) (weighted score ${h.weighted_score}, last ${h.last_at}): ` +
      `${Object.entries(h.check_ids).map(([k, v]) => `${k}×${v}`).join(", ")}. ` +
      `This history comes from PaySafe's own blocking verdicts, but scan inputs are client-supplied — treat it as a strong caution and verify the counterparty out-of-band.`,
    details: { ...h, address: payTo.trim().toLowerCase() },
  };
}

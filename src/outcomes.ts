// Copyright (c) 2026 Tollwarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Delivery-outcome ledger — the feedback loop the scan layer can't provide.
 *
 * Every scan check validates the PAYMENT (well-formed, un-manipulated). None
 * of them can tell you the seller will actually deliver — a perfectly clean
 * payment to a seller who never ships still fails the agent. This module adds
 * that leg as measured outcomes rather than accusations:
 *
 *  - POST /v1/outcomes records the result of a settled payment: delivered /
 *    not_delivered / partial / wrong_content, with mechanical evidence
 *    (status, content type, bytes). x402 delivery is usually SYNCHRONOUS —
 *    the resource arrives in the paid response — so the SDK payment-path
 *    wrappers capture this automatically, the same way they auto-tag
 *    provenance.
 *  - Every outcome is BOUND to a scan Tollwarden actually performed: the report
 *    must present the (scan_id, payment_commitment) pair from a real scan,
 *    verified against the rolling scan index, one outcome per scan, and (for
 *    keyed scans) only from the account that made the scan. Fabricating
 *    delivery history therefore requires making real, scanned payments —
 *    an anti-Sybil property free-text reports can't have.
 *  - Aggregates key off the pay_to RECORDED AT SCAN TIME (from the index),
 *    never the reporter's claim — and, in parallel, off the resource DOMAIN
 *    recorded at scan time. The domain ledger joins the outcome history to the
 *    pinning layer's stable identity, so rotating the pay_to address cannot
 *    launder a bad delivery record (the fresh wallet's empty ledger is
 *    backstopped by the domain's).
 *  - Flag decisions use a PRIOR-SMOOTHED delivery rate (Beta prior, mean 0.9,
 *    strength 10 pseudo-outcomes): 3 failures out of 3 and 300 out of 300 are
 *    very different confidence, and the smoothed rate says so. The raw rate is
 *    always reported alongside.
 *
 * Verdict integration preserves audit H-2: delivery history can only ever
 * FLAG, never block — third-party history must not stop an honest payment on
 * its own. Positive outcomes contextualize but never erase negative reports.
 *
 * Honest limits: this measures that content ARRIVED (mechanically), not that
 * it was good — quality judgments stay with POST /v1/reputation/report. And
 * it covers digital, synchronous x402 delivery, not physical shipment.
 */
import type { TollwardenConfig } from "./config.ts";
import type { CounterpartyOutcomes, DomainOutcomes, Store } from "./store.ts";
import type { ApiResult } from "./api.ts";
import type { CheckResult, PaymentDetails } from "./types.ts";

export const OUTCOME_KINDS = ["delivered", "not_delivered", "partial", "wrong_content"] as const;
export type OutcomeKind = (typeof OUTCOME_KINDS)[number];

const MAX_DISTINCT_REPORTERS = 50;
const MAX_LINKED_PAY_TOS = 20;

/** Defaults for the small-sample prior (config-overridable). Shared with
 * deliverySummary so display and scan checks agree when cfg isn't threaded. */
export const DELIVERY_PRIOR_RATE = 0.9;
export const DELIVERY_PRIOR_STRENGTH = 10;

/** Posterior-mean delivery rate under a Beta(p0·m, (1−p0)·m) prior: the rate
 * starts at the prior mean p0 and needs real evidence to move — 3 failures on
 * 3 outcomes is jumpy noise, 300 on 300 is a verdict. The raw rate is always
 * reported alongside; only the FLAG DECISION uses the smoothed value. */
function smoothedRate(delivered: number, total: number, cfg?: TollwardenConfig): number {
  const m = cfg?.deliveryPriorStrength ?? DELIVERY_PRIOR_STRENGTH;
  const p0 = cfg?.deliveryPriorRate ?? DELIVERY_PRIOR_RATE;
  return (delivered + p0 * m) / (total + m);
}

/** Uniform failure: unknown scan, commitment mismatch, and wrong account are
 * indistinguishable — the (scan_id, commitment) pair is a bearer proof of
 * having seen the scan, and this endpoint must not help brute-force either. */
const NOT_FOUND: ApiResult = { status: 404, body: { error: "Unknown scan or commitment mismatch." } };

/**
 * POST /v1/outcomes — record the delivery outcome of a scanned payment.
 * Free (rate-limited per IP at the route layer).
 */
export function handleOutcomeReport(store: Store, cfg: TollwardenConfig, apiKey: string | undefined, body: unknown): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const scanId = typeof b.scan_id === "string" ? b.scan_id : "";
  const commitment = typeof b.payment_commitment === "string" ? b.payment_commitment.toLowerCase() : "";
  const outcome = typeof b.outcome === "string" && (OUTCOME_KINDS as readonly string[]).includes(b.outcome) ? (b.outcome as OutcomeKind) : null;
  if (!outcome) {
    return { status: 400, body: { error: `outcome must be one of: ${OUTCOME_KINDS.join(", ")}` } };
  }

  const entry = scanId ? store.scanIndex.get(scanId) : undefined;
  if (!entry || entry.commitment !== commitment) return NOT_FOUND;
  if (entry.key_hash) {
    // Keyed scan: only the account that made it may report its outcome.
    const { hash } = store.resolveKey(apiKey);
    if (hash !== entry.key_hash) return NOT_FOUND;
  }

  // One outcome per scan: repeating the same outcome is idempotent; changing
  // a recorded outcome is refused (first report wins).
  if (entry.outcome) {
    if (entry.outcome === outcome) {
      return { status: 200, body: { recorded: true, scan_id: scanId, outcome, idempotent: true } };
    }
    return { status: 409, body: { error: `An outcome (${entry.outcome}) is already recorded for this scan; outcomes are final.` } };
  }

  entry.outcome = outcome;
  const now = new Date().toISOString();
  const reporter = entry.key_hash ?? "anon";

  // Approval-pairing: if this scan's flag went through a human decision, stamp
  // the delivery outcome onto that decision's telemetry ring entry. Recording
  // happens AFTER the decision (never influences it) — the pairing is what
  // separates "fast approvals because the operator got calibrated" from "fast
  // approvals and the payments don't deliver". Owner-only data (see store.ts
  // approval_stats). Ring lookup is O(APPROVAL_RING_MAX).
  if (entry.key_hash) {
    const ownerRec = store.keys.get(entry.key_hash);
    const ringEntry = ownerRec?.approval_stats?.recent.find((e) => e.scan_id === scanId && !e.outcome);
    if (ringEntry) ringEntry.outcome = outcome;
  }

  // Aggregate against the pay_to captured AT SCAN TIME — never reporter input.
  if (entry.pay_to) {
    const agg: CounterpartyOutcomes = store.outcomes.get(entry.pay_to) ?? {
      delivered: 0,
      not_delivered: 0,
      partial: 0,
      wrong_content: 0,
      reporters: [],
      first_at: now,
      last_at: now,
    };
    agg[outcome] += 1;
    agg.last_at = now;
    if (!agg.reporters.includes(reporter) && agg.reporters.length < MAX_DISTINCT_REPORTERS) {
      agg.reporters.push(reporter);
    }
    store.outcomes.set(entry.pay_to, agg);
  }

  // Second aggregation, keyed by the resource DOMAIN captured at scan time —
  // the stable identity the pinning layer already trusts. This is what makes
  // pay_to rotation useless for laundering a bad delivery record: the new
  // wallet starts a fresh pay_to ledger, but the domain ledger carries over.
  // entry.domain is only ever set for non-blocked scans (see api.ts), so a
  // blocked pin-mismatch scan cannot write history under someone else's domain.
  if (entry.domain && entry.pay_to) {
    const dagg: DomainOutcomes = store.outcomesByDomain.get(entry.domain) ?? {
      delivered: 0,
      not_delivered: 0,
      partial: 0,
      wrong_content: 0,
      reporters: [],
      pay_tos: [],
      first_at: now,
      last_at: now,
    };
    dagg[outcome] += 1;
    dagg.last_at = now;
    if (!dagg.reporters.includes(reporter) && dagg.reporters.length < MAX_DISTINCT_REPORTERS) {
      dagg.reporters.push(reporter);
    }
    if (!dagg.pay_tos.includes(entry.pay_to) && dagg.pay_tos.length < MAX_LINKED_PAY_TOS) {
      dagg.pay_tos.push(entry.pay_to);
    }
    store.outcomesByDomain.set(entry.domain, dagg);
  }
  store.markDirty();

  const evidence = (typeof b.evidence === "object" && b.evidence !== null ? b.evidence : {}) as Record<string, unknown>;

  // Receiptless settlement: the buyer saw the transfer on-chain but the seller
  // returned no settlement-receipt header, so a stock client believes the call
  // was free and may pay again. Client-supplied and therefore Sybil-forgeable
  // (H-2) — counted and surfaced, never allowed to block.
  const receiptRaw = evidence.settlement_receipt;
  const receiptless = receiptRaw === "absent";
  if (receiptless) {
    if (entry.pay_to) {
      const agg = store.outcomes.get(entry.pay_to);
      if (agg) agg.receiptless = (agg.receiptless ?? 0) + 1;
    }
    if (entry.domain && entry.pay_to) {
      const dagg = store.outcomesByDomain.get(entry.domain);
      if (dagg) dagg.receiptless = (dagg.receiptless ?? 0) + 1;
    }
    store.markDirty();
  }

  return {
    status: 201,
    body: {
      recorded: true,
      scan_id: scanId,
      outcome,
      counterparty: entry.pay_to || null,
      evidence_noted: {
        status: typeof evidence.status === "number" ? evidence.status : null,
        content_type: typeof evidence.content_type === "string" ? evidence.content_type.slice(0, 100) : null,
        bytes: typeof evidence.bytes === "number" ? evidence.bytes : null,
        latency_ms: typeof evidence.latency_ms === "number" ? evidence.latency_ms : null,
        settlement_receipt: receiptRaw === "present" || receiptRaw === "absent" ? receiptRaw : null,
      },
      note: "Outcome bound to the scanned payment. Delivery rates feed GET /v1/reputation/{address} and future scans of this counterparty.",
    },
  };
}

interface DeliveryStats {
  outcomes_total: number;
  delivered: number;
  not_delivered: number;
  partial: number;
  wrong_content: number;
  /** Raw observed rate — always reported, never the flag trigger. */
  delivery_rate: number;
  /** Prior-smoothed rate (see smoothedRate) — what the flag checks compare. */
  smoothed_delivery_rate: number;
  distinct_reporters: number;
  /** Settlements reported with no seller receipt header (see CounterpartyOutcomes). */
  receiptless: number;
  first_at: string;
  last_at: string;
}

function statsOf(agg: CounterpartyOutcomes, cfg?: TollwardenConfig): DeliveryStats | null {
  const total = agg.delivered + agg.not_delivered + agg.partial + agg.wrong_content;
  if (!total) return null;
  return {
    outcomes_total: total,
    delivered: agg.delivered,
    not_delivered: agg.not_delivered,
    partial: agg.partial,
    wrong_content: agg.wrong_content,
    delivery_rate: Number((agg.delivered / total).toFixed(4)),
    smoothed_delivery_rate: Number(smoothedRate(agg.delivered, total, cfg).toFixed(4)),
    distinct_reporters: agg.reporters.length,
    receiptless: agg.receiptless ?? 0,
    first_at: agg.first_at,
    last_at: agg.last_at,
  };
}

/** The outcome ledger's DENOMINATOR, surfaced. `scans_seen` is how many
 * non-blocked scans Tollwarden has performed against this counterparty since
 * counting began; `report_coverage` is outcomes_total over that. Publishing
 * the denominator makes selective reporting legible — a curated slice of
 * outcomes reads as low coverage instead of passing as a complete record.
 * INFORMATIONAL ONLY: scan counts are client-driven (anyone can scan any
 * pay_to, inflating the denominator), so neither field may ever feed a
 * flag/block decision — failureVerdict must not read them. */
export interface DeliveryCoverage {
  scans_seen: number;
  /** When the denominator started counting — coverage before this is unknowable. */
  scans_tracked_since: string | null;
  /** outcomes_total / scans_seen, clamped to [0,1] (outcomes predating the
   * counter can push the raw ratio past 1). Null when scans_seen is 0. */
  report_coverage: number | null;
}

function coverageOf(store: Store, address: string, outcomesTotal: number): DeliveryCoverage {
  const sc = store.scanCounts.get(address);
  const seen = sc?.scans ?? 0;
  return {
    scans_seen: seen,
    scans_tracked_since: sc?.first_at ?? null,
    report_coverage: seen > 0 ? Number(Math.min(1, outcomesTotal / seen).toFixed(4)) : null,
  };
}

/** Delivery stats + coverage for one counterparty, for the reputation summary.
 * Null when there is no outcome history (absence of history is not a signal). */
export function deliverySummary(store: Store, addressRaw: string, cfg?: TollwardenConfig): (DeliveryStats & DeliveryCoverage) | null {
  const address = addressRaw.trim().toLowerCase();
  const agg = store.outcomes.get(address);
  const stats = agg ? statsOf(agg, cfg) : null;
  return stats ? { ...stats, ...coverageOf(store, address, stats.outcomes_total) } : null;
}

/** Reputation view for a counterparty with scans on record but ZERO reported
 * outcomes: the un-reported population stays visible instead of reading as
 * "no history" — exactly the selective-logging case coverage exists to
 * expose. Null when nothing was ever counted (then absence means absence). */
export function coverageOnlySummary(store: Store, addressRaw: string): ({ outcomes_total: 0 } & DeliveryCoverage) | null {
  const cov = coverageOf(store, addressRaw.trim().toLowerCase(), 0);
  return cov.scans_seen > 0 ? { outcomes_total: 0, ...cov } : null;
}

/** The two failure tests, shared by the pay_to and the domain-joined ledgers.
 * Returns null when the history doesn't trip either. */
function failureVerdict(d: DeliveryStats, cfg: TollwardenConfig): { kind: "no_confirmed" | "low_rate"; severity: "high" | "medium" } | null {
  const failures = d.not_delivered + d.wrong_content;
  // Repeated failures with zero confirmed deliveries — flags even below the
  // volume threshold, because there is no success to weigh against. Severity
  // scales with sample size: 3 failures is a pattern, not yet a verdict.
  if (failures >= 3 && d.delivered === 0) {
    return { kind: "no_confirmed", severity: failures >= cfg.deliveryMinOutcomes ? "high" : "medium" };
  }
  if (d.outcomes_total >= cfg.deliveryMinOutcomes && d.smoothed_delivery_rate < cfg.deliveryFlagRate) {
    return { kind: "low_rate", severity: d.smoothed_delivery_rate < cfg.deliveryFlagRate / 2 ? "high" : "medium" };
  }
  return null;
}

function domainOf(resourceUrl: string | undefined): string | null {
  if (!resourceUrl) return null;
  try {
    return new URL(resourceUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Scan-time delivery checks (both directions — they key on who gets paid).
 * FLAG-ONLY by design (audit H-2): measured history is still third-party
 * signal and must never hard-block an honest payment on its own. No history
 * reads as "no history", never as suspicion.
 *
 * Two ledgers are consulted:
 *  1. pay_to — the counterparty's own record.
 *  2. the resource DOMAIN — the stable identity pinning already trusts. This
 *     closes the rotation loophole: same-domain rotation is hard-blocked by
 *     pin.mismatch, but after a LEGITIMATE rotation (operator clears the pin)
 *     the new wallet would otherwise start with a clean, empty ledger. The
 *     domain ledger carries the record across the rotation.
 */
export function checkDelivery(store: Store, payment: PaymentDetails, cfg: TollwardenConfig): CheckResult[] {
  const payTo = (payment.pay_to ?? "").trim().toLowerCase();
  if (!payTo) return [];
  const checks: CheckResult[] = [];

  const d = deliverySummary(store, payTo, cfg);
  let addressFlagged = false;
  if (d) {
    const bad = failureVerdict(d, cfg);
    if (bad?.kind === "no_confirmed") {
      addressFlagged = true;
      const failures = d.not_delivered + d.wrong_content;
      checks.push({
        id: "delivery.no_confirmed",
        name: "Delivery outcomes",
        verdict: "flag",
        severity: bad.severity,
        reason: `Counterparty ${payment.pay_to} has ${failures} commitment-bound delivery failure(s) (${d.not_delivered} not delivered, ${d.wrong_content} wrong content) and ZERO confirmed deliveries, from ${d.distinct_reporters} distinct reporter(s). A clean payment to a seller who never ships still fails you.`,
        details: { ...d },
      });
    } else if (bad?.kind === "low_rate") {
      addressFlagged = true;
      checks.push({
        id: "delivery.low_rate",
        name: "Delivery outcomes",
        verdict: "flag",
        severity: bad.severity,
        reason: `Counterparty ${payment.pay_to} delivered on ${(d.delivery_rate * 100).toFixed(1)}% of ${d.outcomes_total} commitment-bound settlements (${(d.smoothed_delivery_rate * 100).toFixed(1)}% prior-smoothed, threshold ${(cfg.deliveryFlagRate * 100).toFixed(0)}%), per ${d.distinct_reporters} distinct reporter(s). Outcomes are bound to scans Tollwarden performed — this is measured history, not accusation.`,
        details: { ...d },
      });
    } else {
      checks.push({
        id: "delivery.history",
        name: "Delivery outcomes",
        verdict: "allow",
        severity: "info",
        reason: `Counterparty delivered on ${(d.delivery_rate * 100).toFixed(1)}% of ${d.outcomes_total} commitment-bound settlement(s).`,
        details: { ...d },
      });
    }

    // Receiptless settlement is orthogonal to whether the goods arrived, so it
    // reports independently of the delivery verdict above. A seller can ship
    // perfectly and still leave the buyer unable to see that they were
    // charged. Flag-only (H-2): the signal is buyer-reported.
    if (d.receiptless > 0) {
      const majority = d.receiptless * 2 >= d.outcomes_total;
      checks.push({
        id: "delivery.receiptless_settlement",
        name: "Delivery outcomes",
        verdict: "flag",
        severity: majority && d.receiptless >= 3 ? "high" : "medium",
        reason: `${d.receiptless} of ${d.outcomes_total} reported settlement(s) with this counterparty moved funds on-chain but returned NO settlement-receipt header. A stock x402 client reads such a call as free, so the charge is invisible without an on-chain audit — and an agent that retries a "free" call pays twice. Reconcile this payment against an on-chain transfer log rather than trusting the response headers.`,
        details: { receiptless: d.receiptless, outcomes_total: d.outcomes_total },
      });
    }
  }
  // No pay_to history: silent (the first-contact check covers "unknown seller")
  // — but the domain join below still runs, which is exactly the rotation case.

  // Rotation join: does this domain carry delivery history earned under OTHER
  // pay_to addresses? Only speaks up when that joined record trips the same
  // failure tests and the address-level check hasn't already flagged (one flag
  // is enough); healthy domain history stays silent.
  const domain = domainOf(payment.resource_url);
  if (!addressFlagged && domain) {
    const dagg = store.outcomesByDomain.get(domain);
    if (dagg && dagg.pay_tos.some((a) => a !== payTo)) {
      const dd = statsOf(dagg, cfg);
      const bad = dd ? failureVerdict(dd, cfg) : null;
      if (dd && bad) {
        const others = dagg.pay_tos.filter((a) => a !== payTo);
        checks.push({
          id: "delivery.rotated_history",
          name: "Delivery outcomes",
          verdict: "flag",
          severity: bad.severity,
          reason: `Domain ${domain} has commitment-bound delivery history under ${others.length} other payment address(es): delivered on ${(dd.delivery_rate * 100).toFixed(1)}% of ${dd.outcomes_total} settlements (${(dd.smoothed_delivery_rate * 100).toFixed(1)}% prior-smoothed), ${dd.delivered === 0 ? "with ZERO confirmed deliveries, " : ""}per ${dd.distinct_reporters} distinct reporter(s). Rotating the pay_to address does not reset a domain's measured delivery record.`,
          details: { domain, current_pay_to: payTo, previous_pay_tos: others, ...dd },
        });
      }
    }
  }

  return checks;
}

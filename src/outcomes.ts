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
 *  - Every outcome is BOUND to a scan PaySafe actually performed: the report
 *    must present the (scan_id, payment_commitment) pair from a real scan,
 *    verified against the rolling scan index, one outcome per scan, and (for
 *    keyed scans) only from the account that made the scan. Fabricating
 *    delivery history therefore requires making real, scanned payments —
 *    an anti-Sybil property free-text reports can't have.
 *  - Aggregates key off the pay_to RECORDED AT SCAN TIME (from the index),
 *    never the reporter's claim.
 *
 * Verdict integration preserves audit H-2: delivery history can only ever
 * FLAG, never block — third-party history must not stop an honest payment on
 * its own. Positive outcomes contextualize but never erase negative reports.
 *
 * Honest limits: this measures that content ARRIVED (mechanically), not that
 * it was good — quality judgments stay with POST /v1/reputation/report. And
 * it covers digital, synchronous x402 delivery, not physical shipment.
 */
import type { PaySafeConfig } from "./config.ts";
import type { CounterpartyOutcomes, Store } from "./store.ts";
import type { ApiResult } from "./api.ts";
import type { CheckResult, PaymentDetails } from "./types.ts";

export const OUTCOME_KINDS = ["delivered", "not_delivered", "partial", "wrong_content"] as const;
export type OutcomeKind = (typeof OUTCOME_KINDS)[number];

const MAX_DISTINCT_REPORTERS = 50;

/** Uniform failure: unknown scan, commitment mismatch, and wrong account are
 * indistinguishable — the (scan_id, commitment) pair is a bearer proof of
 * having seen the scan, and this endpoint must not help brute-force either. */
const NOT_FOUND: ApiResult = { status: 404, body: { error: "Unknown scan or commitment mismatch." } };

/**
 * POST /v1/outcomes — record the delivery outcome of a scanned payment.
 * Free (rate-limited per IP at the route layer).
 */
export function handleOutcomeReport(store: Store, cfg: PaySafeConfig, apiKey: string | undefined, body: unknown): ApiResult {
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
    const reporter = entry.key_hash ?? "anon";
    if (!agg.reporters.includes(reporter) && agg.reporters.length < MAX_DISTINCT_REPORTERS) {
      agg.reporters.push(reporter);
    }
    store.outcomes.set(entry.pay_to, agg);
  }
  store.markDirty();

  const evidence = (typeof b.evidence === "object" && b.evidence !== null ? b.evidence : {}) as Record<string, unknown>;
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
      },
      note: "Outcome bound to the scanned payment. Delivery rates feed GET /v1/reputation/{address} and future scans of this counterparty.",
    },
  };
}

/** Delivery stats for one counterparty, for the reputation summary. Null when
 * there is no outcome history (absence of history is not a signal). */
export function deliverySummary(store: Store, addressRaw: string): {
  outcomes_total: number;
  delivered: number;
  not_delivered: number;
  partial: number;
  wrong_content: number;
  delivery_rate: number;
  distinct_reporters: number;
  first_at: string;
  last_at: string;
} | null {
  const agg = store.outcomes.get(addressRaw.trim().toLowerCase());
  if (!agg) return null;
  const total = agg.delivered + agg.not_delivered + agg.partial + agg.wrong_content;
  if (!total) return null;
  return {
    outcomes_total: total,
    delivered: agg.delivered,
    not_delivered: agg.not_delivered,
    partial: agg.partial,
    wrong_content: agg.wrong_content,
    delivery_rate: Number((agg.delivered / total).toFixed(4)),
    distinct_reporters: agg.reporters.length,
    first_at: agg.first_at,
    last_at: agg.last_at,
  };
}

/**
 * Scan-time delivery check (both directions — it keys on who gets paid).
 * FLAG-ONLY by design (audit H-2): measured history is still third-party
 * signal and must never hard-block an honest payment on its own. No history
 * reads as "no history", never as suspicion.
 */
export function checkDelivery(store: Store, payment: PaymentDetails, cfg: PaySafeConfig): CheckResult | null {
  const payTo = (payment.pay_to ?? "").trim().toLowerCase();
  if (!payTo) return null;
  const d = deliverySummary(store, payTo);
  if (!d) return null; // no outcome history: silent (the first-contact check covers "unknown seller")

  const failures = d.not_delivered + d.wrong_content;

  // Repeated failures with zero confirmed deliveries — flags even below the
  // volume threshold, because there is no success to weigh against.
  if (failures >= 3 && d.delivered === 0) {
    return {
      id: "delivery.no_confirmed",
      name: "Delivery outcomes",
      verdict: "flag",
      severity: "high",
      reason: `Counterparty ${payment.pay_to} has ${failures} commitment-bound delivery failure(s) (${d.not_delivered} not delivered, ${d.wrong_content} wrong content) and ZERO confirmed deliveries, from ${d.distinct_reporters} distinct reporter(s). A clean payment to a seller who never ships still fails you.`,
      details: { ...d },
    };
  }

  if (d.outcomes_total >= cfg.deliveryMinOutcomes && d.delivery_rate < cfg.deliveryFlagRate) {
    return {
      id: "delivery.low_rate",
      name: "Delivery outcomes",
      verdict: "flag",
      severity: d.delivery_rate < cfg.deliveryFlagRate / 2 ? "high" : "medium",
      reason: `Counterparty ${payment.pay_to} delivered on ${(d.delivery_rate * 100).toFixed(1)}% of ${d.outcomes_total} commitment-bound settlements (threshold ${(cfg.deliveryFlagRate * 100).toFixed(0)}%), per ${d.distinct_reporters} distinct reporter(s). Outcomes are bound to scans PaySafe performed — this is measured history, not accusation.`,
      details: { ...d },
    };
  }

  return {
    id: "delivery.history",
    name: "Delivery outcomes",
    verdict: "allow",
    severity: "info",
    reason: `Counterparty delivered on ${(d.delivery_rate * 100).toFixed(1)}% of ${d.outcomes_total} commitment-bound settlement(s).`,
    details: { ...d },
  };
}

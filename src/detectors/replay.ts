/**
 * Replay detection: tracks payment nonces and blocks reuse.
 * Key is scoped by network + payer (when known) so distinct payers with
 * coincidentally equal nonces don't collide.
 */
import type { CheckResult, PaymentDetails } from "../types.ts";
import type { Store } from "../store.ts";

export function checkReplay(
  payment: PaymentDetails,
  store: Store,
  scanId: string,
  ttlHours: number,
): CheckResult {
  if (!payment.nonce) {
    return {
      id: "replay.no_nonce",
      name: "Replay detection",
      verdict: "flag",
      severity: "low",
      reason:
        "No nonce supplied with the payment payload, so replay protection cannot be verified. Include the payment nonce for full coverage.",
    };
  }

  // Nonce TTL pruning runs on the Store's maintenance timer, not here, so the
  // hot path stays O(1) instead of O(nonces) per request (audit H-4).
  void ttlHours;
  const key = `${payment.network ?? "?"}:${(payment.payer ?? "").toLowerCase()}:${payment.nonce}`;
  const existing = store.nonces.get(key);

  if (existing) {
    existing.times_seen += 1;
    store.markDirty();
    return {
      id: "replay.nonce_reuse",
      name: "Replay detection",
      verdict: "block",
      severity: "critical",
      reason: `Nonce reuse detected: this nonce was first seen ${existing.first_seen} (scan ${existing.scan_id}) and has now appeared ${existing.times_seen} times. A reused nonce means a stale or captured payment authorization is being replayed.`,
      details: {
        nonce: payment.nonce,
        first_seen: existing.first_seen,
        first_scan_id: existing.scan_id,
        times_seen: existing.times_seen,
      },
    };
  }

  store.nonces.set(key, {
    first_seen: new Date().toISOString(),
    times_seen: 1,
    scan_id: scanId,
  });
  store.markDirty();

  return {
    id: "replay.clean",
    name: "Replay detection",
    verdict: "allow",
    severity: "info",
    reason: "Nonce has not been seen before within the tracking window.",
  };
}

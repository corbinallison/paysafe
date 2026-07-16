/**
 * Address-poisoning detection.
 *
 * The attack: an attacker generates a vanity address whose FIRST and LAST
 * characters match an address the victim pays regularly, betting that agents
 * (and humans) verify addresses by their displayed form — "0x2096…287C" —
 * and never check the middle. Poisoned history entries, injected content, and
 * spoofed 402 offers all rely on this truncated-display blind spot.
 *
 * The defense: compare this payment's pay_to against addresses this agent has
 * actually paid before (its counterparty history) and against all pinned
 * merchant addresses. An address that is NOT an exact match but shares a
 * significant prefix AND suffix with a known address is overwhelmingly likely
 * to be adversarial: for random 20-byte addresses, a ≥4-hex-char match on
 * both ends happens by chance ~1 in 4 billion pairs — while vanity-grinding
 * exactly that match costs an attacker seconds.
 *
 * Like pinning, this is a fact about history, not about the agent's
 * narration — it holds even when the agent's context is fully compromised.
 */
import type { CheckResult, ScanRequest } from "../types.ts";
import type { Store } from "../store.ts";

/** Chars (after "0x") that must match on BOTH ends to call it a lookalike. */
const PREFIX_MIN = 4;
const SUFFIX_MIN = 4;

const EVM_ADDR = /^0x[0-9a-f]{40}$/;

function sharedPrefix(a: string, b: string): number {
  let n = 0;
  while (n < a.length && n < b.length && a[n] === b[n]) n++;
  return n;
}

function sharedSuffix(a: string, b: string): number {
  let n = 0;
  while (n < a.length && n < b.length && a[a.length - 1 - n] === b[b.length - 1 - n]) n++;
  return n;
}

interface KnownAddress {
  address: string;
  source: string; // human-readable provenance for the reason string
}

/**
 * Returns a block CheckResult if pay_to is a lookalike of a known-good
 * address, or null when there is nothing to report (exact match, no
 * similarity, or nothing to compare against). Must run BEFORE velocity
 * records this scan's counterparty, so the lookalike is judged against
 * history that does not yet include it.
 */
export function checkAddressPoisoning(req: ScanRequest, store: Store): CheckResult | null {
  const payTo = req.payment.pay_to?.toLowerCase();
  if (!payTo || !EVM_ADDR.test(payTo)) return null; // non-EVM shapes: nothing to compare

  // Known-good set: this agent's own payment history + pinned merchants.
  // Scoped to the caller's history (plus global pins) so one tenant's
  // counterparty list is never revealed through another tenant's scan reasons.
  const scopeKey = req.agent_id ?? req.payment.payer?.toLowerCase();
  const known: KnownAddress[] = [];
  if (scopeKey) {
    for (const addr of store.counterparties.get(scopeKey) ?? []) {
      known.push({ address: addr, source: `a counterparty this agent has paid before` });
    }
  }
  for (const [domain, pin] of store.pins) {
    known.push({ address: pin.pay_to, source: `the pinned address for ${domain}` });
  }
  if (known.length === 0) return null;

  // Exact match with any known address = the real counterparty. Fine.
  if (known.some((k) => k.address === payTo)) return null;

  const body = payTo.slice(2);
  let best: { k: KnownAddress; pre: number; suf: number } | null = null;
  for (const k of known) {
    if (!EVM_ADDR.test(k.address)) continue;
    const kb = k.address.slice(2);
    const pre = sharedPrefix(body, kb);
    const suf = sharedSuffix(body, kb);
    if (pre >= PREFIX_MIN && suf >= SUFFIX_MIN) {
      if (!best || pre + suf > best.pre + best.suf) best = { k, pre, suf };
    }
  }
  if (!best) return null;

  return {
    id: "poison.lookalike",
    name: "Address poisoning",
    verdict: "block",
    severity: "critical",
    reason:
      `pay_to ${payTo} matches ${best.k.address} (${best.k.source}) on its first ${best.pre} and last ${best.suf} characters but is a DIFFERENT address. ` +
      `Truncated displays ("0x${body.slice(0, 4)}…${body.slice(-4)}") make these indistinguishable — this is the signature of an address-poisoning attack. ` +
      `Verify the full address out-of-band before paying; if this is genuinely a new counterparty, use a distinct agent_id context or pay after human confirmation.`,
    details: {
      presented: payTo,
      similar_to: best.k.address,
      shared_prefix_chars: best.pre,
      shared_suffix_chars: best.suf,
      similar_source: best.k.source,
    },
  };
}

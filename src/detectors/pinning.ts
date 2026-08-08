// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Merchant pinning (TOFU — trust on first use). The first time a resource
 * domain is scanned, its pay_to address is pinned; any later scan of the same
 * domain with a DIFFERENT pay_to is blocked. This catches payment-address
 * redirection even when content analysis finds nothing — the pin is a fact
 * about history, not about the agent's narration.
 *
 * Zero latency at scan time. Optionally, a non-blocking background cross-check
 * against the CDP Bazaar merchant index verifies pins out-of-band.
 */
import type { CheckResult, PaymentDetails, PinEvidence } from "../types.ts";
import type { Store } from "../store.ts";

function domainOf(resourceUrl: string | undefined): string | null {
  if (!resourceUrl) return null;
  try {
    return new URL(resourceUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function checkPinning(payment: PaymentDetails, store: Store): CheckResult {
  const domain = domainOf(payment.resource_url);
  const payTo = payment.pay_to?.toLowerCase();

  if (!domain || !payTo) {
    return {
      id: "pin.unscoped",
      name: "Merchant pinning",
      verdict: "allow",
      severity: "info",
      reason: "Pinning needs both resource_url and pay_to; check skipped.",
    };
  }

  const pin = store.pins.get(domain);
  if (!pin) {
    store.pins.set(domain, {
      pay_to: payTo,
      first_seen: new Date().toISOString(),
      times_seen: 1,
      cdp_status: "unchecked",
    });
    store.markDirty();
    return {
      id: "pin.created",
      name: "Merchant pinning",
      verdict: "allow",
      severity: "info",
      reason: `First sighting of ${domain}: pinned to ${payTo} (trust on first use).`,
    };
  }

  if (pin.pay_to === payTo) {
    pin.times_seen += 1;
    store.markDirty();
    return {
      id: "pin.match",
      name: "Merchant pinning",
      verdict: "allow",
      severity: "info",
      reason: `pay_to matches the pinned address for ${domain} (seen ${pin.times_seen}×, pinned ${pin.first_seen}${pin.cdp_status === "verified" ? ", CDP-verified" : ""}).`,
    };
  }

  return {
    id: "pin.mismatch",
    name: "Merchant pinning",
    verdict: "block",
    severity: "critical",
    reason: `Payment address for ${domain} CHANGED: pinned ${pin.pay_to} (since ${pin.first_seen}, seen ${pin.times_seen}×) but this payment targets ${payTo}. Address rotation on a known domain is the signature of a redirection attack. If the merchant legitimately rotated wallets, clear the pin from the data store.`,
    details: { domain, pinned: pin.pay_to, presented: payTo, pinned_since: pin.first_seen },
  };
}

/**
 * Pin facts for the signed evidence record — READ-ONLY, computed at
 * attestation time (after the scanner has created/updated/rolled-back pins,
 * so a blocked first-sighting whose pin was rolled back honestly reads as "no
 * pin"). Returns facts only when the pin refers to THIS payment's payee
 * (pin.pay_to === payment.pay_to): a pin held by a different address is not
 * evidence about the presented one. Null when pinning is disabled (nothing
 * maintains the pin map, so a stale entry must not be signed as evidence),
 * when no pin applies, or when the stored timestamp is unusable (never sign a
 * garbage age).
 */
export function pinEvidenceFor(
  payment: PaymentDetails,
  store: Store,
  pinningEnabled: boolean,
  scannedAt: string,
): PinEvidence | null {
  if (!pinningEnabled) return null;
  const domain = domainOf(payment.resource_url);
  const payTo = payment.pay_to?.toLowerCase();
  if (!domain || !payTo) return null;
  const pin = store.pins.get(domain);
  if (!pin || pin.pay_to !== payTo) return null;
  const ageMs = Date.parse(scannedAt) - Date.parse(pin.first_seen);
  if (!Number.isFinite(ageMs)) return null;
  return {
    domain,
    age_seconds: Math.max(0, Math.floor(ageMs / 1000)),
    corroboration: pin.cdp_status === "verified" ? ["cdp_bazaar"] : [],
  };
}

/**
 * Non-blocking CDP Bazaar cross-check: does the CDP merchant index list this
 * domain among the resources served by the pinned pay_to? Fire-and-forget —
 * never in the scan's latency path. Enable with CDP_PIN_VERIFY=on.
 */
export function scheduleCdpPinVerify(store: Store, domain: string): void {
  const pin = store.pins.get(domain);
  if (!pin || pin.cdp_status !== "unchecked") return;

  setImmediate(async () => {
    try {
      const res = await fetch(
        `https://api.cdp.coinbase.com/platform/v2/x402/discovery/merchant?payTo=${encodeURIComponent(pin.pay_to)}`,
        { signal: AbortSignal.timeout(10_000) },
      );
      if (res.status === 404) return; // merchant not indexed (yet) — stay unchecked
      if (!res.ok) return;
      const data = (await res.json()) as { resources?: Array<{ resource?: string }> };
      const domains = (data.resources ?? [])
        .map((r) => domainOf(r.resource))
        .filter((d): d is string => d !== null);
      if (domains.length === 0) return;
      pin.cdp_status = domains.includes(domain) ? "verified" : "mismatch";
      store.markDirty();
    } catch {
      // best-effort; pin stays "unchecked"
    }
  });
}

/** Surface an out-of-band CDP mismatch found by a previous background check. */
export function checkCdpPinStatus(payment: PaymentDetails, store: Store): CheckResult | null {
  const domain = domainOf(payment.resource_url);
  if (!domain) return null;
  const pin = store.pins.get(domain);
  if (!pin || pin.cdp_status !== "mismatch") return null;
  return {
    id: "pin.cdp_mismatch",
    name: "Merchant pinning",
    verdict: "flag",
    severity: "high",
    reason: `Background CDP Bazaar check: the pinned pay_to for ${domain} is indexed as a merchant, but ${domain} is not among its registered resources. Verify the merchant identity out-of-band.`,
    details: { domain, pinned: pin.pay_to },
  };
}

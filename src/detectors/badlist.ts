// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Known-bad address list. O(1) set membership over a JSON file of addresses
 * (curated manually or synced from public scam-address feeds out-of-band).
 */
import type { CheckResult, PaymentDetails } from "../types.ts";
import type { Store } from "../store.ts";

export function checkBadlist(payment: PaymentDetails, store: Store): CheckResult | null {
  const payTo = payment.pay_to?.toLowerCase();
  if (!payTo || store.badlist.size === 0) return null;
  if (!store.badlist.has(payTo)) return null;
  return {
    id: "badlist.hit",
    name: "Known-bad address list",
    verdict: "block",
    severity: "critical",
    reason: `Recipient ${payTo} is on the configured known-bad address list (BADLIST_PATH).`,
    details: { pay_to: payTo },
  };
}

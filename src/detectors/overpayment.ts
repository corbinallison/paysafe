// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Overpayment detection: compares the actual payment amount against the
 * expected price and an absolute ceiling.
 */
import type { CheckResult, PaymentDetails } from "../types.ts";

/** Resolve the payment's USD value from amount_usd or atomic units (default 6 decimals = USDC). */
export function resolveUsd(payment: PaymentDetails): number | null {
  if (typeof payment.amount_usd === "number" && Number.isFinite(payment.amount_usd)) {
    return payment.amount_usd;
  }
  if (payment.amount !== undefined) {
    const atomic = Number(payment.amount);
    if (Number.isFinite(atomic)) {
      const decimals = payment.asset_decimals ?? 6;
      const usd = atomic / 10 ** decimals;
      if (Number.isFinite(usd)) return usd;
    }
  }
  return null;
}

export function checkOverpayment(
  payment: PaymentDetails,
  expectedUsd: number | undefined,
  opts: { flagMultiple: number; blockMultiple: number; maxUsd: number },
): CheckResult {
  const usd = resolveUsd(payment);
  if (usd === null) {
    return {
      id: "overpay.no_amount",
      name: "Overpayment detection",
      verdict: "flag",
      severity: "low",
      reason:
        "Payment amount could not be determined (provide amount + asset_decimals, or amount_usd). Overpayment protection cannot be verified.",
    };
  }

  if (usd <= 0) {
    return {
      id: "overpay.non_positive",
      name: "Overpayment detection",
      verdict: "block",
      severity: "high",
      reason: `Payment amount resolves to $${usd.toFixed(6)} — zero or negative amounts are malformed and are sometimes used to probe payment plumbing. Refuse and re-quote.`,
      details: { amount_usd: usd },
    };
  }

  if (usd > opts.maxUsd) {
    return {
      id: "overpay.absolute_cap",
      name: "Overpayment detection",
      verdict: "block",
      severity: "high",
      reason: `Payment of $${usd.toFixed(4)} exceeds the configured absolute ceiling of $${opts.maxUsd}. Raise MAX_PAYMENT_USD if intentional.`,
      details: { amount_usd: usd, max_usd: opts.maxUsd },
    };
  }

  if (expectedUsd !== undefined && expectedUsd > 0) {
    const ratio = usd / expectedUsd;
    if (ratio >= opts.blockMultiple) {
      return {
        id: "overpay.block_multiple",
        name: "Overpayment detection",
        verdict: "block",
        severity: "high",
        reason: `Payment of $${usd.toFixed(4)} is ${ratio.toFixed(1)}× the expected price of $${expectedUsd.toFixed(4)} (block threshold ${opts.blockMultiple}×).`,
        details: { amount_usd: usd, expected_usd: expectedUsd, ratio },
      };
    }
    if (ratio >= opts.flagMultiple) {
      return {
        id: "overpay.flag_multiple",
        name: "Overpayment detection",
        verdict: "flag",
        severity: "medium",
        reason: `Payment of $${usd.toFixed(4)} is ${ratio.toFixed(1)}× the expected price of $${expectedUsd.toFixed(4)} (flag threshold ${opts.flagMultiple}×). Verify the quote before proceeding.`,
        details: { amount_usd: usd, expected_usd: expectedUsd, ratio },
      };
    }
  }

  return {
    id: "overpay.clean",
    name: "Overpayment detection",
    verdict: "allow",
    severity: "info",
    reason:
      expectedUsd !== undefined
        ? `Payment of $${usd.toFixed(4)} is within expected bounds ($${expectedUsd.toFixed(4)} expected).`
        : `Payment of $${usd.toFixed(4)} is under the absolute ceiling; no expected price supplied for ratio checks.`,
  };
}

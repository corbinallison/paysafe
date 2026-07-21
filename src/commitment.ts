// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Deterministic hashing of payments.
 *
 * - paymentCommitment: a short binding over the transaction-defining fields
 *   (network, pay_to, asset, amount, nonce). Embedded in the signed verdict so
 *   a wallet can prove an allow-attestation belongs to THIS payment and not a
 *   different one (defends against attestation replay across payments).
 * - paymentDigest: SHA-256 over ALL payment fields (including the sensitive
 *   description/reason/metadata). Recorded in the audit log so it can be proven
 *   later exactly what was scanned, WITHOUT retaining the plaintext PII/secrets.
 */
import { createHash } from "node:crypto";
import type { PaymentDetails } from "./types.ts";

export function paymentCommitment(p: PaymentDetails): string {
  const amount =
    p.amount !== undefined ? String(p.amount)
    : p.amount_usd !== undefined ? `usd:${p.amount_usd}`
    : "";
  const canonical = [
    p.network ?? "",
    (p.pay_to ?? "").toLowerCase(),
    (p.asset ?? "").toLowerCase(),
    amount,
    p.nonce ?? "",
  ].join("|");
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/** Stable stringify (sorted keys) so the digest is reproducible. */
function stableStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${stableStringify((obj as Record<string, unknown>)[k])}`)
    .join(",")}}`;
}

export function paymentDigest(p: PaymentDetails): string {
  return createHash("sha256").update(stableStringify(p), "utf8").digest("hex");
}

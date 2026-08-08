// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Deterministic hashing of payments.
 *
 * - paymentCommitment: a short binding over the transaction-defining fields
 *   (network, pay_to, asset, amount, nonce). Embedded in the signed verdict so
 *   a wallet can prove an allow-attestation belongs to THIS payment and not a
 *   different one (defends against attestation replay across payments).
 *
 *   The commitment binds the AUTHORIZATION, not the errand. It deliberately
 *   omits resource_url, description and time: those are not fields the wallet
 *   signs, so including them would make the commitment impossible to check
 *   against the actual EIP-3009 authorization it exists to bind.
 *
 *   Consequence, confirmed intended: two different purchases from the same
 *   seller at the same price on the same rail collapse to the SAME commitment
 *   whenever `nonce` is absent — which is exactly the case for `pre_sign`
 *   scans, since the nonce does not exist yet. Field scouting hits this
 *   routinely (two Bazaar queries, same endpoint, same price, one commitment).
 *
 *   That is safe because the commitment is not the identifier of a settlement.
 *   Outcomes are keyed by `scan_id`, which is unique per scan; the commitment
 *   is only ever checked FOR EQUALITY against the scan it was issued with
 *   (see handleOutcomeReport). A shared commitment therefore cannot merge two
 *   outcome records or let one settlement's report land on another's scan.
 *   Supply `nonce` on post-sign scans if you want commitments to be unique per
 *   settlement as well as per authorization.
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

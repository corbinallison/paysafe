// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * x402 trust-provider interface (seller-side trust signal).
 *
 * Implements the provider half of the x402 trust-provider extension proposed
 * in x402-foundation/x402#2299 (PR #2300): a resource server's onBeforeSettle
 * hook POSTs a TrustQuery about the PAYER, and providers answer with a
 * TrustEvaluation (PASS / FAIL / UNCERTAIN + score + evidence pointer). This
 * is the mirror image of TollWarden's buyer-side scan: instead of protecting the
 * paying agent from a bad payee, it lets a seller gate settlement on the
 * paying agent's history.
 *
 * Decision policy (consistent with audit H-2):
 *  - FAIL comes ONLY from the operator-curated badlist. The report registry is
 *    self-asserted and spoofable, so reports alone can never hard-fail a payer
 *    — otherwise a Sybil attacker could weaponize our provider to abort an
 *    honest agent's settlements under a fail-closed aggregation policy.
 *  - Dense reports (many distinct reporters) yield UNCERTAIN with a low score;
 *    consumers running fail-closed treat that as abort, quorum policies weigh
 *    it — the choice stays with the consumer, as the extension intends.
 *  - A clean subject yields PASS with a deliberately moderate score: "no
 *    adverse history on record" is not an endorsement.
 *
 * The endpoint is free and rate-limited; evidence_uri points at the public
 * reputation summary so consumers can audit the basis for any evaluation.
 */
import type { TollWardenConfig } from "./config.ts";
import type { Store } from "./store.ts";
import type { ApiResult } from "./api.ts";
import { summarize } from "./reputation.ts";

const QUERY_SCHEMA = "x402-trust-query-v0.1";
const EVALUATION_SCHEMA = "x402-trust-evaluation-v0.1";

interface TrustSubject {
  wallet?: string;
  agent_id?: string;
}

function parseSubject(body: unknown): TrustSubject | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;
  // Tolerate schema drift: accept the documented shape (payer.wallet /
  // payer.agent_id) plus flat fallbacks seen in early provider examples.
  const payer = (typeof b.payer === "object" && b.payer !== null ? b.payer : {}) as Record<string, unknown>;
  const s = (v: unknown): string | undefined =>
    typeof v === "string" && v.trim().length >= 6 ? v.trim().toLowerCase() : undefined;
  const wallet = s(payer.wallet) ?? s(b.wallet) ?? s(b.address);
  const agentId = typeof payer.agent_id === "string" ? payer.agent_id.slice(0, 200) : undefined;
  if (!wallet && !agentId) return null;
  return { wallet, agent_id: agentId };
}

/**
 * POST /v1/trust/evaluate — TrustQuery in, TrustEvaluation out.
 * Malformed queries get 400 with the expected schema named, so integrators
 * can self-serve. Unknown subjects are UNCERTAIN, never PASS.
 */
export function handleTrustEvaluate(body: unknown, cfg: TollWardenConfig, store: Store): ApiResult {
  const subject = parseSubject(body);
  const now = new Date().toISOString();
  const base = cfg.publicBaseUrl;

  const evaluation = (
    decision: "PASS" | "FAIL" | "UNCERTAIN",
    score: number,
    reasonCode: string,
    detail: string,
    ttlSeconds: number,
    evidence?: string,
  ): ApiResult => ({
    status: 200,
    body: {
      schema: EVALUATION_SCHEMA,
      provider: "TollWarden",
      provider_url: base,
      decision,
      score,
      reason_code: reasonCode,
      detail,
      evidence_uri: evidence,
      ttl_seconds: ttlSeconds,
      evaluated_at: now,
    },
  });

  if (subject === null) {
    return {
      status: 400,
      body: {
        error: `Provide a ${QUERY_SCHEMA} object with payer.wallet (and/or payer.agent_id).`,
        expected_schema: QUERY_SCHEMA,
        example: {
          schema: QUERY_SCHEMA,
          payer: { agent_id: "agent_42", wallet: "0x..." },
          resource: { url: "https://api.example.com/x", method: "POST", amount: { value: "20000", currency: "USDC", chain: "base" } },
          requested_at: now,
        },
      },
    };
  }

  // No wallet: we key adverse history by address, so an agent_id alone is
  // unverifiable. UNCERTAIN — never PASS a subject we cannot look up.
  if (!subject.wallet) {
    return evaluation(
      "UNCERTAIN",
      50,
      "NO_WALLET_SUBJECT",
      "Query carried only a self-asserted agent_id; TollWarden keys payer history by wallet address. Include payer.wallet for a substantive evaluation.",
      300,
    );
  }

  const wallet = subject.wallet;
  const evidence = `${base}/v1/reputation/${encodeURIComponent(wallet)}`;

  // Operator-curated badlist: the only source of a hard FAIL.
  if (store.badlist.has(wallet)) {
    return evaluation(
      "FAIL",
      0,
      "BADLISTED",
      "Subject wallet is on TollWarden's operator-curated known-bad list.",
      86_400,
      evidence,
    );
  }

  // Community report registry: self-asserted, so it lowers confidence but
  // never hard-fails (see module header).
  const rep = summarize(store, wallet);
  if (rep.risk === "high") {
    return evaluation(
      "UNCERTAIN",
      15,
      "REPORTED_HIGH_DENSITY",
      `${rep.report_count} unverified report(s) from ${rep.distinct_reporters} distinct reporters (${Object.entries(rep.categories).map(([k, v]) => `${k}×${v}`).join(", ")}). Reports are self-asserted; review the evidence before gating.`,
      3_600,
      evidence,
    );
  }
  if (rep.risk === "medium") {
    return evaluation(
      "UNCERTAIN",
      35,
      "REPORTED_MEDIUM_DENSITY",
      `${rep.report_count} unverified report(s) from ${rep.distinct_reporters} distinct reporters. Review the evidence before gating.`,
      3_600,
      evidence,
    );
  }
  if (rep.risk === "low") {
    return evaluation(
      "PASS",
      60,
      "REPORTED_LOW_DENSITY",
      "A single unverified report exists; not enough to lower trust below passing on its own.",
      3_600,
      evidence,
    );
  }

  return evaluation(
    "PASS",
    70,
    "NO_ADVERSE_HISTORY",
    "No badlist entry and no reputation reports on record for this wallet. Absence of adverse history is not an endorsement.",
    3_600,
    evidence,
  );
}

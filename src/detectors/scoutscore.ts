// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * ScoutScore trust signal (external, advisory).
 *
 * ScoutScore (scoutscore.ai) publishes behavioral trust scores for x402
 * services, keyed by domain: contract clarity, availability, response
 * fidelity, identity/safety, spam-farm clustering. That is identity-level
 * reputation — exactly the thing TollWarden deliberately is not — so it enters
 * the scan as ONE labeled external signal with hard limits:
 *
 *  - It can only ever FLAG, never block (same policy as our own reputation
 *    registry, audit H-2: third-party opinion must not be able to stop a
 *    payment on its own).
 *  - Zero scan latency: lookups run out-of-band (same fire-and-forget pattern
 *    as the CDP pin cross-check) and results are cached in the store; a scan
 *    only ever reads the cache.
 *  - Privacy: the query shares the merchant DOMAIN only — never addresses,
 *    amounts, keys, or payload contents. Off by default (SCOUTSCORE=on).
 *  - Free-tier only: ScoutScore's launch API is unauthenticated; if it starts
 *    answering 402/4xx (paid-only), we cache "unavailable" and stay silent.
 *    TollWarden never pays for lookups — it holds no wallet by design.
 */
import type { CheckResult, PaymentDetails } from "../types.ts";
import type { Store, ScoutScoreRecord } from "../store.ts";

/** Re-query cadence: good answers daily, failures hourly. */
const OK_TTL_MS = 24 * 3600_000;
const ERR_TTL_MS = 3600_000;

const LEVELS = new Set(["HIGH", "MEDIUM", "LOW", "VERY_LOW"]);

function domainOf(resourceUrl: string | undefined): string | null {
  if (!resourceUrl) return null;
  try {
    return new URL(resourceUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isFresh(rec: ScoutScoreRecord): boolean {
  const age = Date.now() - Date.parse(rec.checked_at);
  return age < (rec.level === "unavailable" ? ERR_TTL_MS : OK_TTL_MS);
}

/** Defensive parse of a ScoutScore response body into a cacheable record. */
export function parseScoutScore(body: unknown): ScoutScoreRecord | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;
  const level = typeof b.level === "string" && LEVELS.has(b.level) ? (b.level as ScoutScoreRecord["level"]) : null;
  if (!level) return null;
  return {
    score: typeof b.score === "number" && Number.isFinite(b.score) ? b.score : null,
    level,
    flags: Array.isArray(b.flags) ? b.flags.filter((f): f is string => typeof f === "string").slice(0, 12).map((f) => f.slice(0, 64)) : [],
    checked_at: new Date().toISOString(),
  };
}

/**
 * Surface a cached LOW / VERY_LOW rating as a flag. HIGH/MEDIUM/unavailable
 * stay silent — an external score must add signal, not noise.
 */
export function checkScoutScore(payment: PaymentDetails, store: Store): CheckResult | null {
  const domain = domainOf(payment.resource_url);
  if (!domain) return null;
  const rec = store.scoutScores.get(domain);
  if (!rec || (rec.level !== "LOW" && rec.level !== "VERY_LOW")) return null;
  const flags = rec.flags.length ? ` Flags: ${rec.flags.join(", ")}.` : "";
  return {
    id: "scout.low_trust",
    name: "ScoutScore trust signal",
    verdict: "flag",
    severity: rec.level === "VERY_LOW" ? "high" : "medium",
    reason:
      `External signal: ScoutScore rates ${domain} ${rec.level}${rec.score !== null ? ` (score ${rec.score}/100)` : ""} as of ${rec.checked_at}.${flags} ` +
      `This is a third-party behavioral rating of the service, not a finding about this payment — verify the merchant out-of-band before proceeding.`,
    details: { domain, level: rec.level, score: rec.score, flags: rec.flags, checked_at: rec.checked_at, source: "scoutscore.ai" },
  };
}

/**
 * Fire-and-forget refresh of a domain's cached rating. Never in the scan's
 * latency path; never throws; never pays (a 402 caches as unavailable).
 */
export function scheduleScoutScoreRefresh(store: Store, domain: string, baseUrl: string): void {
  const existing = store.scoutScores.get(domain);
  if (existing && isFresh(existing)) return;
  // Mark immediately so concurrent scans don't stack duplicate fetches.
  const pending: ScoutScoreRecord = existing ?? { score: null, level: "unavailable", flags: [], checked_at: new Date(0).toISOString() };
  store.scoutScores.set(domain, { ...pending, checked_at: new Date().toISOString() });

  setImmediate(async () => {
    let rec: ScoutScoreRecord | null = null;
    try {
      // Launch-phase free endpoint, with the documented bazaar path as fallback.
      for (const url of [
        `${baseUrl}/api/score?domain=${encodeURIComponent(domain)}`,
        `${baseUrl}/api/bazaar/score/${encodeURIComponent(domain)}`,
      ]) {
        const res = await fetch(url, { signal: AbortSignal.timeout(10_000), headers: { accept: "application/json" } });
        if (res.status === 404) continue; // try the other path shape
        if (!res.ok) break;               // 402/5xx: paid-only or down — stay unavailable
        rec = parseScoutScore(await res.json());
        break;
      }
    } catch {
      // network failure: stay unavailable
    }
    store.scoutScores.set(
      domain,
      rec ?? { score: null, level: "unavailable", flags: [], checked_at: new Date().toISOString() },
    );
    store.markDirty();
  });
}

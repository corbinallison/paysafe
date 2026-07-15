/**
 * Plan / tier structures — agent-readable subscription plans.
 *
 * Design (see ROADMAP.md §2):
 *  - GET /v1/plans (free) serves the machine-readable catalog below.
 *  - POST /v1/plans/subscribe (x402-paid at the plan's price) upgrades the
 *    caller's API key with a plan + expiry. Renewal = pay again (extends).
 *  - At scan time the key's active plan overrides the env-default thresholds,
 *    clamped to HARD_CEILINGS.
 *
 * SECURITY INVARIANTS (do not relax):
 *  - Plans only tune the customer's OWN sensitivity thresholds (velocity,
 *    spend, first-contact) and pricing. Safety-critical checks — replay,
 *    merchant pinning, asset verification, PII/secret detection — are NOT
 *    plan-configurable and cannot be disabled by any tier.
 *  - Every numeric override is clamped to HARD_CEILINGS: no tier, present or
 *    future, may exceed them. We never sell "scan less carefully."
 */
import type { PaySafeConfig } from "./config.ts";
import type { Store } from "./store.ts";
import { createHash } from "node:crypto";

export interface PlanLimits {
  /** x402 price per scan while this plan is active, e.g. "$0.005" */
  price_per_scan: string;
  /** Scans per agent per minute before velocity flags (block at 2x) */
  max_payments_per_minute: number;
  /** Cumulative scanned spend per agent per hour (USD) before block */
  max_usd_per_hour: number;
  /** First payment to a never-seen counterparty above this (USD) is flagged */
  first_payment_max_usd: number;
  /** Deep content analysis on every scan (micropayment bypass disabled) */
  force_deep: boolean;
  /** Non-blocking CDP Bazaar cross-check of merchant pins */
  cdp_pin_verify: boolean;
}

export interface Plan {
  id: string;
  name: string;
  /** Subscription price (x402, USDC), e.g. "$4.99" */
  price: string;
  duration_days: number;
  description: string;
  limits: PlanLimits;
}

/** No plan may exceed these, ever (clamped at resolution time too). */
export const HARD_CEILINGS = {
  max_payments_per_minute: 300,
  max_usd_per_hour: 250,
  first_payment_max_usd: 50,
} as const;

/** Catalog. The implicit default (no plan / expired plan) is env-default config. */
export const PLANS: Plan[] = [
  {
    id: "pro",
    name: "Pro",
    price: "$4.99",
    duration_days: 30,
    description:
      "For agents in steady production: half-price scans, 6x velocity headroom, 10x hourly spend allowance, deep content analysis on every scan (micropayment bypass disabled), and async CDP Bazaar cross-checking of merchant pins.",
    limits: {
      price_per_scan: "$0.005",
      max_payments_per_minute: 60,
      max_usd_per_hour: 50,
      first_payment_max_usd: 5,
      force_deep: true,
      cdp_pin_verify: true,
    },
  },
  {
    id: "scale",
    name: "Scale",
    price: "$19.99",
    duration_days: 30,
    description:
      "For high-volume fleets: $0.002 scans, 300/min velocity, $250/hr spend allowance (the hard ceiling — no tier goes higher), deep analysis always on, CDP pin cross-checking.",
    limits: {
      price_per_scan: "$0.002",
      max_payments_per_minute: HARD_CEILINGS.max_payments_per_minute,
      max_usd_per_hour: HARD_CEILINGS.max_usd_per_hour,
      first_payment_max_usd: 25,
      force_deep: true,
      cdp_pin_verify: true,
    },
  },
];

export function getPlan(id: string): Plan | undefined {
  return PLANS.find((p) => p.id === id);
}

function hashKey(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

/** The key's currently active plan, or null (none, unknown key, or expired). */
export function activePlan(store: Store, apiKey: string | undefined): { plan: Plan; expires_at: string } | null {
  if (!apiKey) return null;
  const rec = store.keys.get(hashKey(apiKey));
  if (!rec?.plan || !rec.plan_expires_at) return null;
  if (new Date(rec.plan_expires_at).getTime() <= Date.now()) return null;
  const plan = getPlan(rec.plan);
  return plan ? { plan, expires_at: rec.plan_expires_at } : null;
}

/**
 * Per-request effective config: env defaults overridden by the key's active
 * plan, clamped to HARD_CEILINGS. Safety-critical fields (pinning, asset
 * verification, replay TTL, PII detection) are deliberately not touched.
 */
export function resolveEffectiveConfig(cfg: PaySafeConfig, store: Store, apiKey: string | undefined): PaySafeConfig {
  const active = activePlan(store, apiKey);
  if (!active) return cfg;
  const l = active.plan.limits;
  return {
    ...cfg,
    maxPaymentsPerMinute: Math.min(l.max_payments_per_minute, HARD_CEILINGS.max_payments_per_minute),
    maxUsdPerHour: Math.min(l.max_usd_per_hour, HARD_CEILINGS.max_usd_per_hour),
    firstPaymentMaxUsd: Math.min(l.first_payment_max_usd, HARD_CEILINGS.first_payment_max_usd),
    // force_deep = deep tier on every scan: disable the micropayment bypass.
    microBypassUsd: l.force_deep ? 0 : cfg.microBypassUsd,
    cdpPinVerify: l.cdp_pin_verify || cfg.cdpPinVerify,
    priceScan: l.price_per_scan,
  };
}

/**
 * Activate (or renew) a plan on a key record. Payment enforcement is the API
 * layer's job — call this only after the x402 payment for `plan.price` has
 * settled (or in dev mode). Renewing an active plan extends from its current
 * expiry; switching plans starts fresh from now.
 */
export function activatePlanOnKey(store: Store, apiKey: string, plan: Plan): { plan_id: string; expires_at: string } {
  const h = hashKey(apiKey);
  const rec = store.keys.get(h);
  if (!rec) throw new Error("unknown API key");
  const now = Date.now();
  const currentExpiry =
    rec.plan === plan.id && rec.plan_expires_at ? new Date(rec.plan_expires_at).getTime() : 0;
  const base = Math.max(now, currentExpiry);
  const expires = new Date(base + plan.duration_days * 24 * 3600_000).toISOString();
  rec.plan = plan.id;
  rec.plan_expires_at = expires;
  store.markDirty();
  return { plan_id: plan.id, expires_at: expires };
}

/** Machine-readable catalog for GET /v1/plans, the manifest, and the agent card. */
export function plansCatalog(cfg: PaySafeConfig): object {
  return {
    plans: [
      {
        id: "starter",
        name: "Starter (default)",
        price: "$0.00",
        duration_days: null,
        description: `Default tier for every API key: first ${cfg.freeCalls} calls free, then ${cfg.priceScan}/scan via x402.`,
        limits: {
          price_per_scan: cfg.priceScan,
          max_payments_per_minute: cfg.maxPaymentsPerMinute,
          max_usd_per_hour: cfg.maxUsdPerHour,
          first_payment_max_usd: cfg.firstPaymentMaxUsd,
          force_deep: false,
          cdp_pin_verify: cfg.cdpPinVerify,
        },
      },
      ...PLANS,
    ],
    hard_ceilings: HARD_CEILINGS,
    not_configurable:
      "Replay detection, merchant pinning, asset verification, and PII/secret detection are always on for every tier and cannot be relaxed by any plan.",
    how_to_subscribe: {
      endpoint: "POST /v1/plans/subscribe",
      body: { plan: "<plan id>" },
      headers: { "X-API-Key": "<your key from POST /v1/keys — omit to have one minted and returned>" },
      payment: "x402 (exact scheme, USDC): the 402 challenge quotes the plan price; pay and retry as with any x402 resource.",
      renewal: "POST the same body again before expiry — the new period extends from your current expiry, not from today.",
      response: { plan: "<plan id>", api_key: "<only present when newly minted>", expires_at: "<ISO 8601>" },
    },
  };
}

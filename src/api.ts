/**
 * Framework-agnostic API handlers. Both the production Express app (index.ts)
 * and the zero-dependency dev server (devserver.ts) route into these.
 */
import { randomUUID, timingSafeEqual } from "node:crypto";
import type { PaySafeConfig } from "./config.ts";
import { hashApiKey, type Store } from "./store.ts";
import type { VerdictSigner } from "./verdictsign.ts";
import { runScan } from "./scanner.ts";
import { sanitizeScanRequest } from "./sanitize.ts";
import { paymentCommitment, paymentDigest } from "./commitment.ts";
import { addReport, summarize } from "./reputation.ts";
import { activatePlanOnKey, activePlan, getPlan, plansCatalog, resolveEffectiveConfig } from "./plans.ts";

export interface ApiResult {
  status: number;
  body: unknown;
}

/** Keys are hashed at rest via store.hashApiKey (audit M-3); raw shown once, on issue. */
const hashKey = hashApiKey;

/** 401 body for a key that is positively dead. Deliberately specific: unlike
 * "unknown key" (kept indistinguishable from a typo so probes learn nothing),
 * a tombstoned key is already unusable — naming why it stopped working is
 * pure operational value for the legitimate owner mid-incident. */
function deadKeyResult(dead: "rotated" | "revoked"): ApiResult {
  return {
    status: 401,
    body: {
      error:
        dead === "rotated"
          ? "This API key was rotated and its grace period has ended. Use the replacement key returned by POST /v1/keys/rotate."
          : "This API key was revoked. Mint a fresh key with POST /v1/keys.",
      code: dead === "rotated" ? "key_rotated" : "key_revoked",
    },
  };
}

function mintKey(store: Store, agentId?: string): string {
  const key = `psk_${randomUUID().replace(/-/g, "")}`;
  store.keys.set(hashKey(key), {
    created_at: new Date().toISOString(),
    agent_id: typeof agentId === "string" ? agentId.slice(0, 200) : undefined,
    calls_used: 0,
  });
  store.markDirty();
  return key;
}

export function createApiKey(store: Store, cfg: PaySafeConfig, agentId?: string): ApiResult {
  const key = mintKey(store, agentId);
  return {
    status: 201,
    body: {
      api_key: key,
      free_calls_remaining: cfg.freeCalls,
      note: `Send this key in the X-API-Key header. Your first ${cfg.freeCalls} calls are free; after that, calls are paid via x402 (${cfg.priceScan}/scan). Store it now — it is not recoverable.`,
    },
  };
}

/**
 * Free-tier check. Returns true if this request should bypass x402 payment
 * (valid key with remaining free quota). Increments usage on success.
 */
export function consumeFreeCall(store: Store, cfg: PaySafeConfig, apiKey: string | undefined): boolean {
  const { rec } = store.resolveKey(apiKey);
  if (!rec) return false;
  if (rec.calls_used >= cfg.freeCalls) return false;
  rec.calls_used += 1;
  store.markDirty();
  return true;
}

export function freeCallsRemaining(store: Store, cfg: PaySafeConfig, apiKey: string | undefined): number | null {
  const { rec } = store.resolveKey(apiKey);
  if (!rec) return null;
  return Math.max(0, cfg.freeCalls - rec.calls_used);
}

export function handleScan(
  direction: "outgoing" | "incoming",
  body: unknown,
  cfg: PaySafeConfig,
  store: Store,
  signer?: VerdictSigner | null,
  apiKey?: string,
): ApiResult {
  // Sanitization guarantees detector type assumptions: type-confused fields
  // degrade to "absent" (reduced coverage -> flagged), never crash or bypass.
  const req = sanitizeScanRequest(body);
  if (!req) {
    return {
      status: 400,
      body: { error: "Request body must be JSON with a `payment` object. See GET / for the schema." },
    };
  }
  // Per-key plan overrides (velocity/spend headroom, deep-scan policy), clamped
  // to hard ceilings. Safety-critical checks are not plan-configurable.
  const eff = resolveEffectiveConfig(cfg, store, apiKey);
  const scan = runScan(direction, req, eff, store);
  if (signer) scan.attestation = signer.attest(scan, paymentCommitment(req.payment));

  // Tamper-evident audit record of the DECISION. Stores only a hash of the
  // payment — never the plaintext PII/secrets that were scanned.
  store.auditLog?.append({
    ts: scan.scanned_at,
    scan_id: scan.scan_id,
    direction: scan.direction,
    verdict: scan.verdict,
    risk_score: scan.risk_score,
    agent_id: req.agent_id,
    payment_sha256: paymentDigest(req.payment),
    network: req.payment.network,
    pay_to: req.payment.pay_to,
    amount_usd: req.expected_price_usd ?? req.payment.amount_usd ?? null,
    fired: scan.checks.filter((c) => c.verdict !== "allow").map((c) => c.id),
    attestation_sig: scan.attestation?.signature_hex,
  });

  // Per-key aggregate stats for the usage dashboard (counts only — no payment
  // data, no PII). Only recorded for a recognized key; anonymous paid scans
  // aren't attributable to an account.
  if (apiKey) {
    const { rec } = store.resolveKey(apiKey);
    if (rec) {
      const s = rec.scans ?? { total: 0, allow: 0, flag: 0, block: 0 };
      s.total += 1;
      s[scan.verdict] += 1;
      rec.scans = s;
      rec.last_used_at = scan.scanned_at;
      store.markDirty();
    }
  }

  return { status: 200, body: scan };
}

export function handleReputationLookup(address: string, store: Store): ApiResult {
  if (typeof address !== "string" || address.length < 6 || address.length > 200) {
    return { status: 400, body: { error: "Provide a wallet address, e.g. /v1/reputation/0xabc..." } };
  }
  return { status: 200, body: summarize(store, address) };
}

export function handleReputationReport(body: unknown, store: Store): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const s = (v: unknown): string => (typeof v === "string" ? v : "");
  const res = addReport(store, {
    address: s(b.address).slice(0, 200),
    category: s(b.category),
    reason: s(b.reason).slice(0, 1000),
    reporter_agent_id: s(b.reporter_agent_id).slice(0, 200),
    evidence_url: typeof b.evidence_url === "string" ? b.evidence_url.slice(0, 2000) : undefined,
  });
  if (!res.ok) return { status: 400, body: { error: res.error } };
  return { status: 201, body: { accepted: true, report: res.report } };
}

export function handlePlansCatalog(cfg: PaySafeConfig): ApiResult {
  return { status: 200, body: plansCatalog(cfg) };
}

/**
 * Activate/renew a plan on the caller's key. Payment enforcement happens in
 * the transport layer (index.ts gates this route with x402 at the plan's
 * price); by the time this runs, the subscription fee has settled (or the
 * server is in dev mode). If no key is supplied, one is minted and returned.
 */
export function handlePlanSubscribe(body: unknown, cfg: PaySafeConfig, store: Store, apiKey?: string): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const planId = typeof b.plan === "string" ? b.plan : "";
  const plan = getPlan(planId);
  if (!plan) {
    return { status: 400, body: { error: `Unknown plan. Valid plans: ${["pro", "scale"].join(", ")} — see GET /v1/plans.` } };
  }
  let key = apiKey;
  let minted = false;
  // resolveKey (not a raw hash lookup) so an in-grace rotated key renews its
  // own account instead of getting a brand-new one minted.
  if (!key || !store.resolveKey(key).rec) {
    key = mintKey(store, typeof b.agent_id === "string" ? b.agent_id : undefined);
    minted = true;
  }
  const activated = activatePlanOnKey(store, key, plan);
  return {
    status: 200,
    body: {
      plan: activated.plan_id,
      expires_at: activated.expires_at,
      ...(minted ? { api_key: key, note: "New API key minted (none supplied). Store it now — it is not recoverable." } : {}),
      limits: plan.limits,
      renewal: "POST the same body again before expiry to extend from the current expiry date.",
    },
  };
}

/**
 * Usage stats for the CALLER'S OWN key (X-API-Key). A key can only ever see
 * its own account — the lookup is keyed by the hash of the presented key, so
 * there is no way to read another account's data, and no key is ever returned
 * or logged. Aggregates only; contains no payment data or PII.
 */
export function handleUsage(cfg: PaySafeConfig, store: Store, apiKey: string | undefined): ApiResult {
  if (!apiKey) {
    return { status: 401, body: { error: "Provide your API key in the X-API-Key header." } };
  }
  const resolved = store.resolveKey(apiKey);
  if (resolved.dead) return deadKeyResult(resolved.dead);
  const rec = resolved.rec;
  if (!rec) {
    // Same shape as an auth failure — never distinguish "no such key" from
    // "wrong key", to avoid confirming key validity to a probe.
    return { status: 401, body: { error: "Unknown or invalid API key." } };
  }
  const active = activePlan(store, apiKey);
  const scans = rec.scans ?? { total: 0, allow: 0, flag: 0, block: 0 };
  return {
    status: 200,
    body: {
      account: {
        created_at: rec.created_at,
        agent_id: rec.agent_id ?? null,
        last_used_at: rec.last_used_at ?? null,
      },
      free_tier: {
        included: cfg.freeCalls,
        used: rec.calls_used,
        remaining: Math.max(0, cfg.freeCalls - rec.calls_used),
      },
      plan: active
        ? { id: active.plan.id, name: active.plan.name, expires_at: active.expires_at, price_per_scan: active.plan.limits.price_per_scan }
        : { id: "starter", name: "Starter (default)", expires_at: null, price_per_scan: cfg.priceScan },
      scans: {
        total: scans.total,
        allow: scans.allow,
        flag: scans.flag,
        block: scans.block,
        block_rate: scans.total ? Number((scans.block / scans.total).toFixed(4)) : 0,
      },
    },
  };
}

/** Shared auth for the key-lifecycle endpoints. Returns the live record or an
 * ApiResult error. In-grace rotated secrets are refused (403): a leaked OLD
 * secret must never rotate/revoke the account out from under the real owner. */
function requireLiveKey(
  store: Store,
  apiKey: string | undefined,
): { rec: import("./store.ts").KeyRecord; hash: string } | { err: ApiResult } {
  if (!apiKey) {
    return { err: { status: 401, body: { error: "Provide your API key in the X-API-Key header." } } };
  }
  const r = store.resolveKey(apiKey);
  if (r.dead) return { err: deadKeyResult(r.dead) };
  if (!r.rec || !r.hash) {
    return { err: { status: 401, body: { error: "Unknown or invalid API key." } } };
  }
  if (r.viaGrace) {
    return {
      err: {
        status: 403,
        body: {
          error:
            "This key was already rotated. It still works for scans until its grace period ends, but only the current key can rotate or revoke the account.",
          code: "key_superseded",
        },
      },
    };
  }
  return { rec: r.rec, hash: r.hash };
}

const GRACE_DEFAULT_SECONDS = 900; // 15 min: long enough to redeploy a fleet
const GRACE_MAX_SECONDS = 86_400; // 24 h hard cap — a leaked key must die

/**
 * Rotate the caller's API key: mint a fresh secret bound to the SAME account.
 * Usage counters, remaining free calls, plan, and dashboard stats all carry
 * over — the psk_ secret is a credential, not the identity. The old secret
 * keeps working for `grace_seconds` (default 900, 0 = immediately dead, max
 * 24h) so a fleet can switch over without downtime; during grace it can scan
 * but NOT rotate/revoke (see requireLiveKey). Rotation never resets the free
 * tier, so it cannot be farmed.
 */
export function handleKeyRotate(store: Store, cfg: PaySafeConfig, apiKey: string | undefined, body: unknown): ApiResult {
  const auth = requireLiveKey(store, apiKey);
  if ("err" in auth) return auth.err;
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const requested = typeof b.grace_seconds === "number" && Number.isFinite(b.grace_seconds) ? b.grace_seconds : GRACE_DEFAULT_SECONDS;
  const grace = Math.min(Math.max(Math.floor(requested), 0), GRACE_MAX_SECONDS);

  const newKey = `psk_${randomUUID().replace(/-/g, "")}`;
  const newHash = hashKey(newKey);
  const now = new Date();
  const graceUntil = new Date(now.getTime() + grace * 1000).toISOString();

  // Move the account to the new hash; tombstone the old secret.
  store.keys.delete(auth.hash);
  store.keys.set(newHash, auth.rec);
  store.revoked.set(auth.hash, {
    revoked_at: now.toISOString(),
    reason: "rotated",
    ...(grace > 0 ? { grace_until: graceUntil, successor: newHash } : {}),
  });
  store.markDirty();

  const isAdminKey = !!cfg.adminKeyHash && auth.hash === cfg.adminKeyHash;
  return {
    status: 200,
    body: {
      api_key: newKey,
      api_key_sha256: newHash,
      rotated_at: now.toISOString(),
      previous_key_valid_until: grace > 0 ? graceUntil : null,
      carried_over: {
        free_calls_remaining: Math.max(0, cfg.freeCalls - auth.rec.calls_used),
        plan: auth.rec.plan ?? null,
        scans_total: auth.rec.scans?.total ?? 0,
      },
      note:
        "Store the new key now — it is not recoverable. Your usage history, free-call quota, and plan carried over unchanged." +
        (isAdminKey
          ? " This key is bound to the /admin dashboard (ADMIN_KEY_SHA256): update that env var to api_key_sha256 above, or admin access stays locked."
          : ""),
    },
  };
}

/**
 * Permanently revoke the caller's API key (the leaked-key kill switch).
 * Requires `{"confirm": true}` — this is irreversible: the account's usage
 * history, remaining free calls, and any active plan die with it. The secret's
 * tombstone persists, so the dead key keeps failing with an explanatory 401.
 */
export function handleKeyRevoke(store: Store, cfg: PaySafeConfig, apiKey: string | undefined, body: unknown): ApiResult {
  const auth = requireLiveKey(store, apiKey);
  if ("err" in auth) return auth.err;
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  if (b.confirm !== true) {
    return {
      status: 400,
      body: {
        error:
          'Revocation is irreversible: usage history, remaining free calls, and any active plan are destroyed. POST again with {"confirm": true} to proceed — or use POST /v1/keys/rotate to swap the secret and KEEP the account.',
      },
    };
  }
  const now = new Date().toISOString();
  store.keys.delete(auth.hash);
  store.revoked.set(auth.hash, { revoked_at: now, reason: "revoked" });
  store.markDirty();
  return {
    status: 200,
    body: {
      revoked: true,
      revoked_at: now,
      note: "The key and its account are permanently dead. Mint a fresh key with POST /v1/keys.",
    },
  };
}

/**
 * Owner-only, all-time service stats (the /admin dashboard's data source).
 * Unlocked by the ONE key whose SHA-256 matches cfg.adminKeyHash
 * (ADMIN_KEY_SHA256 env var) — compared in constant time. 404 when
 * unconfigured so the route doesn't advertise itself; 401 otherwise uses the
 * same shape as /v1/usage so probes learn nothing. Aggregates only — no
 * per-customer keys, agent ids, addresses, or payment data are returned.
 */
export function handleAdminStats(cfg: PaySafeConfig, store: Store, apiKey: string | undefined): ApiResult {
  if (!cfg.adminKeyHash) return { status: 404, body: { error: "Not found" } };
  if (!apiKey) {
    return { status: 401, body: { error: "Provide your API key in the X-API-Key header." } };
  }
  const given = Buffer.from(hashKey(apiKey), "utf8");
  const want = Buffer.from(cfg.adminKeyHash, "utf8");
  if (given.length !== want.length || !timingSafeEqual(given, want)) {
    return { status: 401, body: { error: "Unknown or invalid API key." } };
  }
  // The hash match alone isn't enough: a rotated/revoked admin key must lose
  // admin access too (that's the point of revocation). The key must still be
  // LIVE in the store — after rotating the admin key, update ADMIN_KEY_SHA256
  // to the new hash (the rotate response includes it).
  const live = store.resolveKey(apiKey);
  if (!live.rec || live.viaGrace) {
    return { status: 401, body: { error: "Unknown or invalid API key." } };
  }

  // Per-key counters (exist only for keyed scans, since the dashboard feature).
  const keyed = { total: 0, allow: 0, flag: 0, block: 0 };
  let withPlan = 0;
  let active7d = 0;
  const weekAgo = Date.now() - 7 * 86400_000;
  for (const rec of store.keys.values()) {
    if (rec.scans) {
      keyed.total += rec.scans.total;
      keyed.allow += rec.scans.allow;
      keyed.flag += rec.scans.flag;
      keyed.block += rec.scans.block;
    }
    if (rec.plan) withPlan += 1;
    if (rec.last_used_at && Date.parse(rec.last_used_at) > weekAgo) active7d += 1;
  }

  return {
    status: 200,
    body: {
      accounts: { total_keys: store.keys.size, with_plan: withPlan, active_7d: active7d },
      keyed_scans: keyed,
      registry: { reports: store.reports.length, pins: store.pins.size, badlist: store.badlist.size },
      // All-time truth (includes anonymous scans): derived from the audit log.
      audit: store.auditLog
        ? { head: store.auditLog.head(), ...store.auditLog.stats(30) }
        : null,
    },
  };
}

export function serviceInfo(cfg: PaySafeConfig): ApiResult {
  return {
    status: 200,
    body: {
      name: "PaySafe",
      tagline: "Payment security firewall for x402 micropayments. Advisory, non-custodial.",
      version: "1.1.3",
      mode: cfg.mode,
      endpoints: {
        "POST /v1/keys": `Free (rate-limited: ${cfg.keysPerIpPerDay}/IP/day). Issue an API key with a free-call allowance.`,
        "POST /v1/keys/rotate": "Free (X-API-Key header). Swap your key's secret for a fresh one — usage, free quota, and plan carry over. Old secret honors an optional grace window (default 15 min, max 24 h).",
        "POST /v1/keys/revoke": 'Free (X-API-Key header, body {"confirm": true}). Permanently kill a leaked key AND its account. Irreversible.',
        "POST /v1/scan/outgoing": `${cfg.priceScan} (first ${cfg.freeCalls} calls free per key). Screen a payment your agent is about to make.`,
        "POST /v1/scan/incoming": `${cfg.priceScan} (first ${cfg.freeCalls} calls free per key). Screen a payment request / 402 offer your agent received.`,
        "GET /v1/reputation/:address": `${cfg.priceReputation} (first ${cfg.freeCalls} calls free per key). Counterparty report summary.`,
        "POST /v1/reputation/report": `Free (rate-limited: ${cfg.reportsPerIpPerHour}/IP/hour). Report a bad counterparty after the fact.`,
        "GET /v1/plans": "Free. Machine-readable plan catalog (pricing tiers, limits, how to subscribe).",
        "POST /v1/trust/evaluate": `Free (rate-limited: ${cfg.trustQueriesPerIpPerHour}/IP/hour). x402 trust-provider interface: TrustQuery about a payer in, TrustEvaluation (PASS/FAIL/UNCERTAIN + evidence) out — for sellers gating settlement.`,
        "POST /v1/plans/subscribe": "x402-paid at the plan's price. Upgrade your API key to a plan; renew by paying again.",
        "GET /v1/usage": "Free. Your own key's usage stats (X-API-Key header): scan/verdict counts, free-tier quota, plan status.",
        "GET /dashboard": "Free. Browser usage dashboard for your key — key is sent via header only, never a URL.",
        "GET /.well-known/x402": "Free. x402 manifest.",
        "GET /.well-known/agent-card.json": "Free. Agent card.",
        "GET /.well-known/paysafe-verdict-key": "Free. Ed25519 public key for verdict attestations.",
        "GET /health": "Free. Liveness.",
      },
      checks: [
        "pii: PII/secret detection on resource_url, description, reason, metadata",
        "replay: nonce reuse tracking",
        "overpay: configurable multiple-of-expected-price + absolute ceiling + non-positive amounts",
        "injection: prompt-injection-triggered payment provenance analysis (fast tier)",
        "injection-deep: base64 + unicode-obfuscation rescan (bypassed below MICRO_BYPASS_USD; policy.force_deep overrides)",
        "url: resource URL structural risk (incoming)",
        "asset: canonical-USDC verification (lookalike-token defense)",
        "badlist: known-bad address list",
        "pin: TOFU merchant pinning (domain -> pay_to) + optional async CDP cross-check",
        "poison: address-poisoning detection (pay_to matching a known counterparty/pinned merchant on first+last chars but differing in the middle)",
        "scout: ScoutScore external trust signal for merchant domains (opt-in, async + cached, flag-only)",
        "velocity: rate, hourly spend cap, first-contact size cap (outgoing)",
        "reputation: shared counterparty report registry",
      ],
      attestation:
        "Verdicts are Ed25519-signed (see /.well-known/paysafe-verdict-key). Wallet policies can require a fresh allow-verdict before signing.",
      scan_request_schema: {
        agent_id: "string (optional, scopes velocity limits)",
        payment: {
          scheme: "exact",
          network: "eip155:8453",
          asset: "0x... (token contract; enables canonical-USDC verification)",
          amount: "atomic units, e.g. '10000'",
          amount_usd: "or decimal USD",
          asset_decimals: 6,
          pay_to: "0x... recipient",
          payer: "0x... payer (optional)",
          resource_url: "https://...",
          description: "string",
          reason: "why the agent is paying",
          nonce: "payment nonce",
          metadata: { any: "string values" },
        },
        expected_price_usd: 0.01,
        context: {
          origin: "planning | user_instruction | tool_result | fetched_content | unknown",
          content: "the content the agent just read (for injection analysis)",
          content_source_url: "https://...",
        },
        policy: {
          force_deep: "boolean — run deep content analysis even below the micropayment threshold",
          skip_deep: "boolean — skip deep analysis regardless of value",
        },
      },
      custody: "PaySafe never touches private keys, wallets, or funds. Verdicts are advisory (and signed, for wallets that choose to enforce them).",
    },
  };
}

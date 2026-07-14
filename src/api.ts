/**
 * Framework-agnostic API handlers. Both the production Express app (index.ts)
 * and the zero-dependency dev server (devserver.ts) route into these.
 */
import { randomUUID } from "node:crypto";
import type { PaySafeConfig } from "./config.ts";
import type { Store } from "./store.ts";
import type { VerdictSigner } from "./verdictsign.ts";
import { runScan } from "./scanner.ts";
import { sanitizeScanRequest } from "./sanitize.ts";
import { addReport, summarize } from "./reputation.ts";

export interface ApiResult {
  status: number;
  body: unknown;
}

export function createApiKey(store: Store, cfg: PaySafeConfig, agentId?: string): ApiResult {
  const key = `psk_${randomUUID().replace(/-/g, "")}`;
  store.keys.set(key, {
    created_at: new Date().toISOString(),
    agent_id: typeof agentId === "string" ? agentId.slice(0, 200) : undefined,
    calls_used: 0,
  });
  store.markDirty();
  return {
    status: 201,
    body: {
      api_key: key,
      free_calls_remaining: cfg.freeCalls,
      note: `Send this key in the X-API-Key header. Your first ${cfg.freeCalls} calls are free; after that, calls are paid via x402 (${cfg.priceScan}/scan).`,
    },
  };
}

/**
 * Free-tier check. Returns true if this request should bypass x402 payment
 * (valid key with remaining free quota). Increments usage on success.
 */
export function consumeFreeCall(store: Store, cfg: PaySafeConfig, apiKey: string | undefined): boolean {
  if (!apiKey) return false;
  const rec = store.keys.get(apiKey);
  if (!rec) return false;
  if (rec.calls_used >= cfg.freeCalls) return false;
  rec.calls_used += 1;
  store.markDirty();
  return true;
}

export function freeCallsRemaining(store: Store, cfg: PaySafeConfig, apiKey: string | undefined): number | null {
  if (!apiKey) return null;
  const rec = store.keys.get(apiKey);
  if (!rec) return null;
  return Math.max(0, cfg.freeCalls - rec.calls_used);
}

export function handleScan(
  direction: "outgoing" | "incoming",
  body: unknown,
  cfg: PaySafeConfig,
  store: Store,
  signer?: VerdictSigner | null,
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
  const scan = runScan(direction, req, cfg, store);
  if (signer) scan.attestation = signer.attest(scan);
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

export function serviceInfo(cfg: PaySafeConfig): ApiResult {
  return {
    status: 200,
    body: {
      name: "PaySafe",
      tagline: "Payment security firewall for x402 micropayments. Advisory, non-custodial.",
      version: "1.1.0",
      mode: cfg.mode,
      endpoints: {
        "POST /v1/keys": `Free (rate-limited: ${cfg.keysPerIpPerDay}/IP/day). Issue an API key with a free-call allowance.`,
        "POST /v1/scan/outgoing": `${cfg.priceScan} (first ${cfg.freeCalls} calls free per key). Screen a payment your agent is about to make.`,
        "POST /v1/scan/incoming": `${cfg.priceScan} (first ${cfg.freeCalls} calls free per key). Screen a payment request / 402 offer your agent received.`,
        "GET /v1/reputation/:address": `${cfg.priceReputation} (first ${cfg.freeCalls} calls free per key). Counterparty report summary.`,
        "POST /v1/reputation/report": `Free (rate-limited: ${cfg.reportsPerIpPerHour}/IP/hour). Report a bad counterparty after the fact.`,
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

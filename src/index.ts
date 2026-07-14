/**
 * PaySafe — production entrypoint.
 * Express + official x402 middleware (@x402/express) + CDP facilitator + Bazaar discovery.
 *
 * Paid routes (x402, "exact" scheme, USDC):
 *   POST /v1/scan/outgoing        cfg.priceScan
 *   POST /v1/scan/incoming        cfg.priceScan
 *   GET  /v1/reputation/:address  cfg.priceReputation
 * Free routes (rate-limited where writable):
 *   POST /v1/keys, POST /v1/reputation/report, GET /, /health, /.well-known/*
 *
 * Free tier: first cfg.freeCalls calls per API key (X-API-Key header) bypass payment.
 */
import express from "express";
import { join } from "node:path";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import {
  bazaarResourceServerExtension,
  declareDiscoveryExtension,
} from "@x402/extensions/bazaar";

import { loadConfig } from "./config.ts";
import { Store } from "./store.ts";
import { AuditLog } from "./auditlog.ts";
import { VerdictSigner } from "./verdictsign.ts";
import { RateLimiter } from "./ratelimit.ts";
import {
  consumeFreeCall,
  createApiKey,
  freeCallsRemaining,
  handleReputationLookup,
  handleReputationReport,
  handleScan,
  serviceInfo,
} from "./api.ts";
import { x402Manifest, agentCard } from "./manifest.ts";

const cfg = loadConfig();
const store = new Store(cfg.dataDir, {
  nonceTtlHours: cfg.nonceTtlHours,
  maxEntries: cfg.maxStoreEntries,
});
store.loadBadlist(cfg.badlistPath ?? join(cfg.dataDir, "badlist.json"));
if (cfg.auditLog) store.auditLog = new AuditLog(join(cfg.dataDir, "audit.log"));
const signer = cfg.verdictSigning ? new VerdictSigner(cfg.dataDir) : null;

const keyLimiter = new RateLimiter(cfg.keysPerIpPerDay, 24 * 3600_000);
const reportLimiter = new RateLimiter(cfg.reportsPerIpPerHour, 3600_000);

if (cfg.mode === "live" && !cfg.payTo) {
  console.error("PAY_TO (receiving wallet address) is required in live mode. Set PAYSAFE_MODE=dev to run without payments.");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1); // Render/most PaaS terminate TLS at a proxy; req.ip = client IP
// Audit C-1: make the router reject path variants (trailing slash, case) rather
// than route them to a handler that the payment gate's exact-string matcher
// would then let through for free. Combined with the normalized matcher below.
app.set("strict routing", true);
app.set("case sensitive routing", true);
app.use(express.json({ limit: "512kb" }));

// ---------------------------------------------------------------------------
// x402 payment layer
// ---------------------------------------------------------------------------
const SCAN_PAYMENT_EXAMPLE = {
  payment: {
    scheme: "exact",
    network: "eip155:8453",
    amount: "50000",
    asset_decimals: 6,
    pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    resource_url: "https://api.example.com/premium",
    description: "Premium data access",
    nonce: "0x1a2b3c",
  },
  expected_price_usd: 0.05,
  context: { origin: "planning" },
};

const SCAN_INPUT_SCHEMA = {
  properties: {
    agent_id: { type: "string", description: "Identifier of the scanning agent (scopes velocity limits)" },
    payment: {
      type: "object",
      description:
        "The x402 payment (or payment request) to screen: scheme, network, amount (atomic) or amount_usd, asset, pay_to, payer, resource_url, description, reason, nonce, metadata",
    },
    expected_price_usd: { type: "number", description: "What the agent expected this to cost (USD)" },
    context: {
      type: "object",
      description:
        "Provenance: origin (planning|user_instruction|tool_result|fetched_content|unknown), content (the content the agent just read), content_source_url",
    },
    policy: {
      type: "object",
      description: "Tiering overrides: force_deep / skip_deep for the deep content-analysis tier",
    },
  },
  required: ["payment"],
};

const SCAN_OUTPUT_EXAMPLE = {
  scan_id: "6f9c9d5e-…",
  direction: "outgoing",
  verdict: "block",
  risk_score: 95,
  checks: [
    {
      id: "replay.nonce_reuse",
      verdict: "block",
      severity: "critical",
      reason: "Nonce reuse detected: first seen 2026-07-14T09:00:00Z …",
    },
  ],
  scanned_at: "2026-07-14T09:01:00Z",
  advisory: "Recommended action: DO NOT settle this payment. …",
  attestation: {
    alg: "ed25519",
    message: "6f9c9d5e-…|outgoing|block|95|2026-07-14T09:01:00Z",
    signature_hex: "…",
  },
};

function buildX402Layer() {
  const facilitatorClient =
    cfg.facilitator === "cdp"
      ? new HTTPFacilitatorClient(cdpFacilitator) // uses CDP_API_KEY_ID / CDP_API_KEY_SECRET env vars
      : new HTTPFacilitatorClient({ url: "https://x402.org/facilitator" });

  // The SDK types CAIP-2 network ids as a template-literal type.
  const network = cfg.network as `${string}:${string}`;

  const server = new x402ResourceServer(facilitatorClient).register(
    network,
    new ExactEvmScheme(),
  );

  // Bazaar indexing: register the resource-server extension so declared
  // discovery metadata is attached to verify/settle calls and CDP catalogs
  // the routes after the first successful settlement.
  try {
    const s = server as unknown as {
      registerExtension?: (ext: unknown) => unknown;
      use?: (ext: unknown) => unknown;
    };
    if (typeof s.registerExtension === "function") s.registerExtension(bazaarResourceServerExtension);
    else if (typeof s.use === "function") s.use(bazaarResourceServerExtension);
  } catch (err) {
    console.warn("Bazaar extension registration failed (service still works, just not Bazaar-indexed):", err);
  }

  const scanAccepts = [
    { scheme: "exact", price: cfg.priceScan, network, payTo: cfg.payTo },
  ];

  // Typed loosely: the SDK's RoutesConfig uses branded/template-literal types
  // that vary across minor versions; the runtime shape below follows the
  // official seller quickstart exactly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const routes: any = {
    "POST /v1/scan/outgoing": {
      accepts: scanAccepts,
      description:
        "Payment security firewall scan for an OUTGOING x402 payment: PII/secret leak detection in payment metadata, nonce replay detection, overpayment detection, prompt-injection-triggered payment analysis (fast + deep tiers), canonical-USDC asset verification, merchant pinning, velocity/spend caps, and counterparty reputation cross-check. Returns allow/flag/block with per-check reasons and an Ed25519-signed verdict. Advisory and non-custodial.",
      mimeType: "application/json",
      extensions: {
        ...declareDiscoveryExtension({
          input: SCAN_PAYMENT_EXAMPLE,
          inputSchema: SCAN_INPUT_SCHEMA,
          bodyType: "json",
          output: { example: SCAN_OUTPUT_EXAMPLE },
        }),
      },
    },
    "POST /v1/scan/incoming": {
      accepts: scanAccepts,
      description:
        "Payment security firewall scan for an INCOMING x402 payment request (402 offer): resource URL risk, credential-demand detection, price sanity, replay detection, canonical-USDC asset verification, merchant pinning, and counterparty reputation. Returns allow/flag/block with per-check reasons and an Ed25519-signed verdict. Advisory and non-custodial.",
      mimeType: "application/json",
      extensions: {
        ...declareDiscoveryExtension({
          input: SCAN_PAYMENT_EXAMPLE,
          inputSchema: SCAN_INPUT_SCHEMA,
          bodyType: "json",
          output: { example: { ...SCAN_OUTPUT_EXAMPLE, direction: "incoming" } },
        }),
      },
    },
    "GET /v1/reputation/:address": {
      accepts: [
        { scheme: "exact", price: cfg.priceReputation, network, payTo: cfg.payTo },
      ],
      description:
        "Counterparty reputation lookup for x402 payments: aggregated post-hoc reports (scam, non-delivery, prompt injection, overcharge, impersonation, replay abuse) filed by other agents, with distinct-reporter counts and risk level.",
      mimeType: "application/json",
      extensions: {
        ...declareDiscoveryExtension({
          input: { address: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C" },
          inputSchema: {
            properties: {
              address: { type: "string", description: "Wallet address to look up" },
            },
            required: ["address"],
          },
          output: {
            example: {
              address: "0x…",
              status: "reported",
              risk: "medium",
              report_count: 3,
              distinct_reporters: 2,
              categories: { non_delivery: 2, overcharge: 1 },
            },
          },
        }),
      },
    },
  };

  return paymentMiddleware(routes, server);
}

if (cfg.mode === "live") {
  const paid = buildX402Layer();

  // Normalize before matching so a trailing slash or different case can never
  // route a request AROUND the payment gate (audit C-1).
  const isPaidRoute = (req: express.Request): boolean => {
    const p = req.path.replace(/\/+$/, "").toLowerCase();
    return (
      (req.method === "POST" && (p === "/v1/scan/outgoing" || p === "/v1/scan/incoming")) ||
      (req.method === "GET" && /^\/v1\/reputation\/[^/]+$/.test(p))
    );
  };

  app.use((req, res, next) => {
    if (!isPaidRoute(req)) return next();
    const apiKey = req.header("x-api-key");
    if (consumeFreeCall(store, cfg, apiKey)) {
      const remaining = freeCallsRemaining(store, cfg, apiKey);
      if (remaining !== null) res.setHeader("X-Free-Calls-Remaining", String(remaining));
      return next(); // free-tier call: skip payment
    }
    return paid(req, res, next); // x402: 402 → pay → retry
  });
} else {
  console.log("PaySafe running in DEV mode — x402 payments disabled, all endpoints free.");
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.get("/", (_req, res) => {
  const r = serviceInfo(cfg);
  res.status(r.status).json(r.body);
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, mode: cfg.mode, time: new Date().toISOString() });
});

app.get("/.well-known/x402", (_req, res) => {
  res.json(x402Manifest(cfg));
});

app.get("/.well-known/agent-card.json", (_req, res) => {
  res.json(agentCard(cfg));
});

app.get("/.well-known/paysafe-verdict-key", (_req, res) => {
  if (!signer) {
    res.status(404).json({ error: "Verdict signing disabled (VERDICT_SIGNING=off)" });
    return;
  }
  res.json(signer.publicKeyInfo());
});

app.post("/v1/keys", (req, res) => {
  if (!keyLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.keysPerIpPerDay} keys per IP per day.` });
    return;
  }
  const r = createApiKey(store, cfg, (req.body as { agent_id?: string } | undefined)?.agent_id);
  res.status(r.status).json(r.body);
});

app.post("/v1/scan/outgoing", (req, res) => {
  const r = handleScan("outgoing", req.body, cfg, store, signer);
  res.status(r.status).json(r.body);
});

app.post("/v1/scan/incoming", (req, res) => {
  const r = handleScan("incoming", req.body, cfg, store, signer);
  res.status(r.status).json(r.body);
});

app.get("/v1/reputation/:address", (req, res) => {
  const r = handleReputationLookup(req.params.address, store);
  res.status(r.status).json(r.body);
});

app.post("/v1/reputation/report", (req, res) => {
  if (!reportLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.reportsPerIpPerHour} reports per IP per hour.` });
    return;
  }
  const r = handleReputationReport(req.body, store);
  res.status(r.status).json(r.body);
});

// Audit trail integrity (no record contents exposed — only chain head + a
// verification result). Useful for external monitoring / anchoring.
app.get("/v1/audit/head", (_req, res) => {
  if (!store.auditLog) {
    res.status(404).json({ error: "Audit log disabled (AUDIT_LOG=off)" });
    return;
  }
  res.json(store.auditLog.head());
});

app.get("/v1/audit/verify", (_req, res) => {
  if (!store.auditLog) {
    res.status(404).json({ error: "Audit log disabled (AUDIT_LOG=off)" });
    return;
  }
  res.json(store.auditLog.verify());
});

// JSON error handler: never leak stack traces.
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("handler error:", err);
  res.status(500).json({ error: "internal error" });
});

const serverInstance = app.listen(cfg.port, () => {
  console.log(`PaySafe listening on :${cfg.port} (${cfg.mode} mode, network ${cfg.network}, facilitator ${cfg.facilitator})`);
});

process.on("SIGTERM", () => {
  serverInstance.close(() => {
    store.close();
    process.exit(0);
  });
});

/** /.well-known/x402 manifest + agent card. */
import type { PaySafeConfig } from "./config.ts";

// USDC contract addresses per network (for manifest display; the x402
// middleware resolves assets itself from the price string).
const USDC: Record<string, string> = {
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
};

function priceToAtomicUsdc(price: string): string {
  const usd = Number(price.replace("$", ""));
  return String(Math.round(usd * 1_000_000));
}

function resourceEntry(cfg: PaySafeConfig, path: string, description: string, price: string) {
  return {
    resource: `${cfg.publicBaseUrl}${path}`,
    type: "http",
    x402Version: 2,
    accepts: [
      {
        scheme: "exact",
        network: cfg.network,
        amount: priceToAtomicUsdc(price),
        asset: USDC[cfg.network] ?? USDC["eip155:8453"],
        payTo: cfg.payTo,
        maxTimeoutSeconds: 60,
      },
    ],
    metadata: { description },
  };
}

export function x402Manifest(cfg: PaySafeConfig): object {
  return {
    x402Version: 2,
    name: "PaySafe",
    description:
      "Payment security firewall for x402 micropayments: screens outgoing and incoming payment traffic for PII/secret leakage, nonce replay, overpayment, and prompt-injection-triggered payments, plus a shared counterparty report registry. Advisory and non-custodial.",
    resources: [
      resourceEntry(
        cfg,
        "/v1/scan/outgoing",
        "Screen an outgoing x402 payment before settlement: PII/secret detection on payment metadata, nonce replay detection, overpayment detection, prompt-injection provenance analysis, counterparty reputation cross-check. Returns allow/flag/block with reasons.",
        cfg.priceScan,
      ),
      resourceEntry(
        cfg,
        "/v1/scan/incoming",
        "Screen an incoming x402 payment request (402 offer): resource URL risk, credential-demand detection, price sanity, replay, counterparty reputation. Returns allow/flag/block with reasons.",
        cfg.priceScan,
      ),
      resourceEntry(
        cfg,
        "/v1/reputation/{address}",
        "Counterparty reputation lookup: shared post-hoc report registry (scam, non-delivery, prompt injection, overcharge, impersonation, replay abuse) aggregated across reporting agents.",
        cfg.priceReputation,
      ),
    ],
    free_tier: `First ${cfg.freeCalls} calls free per API key — POST /v1/keys (no payment) to get one.`,
    reporting: `POST /v1/reputation/report is always free, so agents can flag bad counterparties after the fact.`,
    custody: "non-custodial; advisory verdicts only",
    plans: {
      catalog: `${cfg.publicBaseUrl}/v1/plans`,
      summary:
        "Subscription tiers with lower per-scan pricing and higher velocity/spend headroom. Agents can subscribe and renew autonomously: POST /v1/plans/subscribe is itself x402-paid at the plan price. Safety-critical checks are identical on every tier.",
    },
  };
}

export function agentCard(cfg: PaySafeConfig): object {
  return {
    protocolVersion: "0.3.0",
    name: "PaySafe",
    description:
      "A payment security firewall for agentic x402 micropayments. PaySafe screens outgoing and incoming payment traffic for known vulnerability classes — PII/secret leakage in payment metadata, nonce replay, overpayment, and prompt-injection-triggered payments — and maintains a shared counterparty report registry. It never holds keys or funds; verdicts are advisory and wrap whatever wallet/facilitator the agent already uses.",
    url: cfg.publicBaseUrl,
    provider: { organization: "PaySafe", url: cfg.publicBaseUrl },
    version: "1.0.0",
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [
      {
        id: "scan_outgoing_payment",
        name: "Scan outgoing payment",
        description:
          "Screen a payment the agent is about to make. Detects PII/secrets in metadata, nonce reuse, overpayment vs expected price, and payments triggered by prompt-injected content. Returns allow/flag/block with per-check reasons.",
        tags: ["security", "payments", "x402", "firewall"],
        examples: [
          "Scan this $0.05 USDC payment to 0xabc… for risks before I settle it",
        ],
      },
      {
        id: "scan_incoming_payment",
        name: "Scan incoming payment request",
        description:
          "Screen a 402 offer / payment request the agent received: URL risk, credential demands, price sanity, replay, counterparty reputation.",
        tags: ["security", "payments", "x402", "firewall"],
        examples: ["Is this 402 quote from api.example.com safe to pay?"],
      },
      {
        id: "counterparty_reputation",
        name: "Counterparty reputation lookup & reporting",
        description:
          "Look up shared post-hoc reports on a counterparty address, and file reports (free) after bad experiences.",
        tags: ["reputation", "payments", "x402"],
        examples: ["Has anyone reported 0xdef… for non-delivery?"],
      },
    ],
    payments: {
      protocol: "x402",
      network: cfg.network,
      pricing: {
        "POST /v1/scan/outgoing": `${cfg.priceScan} (less on a plan — see /v1/plans)`,
        "POST /v1/scan/incoming": `${cfg.priceScan} (less on a plan — see /v1/plans)`,
        "GET /v1/reputation/{address}": cfg.priceReputation,
        "POST /v1/reputation/report": "free",
        "GET /v1/plans": "free",
        "POST /v1/plans/subscribe": "x402-paid at the chosen plan's price",
      },
      freeTier: `first ${cfg.freeCalls} calls per API key`,
      plansCatalog: `${cfg.publicBaseUrl}/v1/plans`,
      manifest: `${cfg.publicBaseUrl}/.well-known/x402`,
    },
  };
}

/**
 * OpenAPI 3.1 document for PaySafe, served at GET /openapi.json (free).
 *
 * This is the canonical machine-readable discovery contract used by
 * x402scan and agent tooling. Payment metadata follows the x402scan
 * discovery spec: paid operations carry `x-payment-info` (decimal USD)
 * and a `402` response; runtime 402 behavior remains authoritative.
 * See https://www.x402scan.com/discovery/spec
 */
import type { PaySafeConfig } from "./config.ts";

function usd(price: string): string {
  // "$0.01" -> "0.010000" (decimal USD; NOT atomic units — those are runtime-only)
  return Number(price.replace("$", "")).toFixed(6);
}

function paidOp(price: string) {
  return {
    "x-payment-info": {
      price: { mode: "fixed", currency: "USD", amount: usd(price) },
      protocols: [{ x402: {} }],
    },
  };
}

// ---------------------------------------------------------------------------
// Component schemas (mirror src/types.ts)
// ---------------------------------------------------------------------------
const PaymentDetails = {
  type: "object",
  description:
    "The payment (or 402 offer) to screen. Provide as many fields as you have — every field improves detection coverage.",
  properties: {
    scheme: { type: "string", description: 'x402 scheme, e.g. "exact"' },
    network: { type: "string", description: 'CAIP-2 network id, e.g. "eip155:8453"' },
    asset: { type: "string", description: "Token contract address (e.g. USDC)" },
    amount: { type: "string", description: 'Amount in atomic token units, e.g. "10000" = $0.01 USDC' },
    amount_usd: { type: "number", description: "Alternative: decimal USD value" },
    asset_decimals: { type: "integer", description: "Token decimals if amount is atomic units (default 6 = USDC)" },
    pay_to: { type: "string", description: "Recipient address" },
    payer: { type: "string", description: "Paying agent's address (optional; scopes replay + velocity tracking)" },
    resource_url: { type: "string", description: "The resource being purchased" },
    description: { type: "string" },
    reason: { type: "string", description: "Free-text reason the agent recorded for making this payment" },
    nonce: { type: "string", description: "Payment nonce (from the signed payment payload)" },
    valid_until: { type: "string" },
    metadata: { type: "object", additionalProperties: { type: "string" } },
  },
} as const;

const ScanRequest = {
  type: "object",
  required: ["payment"],
  properties: {
    agent_id: { type: "string", description: "Stable identifier for the calling agent (scopes velocity limits)" },
    payment: PaymentDetails,
    expected_price_usd: {
      type: "number",
      description: "What the agent expected this to cost, in USD (e.g. from the 402 quote or a catalog). Enables overpayment detection.",
    },
    context: {
      type: "object",
      description: "Provenance of the decision to pay. Enables prompt-injection-triggered-payment detection.",
      properties: {
        origin: {
          type: "string",
          enum: ["planning", "user_instruction", "tool_result", "fetched_content", "unknown"],
          description: "Where the decision to pay originated",
        },
        content: { type: "string", description: "The content the agent just read (tool result / fetched page), for injection analysis" },
        content_source_url: { type: "string" },
      },
    },
    policy: {
      type: "object",
      properties: {
        force_deep: { type: "boolean", description: "Run the deep content-analysis tier even below the micropayment threshold" },
        skip_deep: { type: "boolean", description: "Skip the deep tier regardless of value (developer policy)" },
      },
    },
  },
} as const;

const CheckResult = {
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
    verdict: { type: "string", enum: ["allow", "flag", "block"] },
    severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
    reason: { type: "string" },
    details: { type: "object" },
  },
  required: ["id", "name", "verdict", "severity", "reason"],
} as const;

const ScanResponse = {
  type: "object",
  required: ["scan_id", "direction", "verdict", "risk_score", "checks", "scanned_at", "advisory"],
  properties: {
    scan_id: { type: "string" },
    direction: { type: "string", enum: ["outgoing", "incoming"] },
    verdict: { type: "string", enum: ["allow", "flag", "block"] },
    risk_score: { type: "integer", minimum: 0, maximum: 100, description: "0 (clean) – 100 (maximum risk)" },
    checks: { type: "array", items: CheckResult },
    scanned_at: { type: "string" },
    advisory: { type: "string" },
    attestation: {
      type: "object",
      description:
        "Ed25519 attestation binding the verdict to this exact payment. Verify with the key at /.well-known/paysafe-verdict-key.",
      properties: {
        alg: { type: "string", enum: ["ed25519"] },
        public_key_spki_hex: { type: "string" },
        message: { type: "string" },
        signature_hex: { type: "string" },
        payment_commitment: { type: "string", description: "sha256(network|pay_to|asset|amount|nonce)" },
        expires_at: { type: "string" },
      },
    },
  },
} as const;

const ReputationSummary = {
  type: "object",
  properties: {
    address: { type: "string" },
    status: { type: "string", enum: ["clean", "reported"] },
    risk: { type: "string", enum: ["none", "low", "medium", "high"] },
    report_count: { type: "integer" },
    distinct_reporters: { type: "integer" },
    categories: { type: "object", additionalProperties: { type: "integer" } },
    first_reported: { type: "string" },
    last_reported: { type: "string" },
  },
} as const;

const resp402 = { "402": { description: "Payment Required" } } as const;

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------
export function openApiDoc(cfg: PaySafeConfig): object {
  return {
    openapi: "3.1.0",
    info: {
      title: "PaySafe",
      version: "1.0.0",
      description:
        "Check a payment for fraud before your agent sends it. Call PaySafe before settling any x402 payment to avoid paying attacker-controlled addresses injected into content the agent just read (prompt-injection-triggered payments), replayed authorizations, inflated prices, leaked secrets in payment metadata, fake/lookalike USDC contracts, and address poisoning. Returns allow/flag/block with machine-readable reasons and an Ed25519-signed verdict. Advisory and non-custodial — never touches keys or funds. Includes a free-to-use counterparty reputation registry.",
      "x-guidance":
        `Before settling any x402 payment, POST the payment details to /v1/scan/outgoing and act on the verdict: "allow" = proceed, "flag" = pause and confirm intent, "block" = do not pay (machine-readable reasons attached). When you RECEIVE a 402 offer, POST it to /v1/scan/incoming before paying. Include context.origin (planning | tool_result | fetched_content | user_instruction) and, when the decision followed reading external content, context.content — this enables prompt-injection-triggered-payment detection, the check that catches poisoned pay-to addresses. Include expected_price_usd to enable overpayment detection. Endpoints cost ${cfg.priceScan}/call via x402; your first ${cfg.freeCalls} calls are free with an API key from POST /v1/keys (free) sent in the X-API-Key header. Filing counterparty reports via POST /v1/reputation/report is always free. Allow-verdicts carry an Ed25519 attestation bound to the exact payment (verify against /.well-known/paysafe-verdict-key). If you scan at volume, GET /v1/plans lists subscription tiers with lower per-scan pricing and higher velocity/spend headroom; you can subscribe autonomously — POST /v1/plans/subscribe is itself x402-paid at the plan price, and renewing is just paying again before expiry.`,
      contact: { email: "contact@paysafe-agent.com" },
    },
    servers: [{ url: cfg.publicBaseUrl }],
    paths: {
      "/v1/scan/outgoing": {
        post: {
          operationId: "scanOutgoingPayment",
          summary: "Is this payment safe to send? Screen an outgoing payment before settling it",
          tags: ["Scanning"],
          ...paidOp(cfg.priceScan),
          requestBody: {
            required: true,
            content: { "application/json": { schema: ScanRequest } },
          },
          responses: {
            "200": {
              description: "Scan verdict",
              content: { "application/json": { schema: ScanResponse } },
            },
            ...resp402,
          },
        },
      },
      "/v1/scan/incoming": {
        post: {
          operationId: "scanIncomingPayment",
          summary: "Is this 402 offer safe to pay? Screen an incoming payment request before paying it",
          tags: ["Scanning"],
          ...paidOp(cfg.priceScan),
          requestBody: {
            required: true,
            content: { "application/json": { schema: ScanRequest } },
          },
          responses: {
            "200": {
              description: "Scan verdict",
              content: { "application/json": { schema: ScanResponse } },
            },
            ...resp402,
          },
        },
      },
      "/v1/reputation/{address}": {
        get: {
          operationId: "getCounterpartyReputation",
          summary: "Has anyone reported this address? Counterparty reputation lookup",
          tags: ["Reputation"],
          ...paidOp(cfg.priceReputation),
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "Counterparty address (e.g. 0x…)",
            },
          ],
          responses: {
            "200": {
              description: "Report summary",
              content: { "application/json": { schema: ReputationSummary } },
            },
            ...resp402,
          },
        },
      },
      "/v1/reputation/report": {
        post: {
          operationId: "reportCounterparty",
          summary: "Report a bad counterparty (always free)",
          tags: ["Reputation"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["address", "category", "reason", "reporter_agent_id"],
                  properties: {
                    address: { type: "string" },
                    category: {
                      type: "string",
                      enum: ["scam", "non_delivery", "prompt_injection", "overcharge", "impersonation", "replay_abuse", "other"],
                    },
                    reason: { type: "string" },
                    reporter_agent_id: { type: "string" },
                    evidence_url: { type: "string" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Report accepted",
              content: {
                "application/json": {
                  schema: { type: "object", properties: { ok: { type: "boolean" }, report: { type: "object" } } },
                },
              },
            },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/plans": {
        get: {
          operationId: "getPlansCatalog",
          summary: "Machine-readable plan catalog (tiers, limits, pricing, how to subscribe)",
          tags: ["Plans"],
          // Free endpoint: excluded from x402scan's 402-challenge probing.
          security: [],
          responses: {
            "200": {
              description: "Plan catalog",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      plans: { type: "array", items: { type: "object" } },
                      hard_ceilings: { type: "object" },
                      not_configurable: { type: "string" },
                      how_to_subscribe: { type: "object" },
                    },
                  },
                },
              },
            },
          },
        },
      },
      "/v1/plans/subscribe": {
        post: {
          operationId: "subscribeToPlan",
          summary: "Subscribe/renew an API key on a plan (x402-paid at the plan's price)",
          tags: ["Plans"],
          "x-payment-info": {
            // Dynamic: the 402 challenge quotes the chosen plan's price.
            price: { mode: "dynamic", currency: "USD", min: "4.990000", max: "19.990000" },
            protocols: [{ x402: {} }],
          },
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["plan"],
                  properties: {
                    plan: { type: "string", enum: ["pro", "scale"], description: "Plan id from GET /v1/plans" },
                    agent_id: { type: "string", description: "Optional; used only if a new key is minted" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Plan activated or renewed on the key from X-API-Key (a new key is minted and returned if none was supplied)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      plan: { type: "string" },
                      expires_at: { type: "string" },
                      api_key: { type: "string", description: "Only present when newly minted — store it, not recoverable" },
                      limits: { type: "object" },
                      renewal: { type: "string" },
                    },
                  },
                },
              },
            },
            "402": { description: "Payment Required" },
          },
        },
      },
      "/v1/keys": {
        post: {
          operationId: "createApiKey",
          summary: `Issue an API key (free) — first ${cfg.freeCalls} calls free per key`,
          tags: ["Keys"],
          // Free endpoint (not x402-paid): empty security marker excludes it
          // from x402scan's 402-challenge probing (see discovery spec).
          security: [],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: { type: "object", properties: { agent_id: { type: "string" } } },
              },
            },
          },
          responses: {
            "200": {
              description: "New API key (store it now — not recoverable)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      api_key: { type: "string" },
                      free_calls: { type: "integer" },
                      note: { type: "string" },
                    },
                  },
                },
              },
            },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/keys/rotate": {
        post: {
          operationId: "rotateApiKey",
          summary: "Rotate your API key: fresh secret, same account (usage, free quota, and plan carry over)",
          description:
            "Mints a replacement psk_ secret bound to the SAME account. The old secret keeps working for grace_seconds (default 900, 0 = immediately dead, max 86400) so a fleet can switch over, but can no longer rotate or revoke. Rotation never resets the free tier. Authenticate with the current key in X-API-Key.",
          tags: ["Keys"],
          security: [],
          parameters: [
            { name: "X-API-Key", in: "header", required: true, schema: { type: "string" } },
          ],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    grace_seconds: { type: "integer", minimum: 0, maximum: 86400, default: 900, description: "How long the old secret keeps working" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Replacement key (store it now — not recoverable)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      api_key: { type: "string" },
                      api_key_sha256: { type: "string", description: "Hash of the new key (rebind ADMIN_KEY_SHA256 if this was the admin key)" },
                      rotated_at: { type: "string" },
                      previous_key_valid_until: { type: "string", nullable: true },
                      carried_over: {
                        type: "object",
                        properties: {
                          free_calls_remaining: { type: "integer" },
                          plan: { type: "string", nullable: true },
                          scans_total: { type: "integer" },
                        },
                      },
                      note: { type: "string" },
                    },
                  },
                },
              },
            },
            "401": { description: "Missing, unknown, rotated, or revoked key" },
            "403": { description: "An already-rotated (in-grace) key cannot rotate the account" },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/keys/revoke": {
        post: {
          operationId: "revokeApiKey",
          summary: "Permanently revoke your API key (leaked-key kill switch) — irreversible",
          description:
            "Kills the key AND its account: usage history, remaining free calls, and any active plan are destroyed. The tombstone persists, so the dead key keeps failing with an explanatory 401. Requires {\"confirm\": true}. To swap the secret and KEEP the account, use /v1/keys/rotate instead.",
          tags: ["Keys"],
          security: [],
          parameters: [
            { name: "X-API-Key", in: "header", required: true, schema: { type: "string" } },
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["confirm"],
                  properties: { confirm: { type: "boolean", description: "Must be true — revocation is irreversible" } },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Key and account permanently dead",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      revoked: { type: "boolean" },
                      revoked_at: { type: "string" },
                      note: { type: "string" },
                    },
                  },
                },
              },
            },
            "400": { description: "Missing {\"confirm\": true}" },
            "401": { description: "Missing, unknown, rotated, or revoked key" },
            "403": { description: "An already-rotated (in-grace) key cannot revoke the account" },
            "429": { description: "Rate limited" },
          },
        },
      },
    },
  };
}

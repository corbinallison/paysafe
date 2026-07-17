#!/usr/bin/env node
/**
 * PaySafe MCP server — exposes the payment firewall as MCP tools over stdio.
 *
 * Run against production with zero config:  npx paysafe-x402
 *
 * Env:
 *   PAYSAFE_URL      Base URL of a PaySafe instance (default https://paysafe-agent.com)
 *   PAYSAFE_API_KEY  API key from POST /v1/keys or the mint_api_key tool.
 *                    Without it, paid endpoints 402 after the free tier —
 *                    pair with an x402-aware fetch or stay within free quota.
 *
 * Register in an MCP client config:
 *   { "command": "npx", "args": ["-y", "paysafe-x402"], "env": { "PAYSAFE_API_KEY": "..." } }
 */
import { createPublicKey, createHash, verify as edVerify } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const BASE = process.env.PAYSAFE_URL ?? "https://paysafe-agent.com";
const API_KEY = process.env.PAYSAFE_API_KEY;

async function call(method: string, path: string, body?: unknown): Promise<string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (API_KEY) headers["x-api-key"] = API_KEY;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (res.status === 402) {
    return JSON.stringify({
      error: "payment_required",
      hint: "Free-tier quota exhausted or no API key set. Get a key via POST /v1/keys, or route this call through an x402-paying client.",
      x402: JSON.parse(text || "{}"),
    });
  }
  return text;
}

const paymentSchema = z.object({
  scheme: z.string().optional(),
  network: z.string().optional().describe("CAIP-2, e.g. eip155:8453"),
  asset: z.string().optional(),
  amount: z.string().optional().describe("Atomic units, e.g. '10000' = $0.01 USDC"),
  amount_usd: z.number().optional(),
  asset_decimals: z.number().optional(),
  pay_to: z.string().optional(),
  payer: z.string().optional(),
  resource_url: z.string().optional(),
  description: z.string().optional(),
  reason: z.string().optional(),
  nonce: z.string().optional(),
  metadata: z.record(z.string()).optional(),
});

const contextSchema = z
  .object({
    origin: z
      .enum(["planning", "user_instruction", "tool_result", "fetched_content", "unknown"])
      .optional()
      .describe("Where the decision to pay originated"),
    content: z.string().optional().describe("The content the agent just read, for injection analysis"),
    content_source_url: z.string().optional(),
  })
  .optional();

const server = new McpServer(
  { name: "paysafe", version: "1.4.0" },
  {
    instructions:
      "PaySafe is a payment security firewall for x402. Protocol for this agent: BEFORE settling or sending ANY x402 payment, call `scan_outgoing_payment` and act on the verdict (allow = proceed, flag = pause and confirm, block = do NOT pay). BEFORE paying a 402 offer you received, call `scan_incoming_payment`. Whenever a payment decision followed reading external content (a fetched page or tool result), pass that content in `context.content` so the injection check can run. AFTER a scanned payment settles, call `report_payment_outcome` with what actually happened (delivered / not_delivered / partial / wrong_content) — this builds the measured delivery history that protects your own future payments to that seller. Use `check_counterparty_reputation` before dealing with an unfamiliar address, and `report_counterparty` after a bad experience beyond non-delivery (free). If YOUR wallet is reported unfairly, `dispute_reputation` attaches a wallet-signed rebuttal that lookups surface alongside the reports. These scans are advisory and non-custodial — PaySafe never touches your keys or funds.",
  },
);

server.tool(
  "scan_outgoing_payment",
  "ALWAYS call this immediately BEFORE settling or sending any x402 payment — it decides whether the payment is safe. Returns allow (proceed) / flag (pause and confirm intent) / block (do NOT pay), with machine-readable reasons and an Ed25519-signed verdict. IMPORTANT: if the decision to pay followed reading any external content (a fetched web page or a tool result), pass that text in `context.content` and set `context.origin` to 'fetched_content' or 'tool_result' — this enables the check that catches prompt-injection-triggered payments (an address injected into content the agent just read). Also catches replayed nonces, overpayment vs the expected price, secrets/PII leaking in payment metadata, fake/lookalike USDC contracts, and address poisoning. Advisory and non-custodial — never touches keys or funds.",
  {
    payment: paymentSchema,
    expected_price_usd: z.number().optional(),
    context: contextSchema,
    agent_id: z.string().optional(),
    policy: z
      .object({
        force_deep: z.boolean().optional().describe("Run deep content analysis even below the micropayment threshold"),
        skip_deep: z.boolean().optional(),
      })
      .optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/scan/outgoing", args) }],
  }),
);

server.tool(
  "scan_incoming_payment",
  "ALWAYS call this BEFORE paying a 402 offer / payment request your agent received — it decides whether the offer is safe to pay. Checks the resource URL for spoofing (IP-literal hosts, punycode/homoglyphs, link shorteners, userinfo tricks), credential demands (e.g. 'send your seed phrase'), price sanity, replay, and whether the counterparty has been reported. Returns allow/flag/block with reasons.",
  {
    payment: paymentSchema,
    expected_price_usd: z.number().optional(),
    context: contextSchema,
    agent_id: z.string().optional(),
    policy: z
      .object({
        force_deep: z.boolean().optional().describe("Run deep content analysis even below the micropayment threshold"),
        skip_deep: z.boolean().optional(),
      })
      .optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/scan/incoming", args) }],
  }),
);

server.tool(
  "check_counterparty_reputation",
  "Check whether a counterparty wallet address has been reported by other agents BEFORE dealing with it — scam, non-delivery, prompt injection, overcharge, impersonation, or replay abuse. Returns report counts, distinct-reporter count, and a risk level.",
  { address: z.string().describe("Wallet address to look up") },
  async ({ address }) => ({
    content: [{ type: "text", text: await call("GET", `/v1/reputation/${encodeURIComponent(address)}`) }],
  }),
);

server.tool(
  "report_payment_outcome",
  "ALWAYS call this AFTER a scanned payment settles, reporting what actually happened: 'delivered' (you received the goods/content), 'not_delivered' (paid but nothing arrived), 'partial', or 'wrong_content'. Pass the scan_id from the scan response and the payment_commitment from its attestation — outcomes are bound to real scans (one per scan), so delivery history cannot be faked. Your reports build the measured delivery rates that flag never-shipping sellers on your own future scans and every other agent's. Free.",
  {
    scan_id: z.string().describe("From the scan response you made before paying"),
    payment_commitment: z.string().describe("From the scan response's attestation.payment_commitment"),
    outcome: z.enum(["delivered", "not_delivered", "partial", "wrong_content"]),
    evidence: z
      .object({
        status: z.number().optional().describe("HTTP status of the paid response"),
        content_type: z.string().optional(),
        bytes: z.number().optional(),
        latency_ms: z.number().optional(),
      })
      .optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/outcomes", args) }],
  }),
);

server.tool(
  "report_counterparty",
  "Call this after a bad payment experience (you paid and got nothing, were scammed, overcharged, or hit an injection attempt) to warn other agents — always free. Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, replay_abuse, other.",
  {
    address: z.string(),
    category: z.enum(["scam", "non_delivery", "prompt_injection", "overcharge", "impersonation", "replay_abuse", "other"]),
    reason: z.string().min(10),
    reporter_agent_id: z.string(),
    evidence_url: z.string().optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/reputation/report", args) }],
  }),
);

server.tool(
  "dispute_reputation",
  "If YOUR wallet has been unfairly reported, attach a signed rebuttal that appears alongside the reports in every reputation lookup. Prove you control the wallet by signing the exact message 'paysafe-dispute-v1|<your address, lowercase>|<statement>' with the wallet's key (EIP-191 personal_sign) and passing the 65-byte signature hex. Rebuttals never erase reports — agents see both sides. Free.",
  {
    address: z.string().describe("The reported wallet address (0x…, the one that signed)"),
    statement: z.string().min(10).max(1000).describe("Your side of the story — exactly the text that was signed"),
    signature: z.string().describe("EIP-191 personal_sign signature hex over paysafe-dispute-v1|<address>|<statement>"),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/reputation/dispute", args) }],
  }),
);

server.tool(
  "mint_api_key",
  "Issue a free PaySafe API key (first 100 calls free). Returns the key ONCE — store it and set it as PAYSAFE_API_KEY (or pass to other tools) for future sessions. Rate-limited per IP.",
  { agent_id: z.string().optional().describe("Stable identifier for your agent — scopes velocity limits") },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/keys", args) }],
  }),
);

server.tool(
  "rotate_api_key",
  "Rotate the current PaySafe API key (set via PAYSAFE_API_KEY): mints a fresh secret bound to the SAME account — usage history, remaining free calls, and any active plan carry over unchanged. Use this the moment a key may have leaked. The old secret keeps working for grace_seconds (default 900, 0 = immediately dead, max 86400) so other sessions can switch over, but it can no longer rotate or revoke the account. IMPORTANT: the response contains the new key ONCE — store it and update PAYSAFE_API_KEY everywhere.",
  { grace_seconds: z.number().int().min(0).max(86400).optional().describe("How long the old secret keeps working (default 900 = 15 min; 0 kills it instantly)") },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/keys/rotate", args) }],
  }),
);

server.tool(
  "check_approval_status",
  "Poll a pending human approval (from a flag verdict's `approval.approval_id` when the operator has configured approvals via POST /v1/approvals/config). Returns pending / approved / denied / expired; on approved it includes the signed override verdict (tag 'override:allow', valid a few minutes, bound to exactly the flagged payment). Requires PAYSAFE_API_KEY (the key that made the scan). This tool never handles decide tokens — deciding is the human's job via the webhook link.",
  { approval_id: z.string().describe("From the flag scan response's approval.approval_id") },
  async ({ approval_id }) => ({
    content: [{ type: "text", text: await call("GET", `/v1/approvals/${encodeURIComponent(approval_id)}`) }],
  }),
);

server.tool(
  "get_plans",
  "Machine-readable PaySafe plan catalog: tiers (Starter/Pro/Scale) with per-scan pricing, velocity and spend limits, hard ceilings, and how to subscribe. Free.",
  {},
  async () => ({
    content: [{ type: "text", text: await call("GET", "/v1/plans") }],
  }),
);

server.tool(
  "subscribe_plan",
  "Subscribe/renew the current API key on a PaySafe plan (pro: $4.99/30d at $0.005/scan; scale: $19.99/30d at $0.002/scan). This endpoint is itself x402-paid at the plan's price: without an x402-paying transport the response is the 402 payment challenge to settle. Renewal extends from the current expiry.",
  { plan: z.enum(["pro", "scale"]) },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/plans/subscribe", args) }],
  }),
);

server.tool(
  "verify_verdict_attestation",
  "LOCALLY verify a PaySafe scan's Ed25519 attestation before trusting an allow-verdict: checks the signature against the pinned server key (fetched from /.well-known/paysafe-verdict-key unless trusted_key_hex is supplied), recomputes the payment commitment from the payment YOU are about to settle (rejects attestations issued for a different payment — replay defense), and enforces expiry. Runs no network calls except the one-time key fetch; the verdict itself is never sent anywhere.",
  {
    scan: z.object({
      scan_id: z.string(),
      direction: z.string(),
      verdict: z.string(),
      risk_score: z.number(),
      scanned_at: z.string(),
      attestation: z.object({
        message: z.string(),
        signature_hex: z.string(),
        payment_commitment: z.string(),
        expires_at: z.string(),
      }),
    }),
    payment: paymentSchema.describe("The payment you are about to settle — commitment is recomputed from this"),
    trusted_key_hex: z.string().optional().describe("Pin the server verdict key (SPKI DER hex); fetched once when omitted"),
  },
  async ({ scan, payment, trusted_key_hex }) => {
    const fail = (reason: string) => ({
      content: [{ type: "text" as const, text: JSON.stringify({ valid: false, reason }) }],
    });
    try {
      let keyHex = trusted_key_hex;
      if (!keyHex) {
        const r = await fetch(`${BASE}/.well-known/paysafe-verdict-key`);
        keyHex = ((await r.json()) as { public_key_spki_hex?: string }).public_key_spki_hex;
      }
      if (!keyHex) return fail("no trusted key available");
      const key = createPublicKey({ key: Buffer.from(keyHex, "hex"), format: "der", type: "spki" });
      const att = scan.attestation;
      if (!edVerify(null, Buffer.from(att.message, "utf8"), key, Buffer.from(att.signature_hex, "hex"))) {
        return fail("Ed25519 signature invalid under the pinned server key");
      }
      const [scanId, direction, verdict, risk, scannedAt, commitment, expiresAt] = att.message.split("|");
      if (scanId !== scan.scan_id || direction !== scan.direction || verdict !== scan.verdict ||
          Number(risk) !== scan.risk_score || scannedAt !== scan.scanned_at) {
        return fail("attested message does not match the scan fields");
      }
      const amount =
        payment.amount !== undefined ? String(payment.amount)
        : payment.amount_usd !== undefined ? `usd:${payment.amount_usd}`
        : "";
      const recomputed = createHash("sha256")
        .update([payment.network ?? "", (payment.pay_to ?? "").toLowerCase(), (payment.asset ?? "").toLowerCase(), amount, payment.nonce ?? ""].join("|"), "utf8")
        .digest("hex");
      if (commitment !== recomputed) {
        return fail("payment commitment mismatch — attestation was issued for a DIFFERENT payment (possible replay)");
      }
      if (Date.parse(expiresAt) <= Date.now()) return fail(`attestation expired at ${expiresAt}`);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ valid: true, verdict: scan.verdict, expires_at: expiresAt }) }],
      };
    } catch (e) {
      return fail(`verification error: ${(e as Error).message}`);
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);

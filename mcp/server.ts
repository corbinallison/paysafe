/**
 * PaySafe MCP server — exposes the scans as MCP tools over stdio.
 *
 * Env:
 *   PAYSAFE_URL      Base URL of a running PaySafe instance (default http://localhost:4021)
 *   PAYSAFE_API_KEY  API key from POST /v1/keys (free tier). Without it, paid
 *                    endpoints will 402 — pair this server with an x402-aware
 *                    fetch (e.g. @x402/fetch) or stay within the free tier.
 *
 * Register in an MCP client config:
 *   { "command": "node", "args": ["dist/mcp/server.js"], "env": { "PAYSAFE_URL": "...", "PAYSAFE_API_KEY": "..." } }
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const BASE = process.env.PAYSAFE_URL ?? "http://localhost:4021";
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

const server = new McpServer({ name: "paysafe", version: "1.0.0" });

server.tool(
  "scan_outgoing_payment",
  "Screen an x402 payment your agent is ABOUT TO MAKE. Checks: PII/secret leakage in payment metadata, nonce replay, overpayment vs expected price, prompt-injection-triggered payment provenance, counterparty reputation. Returns allow/flag/block with reasons. Advisory only — PaySafe never touches keys or funds.",
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
  "Screen an x402 payment request / 402 offer your agent RECEIVED. Checks: resource URL risk (IP literals, punycode, shorteners, userinfo tricks), credential demands, price sanity, replay, counterparty reputation. Returns allow/flag/block with reasons.",
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
  "Look up shared post-hoc reports on a counterparty wallet address (scam, non-delivery, prompt injection, overcharge, impersonation, replay abuse), aggregated across reporting agents.",
  { address: z.string().describe("Wallet address to look up") },
  async ({ address }) => ({
    content: [{ type: "text", text: await call("GET", `/v1/reputation/${encodeURIComponent(address)}`) }],
  }),
);

server.tool(
  "report_counterparty",
  "File a report against a counterparty after a bad payment experience (always free). Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, replay_abuse, other.",
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

const transport = new StdioServerTransport();
await server.connect(transport);

/**
 * Demo: a client agent attempts an x402 payment with a REUSED NONCE and
 * PaySafe blocks the second attempt with a clear reason.
 *
 * Run against a local instance:
 *   npm run dev            # terminal 1 (dev server, payments off)
 *   npm run demo:replay    # terminal 2
 *
 * Or against a deployed instance:
 *   PAYSAFE_URL=https://your-paysafe.onrender.com PAYSAFE_API_KEY=psk_... npm run demo:replay
 */
const BASE = process.env.PAYSAFE_URL ?? "http://localhost:4021";

interface ScanResponse {
  scan_id: string;
  verdict: "allow" | "flag" | "block";
  risk_score: number;
  checks: Array<{ id: string; verdict: string; severity: string; reason: string }>;
  advisory: string;
}

async function post(path: string, body: unknown): Promise<{ status: number; json: any }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (process.env.PAYSAFE_API_KEY) headers["x-api-key"] = process.env.PAYSAFE_API_KEY;
  const res = await fetch(`${BASE}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: res.status, json: await res.json() };
}

function show(label: string, r: ScanResponse): void {
  console.log(`\n=== ${label} ===`);
  console.log(`verdict: ${r.verdict.toUpperCase()}   risk_score: ${r.risk_score}`);
  for (const c of r.checks) {
    if (c.verdict !== "allow") console.log(`  [${c.verdict}/${c.severity}] ${c.id}: ${c.reason}`);
  }
  console.log(`advisory: ${r.advisory}`);
}

// The payment our agent wants to make — same signed authorization both times,
// i.e. the same nonce (simulating a captured/stale payment payload being replayed).
const nonce = `0x${Date.now().toString(16)}deadbeef`;
const payment = {
  scheme: "exact",
  network: "eip155:8453",
  amount: "10000", // $0.01 USDC (6 decimals)
  asset_decimals: 6,
  pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  payer: "0xA11ce00000000000000000000000000000000001",
  resource_url: "https://api.example.com/premium/report",
  description: "Premium market report",
  nonce,
};

const scanBody = {
  agent_id: "demo-agent-01",
  payment,
  expected_price_usd: 0.01,
  context: { origin: "planning" },
};

console.log(`PaySafe replay demo → ${BASE}`);
console.log(`Payment nonce: ${nonce}`);

// Attempt 1: fresh nonce — should be ALLOWED.
const first = await post("/v1/scan/outgoing", scanBody);
if (first.status !== 200) {
  console.error(`Scan failed (HTTP ${first.status}):`, first.json);
  process.exit(1);
}
show("Attempt 1 — fresh nonce", first.json);

// Attempt 2: the agent (or an attacker) replays the SAME payment authorization.
const second = await post("/v1/scan/outgoing", scanBody);
show("Attempt 2 — REUSED nonce (replay)", second.json);

const replayCheck = (second.json as ScanResponse).checks.find((c) => c.id === "replay.nonce_reuse");
if (second.json.verdict === "block" && replayCheck) {
  console.log("\n✅ Replay correctly BLOCKED. The agent's wallet should refuse to settle this payment.");
  process.exit(0);
} else {
  console.error("\n❌ Expected the second attempt to be blocked for nonce reuse.");
  process.exit(1);
}

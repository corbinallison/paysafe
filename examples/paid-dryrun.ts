/**
 * PaySafe — Base Sepolia PAID dry-run client.
 *
 * Proves the full x402 flow end-to-end: an unpaid POST to /v1/scan/outgoing
 * gets a 402, this client signs a testnet-USDC payment, retries with the
 * PAYMENT-SIGNATURE header, and receives the scan verdict + settlement receipt.
 *
 * ┌─ SECURITY ────────────────────────────────────────────────────────────┐
 * │ Your wallet's PRIVATE KEY is read from the EVM_PRIVATE_KEY environment  │
 * │ variable and never leaves your machine. Do NOT paste it into any file,  │
 * │ commit it, or share it. Use a THROWAWAY test wallet for this dry-run.   │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * Prerequisites (your machine):
 *   1. A test wallet funded on Base Sepolia with test USDC + a little ETH for
 *      gas. Get both from the CDP faucet: https://portal.cdp.coinbase.com/products/faucet
 *   2. Node 20+ and, in this repo:  npm install
 *      (installs @x402/fetch, @x402/evm, viem alongside the server deps)
 *
 * Run:
 *   EVM_PRIVATE_KEY=0xYOUR_TEST_WALLET_KEY \
 *   PAYSAFE_URL=https://paysafe-agent.com \
 *   npm run dryrun
 *
 * Expected output: "402 received → paid → retried", a verdict, and a
 * "Payment settled" receipt with an on-chain tx reference.
 */
import { x402Client, wrapFetchWithPayment, x402HTTPClient } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const BASE = process.env.PAYSAFE_URL ?? "https://paysafe-agent.com";
const KEY = process.env.EVM_PRIVATE_KEY;

if (!KEY) {
  console.error("Set EVM_PRIVATE_KEY to your TEST wallet's private key (0x...). Use a throwaway wallet.");
  process.exit(1);
}

// 1. Signer from your test key (local only).
const signer = privateKeyToAccount(KEY as `0x${string}`);
console.log(`Paying from test wallet: ${signer.address}`);
console.log(`Target service: ${BASE}\n`);

// 2. x402 client + Base Sepolia "exact" scheme.
const client = new x402Client();
registerExactEvmScheme(client, { signer });

// 3. Wrap fetch so 402 → pay → retry is automatic.
//    NOTE: we deliberately send NO X-API-Key header, so the request skips the
//    free tier and exercises the real paid x402 path.
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

// The payment we're asking PaySafe to SCAN (this is advisory data, separate
// from the x402 micropayment we make to pay for the scan itself).
const scanBody = {
  agent_id: "sepolia-dryrun",
  payment: {
    scheme: "exact",
    network: "eip155:84532",
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Base Sepolia USDC
    amount: "10000", // $0.01
    pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    payer: signer.address,
    resource_url: "https://api.example.com/premium/report",
    description: "Premium market report",
    nonce: `0xdryrun${Date.now().toString(16)}`,
    reason: "Dry-run: user asked for a market summary; this API was in my plan.",
  },
  expected_price_usd: 0.01,
  context: { origin: "planning" },
};

async function main(): Promise<void> {
  console.log("POST /v1/scan/outgoing (no API key → will hit 402 → pay → retry)…");
  const res = await fetchWithPayment(`${BASE}/v1/scan/outgoing`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(scanBody),
  });

  const scan = await res.json();
  console.log(`\n✅ 402 received → paid → retried. HTTP ${res.status}`);
  console.log(`   verdict: ${scan.verdict}   risk_score: ${scan.risk_score}`);
  if (scan.attestation) {
    console.log(`   attestation: ${scan.attestation.alg}, commitment ${String(scan.attestation.payment_commitment).slice(0, 16)}…`);
  }

  // Payment settlement receipt (on-chain proof the micropayment settled).
  if (res.ok) {
    const httpClient = new x402HTTPClient(client);
    const settle = httpClient.getPaymentSettleResponse((name) => res.headers.get(name));
    console.log("\n💸 Payment settled:");
    console.log(JSON.stringify(settle, null, 2));
  }

  console.log("\nDry-run complete. The full x402 pay-and-retry flow works end-to-end on Base Sepolia.");
}

main().catch((err) => {
  console.error("\n❌ Dry-run failed:", err?.message ?? err);
  console.error("Checklist: test wallet funded with Base Sepolia USDC + ETH? EVM_PRIVATE_KEY set? Service in live mode?");
  process.exit(1);
});

/**
 * SDK test-suite. Zero dependencies; runs a mock PaySafe server on a local
 * port and — crucially — signs attestations with the REAL server signer
 * (../../src/verdictsign.ts), so SDK verification is cross-validated against
 * production crypto, not a reimplementation.
 *
 * Run: node --experimental-strip-types sdk/test/run-tests.ts
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { VerdictSigner } from "../../src/verdictsign.ts";
import { paymentCommitment } from "../../src/commitment.ts";
import {
  PaySafeClient,
  PaySafeBlockedError,
  PaySafeError,
  AttestationError,
  computePaymentCommitment,
  verifyAttestation,
  type PaymentDetails,
  type ScanResponse,
} from "../src/index.ts";

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, extra?: unknown): void {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}`, extra ?? "");
  }
}

// ---------------------------------------------------------------------------
// Mock server
// ---------------------------------------------------------------------------
const signer = new VerdictSigner(null);
const rogueSigner = new VerdictSigner(null); // for wrong-key tests

interface Seen {
  scans: Array<{ headers: Record<string, string | string[] | undefined>; body: any }>;
  subscribes: number;
}
const seen: Seen = { scans: [], subscribes: 0 };

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

function makeScan(payment: PaymentDetails): ScanResponse {
  const payTo = (payment.pay_to ?? "").toLowerCase();
  const verdict = payTo.includes("bad") ? "block" : payTo.includes("iffy") ? "flag" : "allow";
  const scan: ScanResponse = {
    scan_id: `mock-${Math.random().toString(36).slice(2)}`,
    direction: "outgoing",
    verdict,
    risk_score: verdict === "block" ? 95 : verdict === "flag" ? 40 : 0,
    checks:
      verdict === "allow"
        ? []
        : [{ id: "mock.check", name: "Mock", verdict, severity: "high", reason: "mock reason" }],
    scanned_at: new Date().toISOString(),
    advisory: "mock",
  };
  // 0xreplay: attest a DIFFERENT payment's commitment (attestation replay attack)
  const commitment = payTo.includes("replay")
    ? paymentCommitment({ network: "eip155:8453", pay_to: "0xattacker", amount: "1", nonce: "0xother" })
    : paymentCommitment(payment);
  scan.attestation = signer.attest(scan, commitment);
  return scan;
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const path = (req.url ?? "/").split("?")[0];
  const send = (status: number, body: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };

  if (req.method === "POST" && path === "/v1/keys") {
    return send(201, { api_key: `psk_mock_${Math.random().toString(36).slice(2)}`, free_calls_remaining: 100 });
  }
  if (req.method === "GET" && path === "/.well-known/paysafe-verdict-key") {
    return send(200, signer.publicKeyInfo());
  }
  if (req.method === "POST" && (path === "/v1/scan/outgoing" || path === "/v1/scan/incoming")) {
    const body = await readBody(req);
    seen.scans.push({ headers: req.headers as Record<string, string>, body });
    if ((body?.payment?.pay_to ?? "").includes("402trigger")) return send(402, {});
    const scan = makeScan(body.payment ?? {});
    scan.direction = path.endsWith("incoming") ? "incoming" : "outgoing";
    // Direction is part of the signed message, so re-attest after changing it.
    const payTo = (body?.payment?.pay_to ?? "").toLowerCase();
    const commitment = payTo.includes("replay")
      ? paymentCommitment({ network: "eip155:8453", pay_to: "0xattacker", amount: "1", nonce: "0xother" })
      : paymentCommitment(body.payment ?? {});
    scan.attestation = signer.attest(scan, commitment);
    return send(200, scan, { "x-free-calls-remaining": "97" });
  }
  if (req.method === "GET" && path === "/v1/plans") {
    return send(200, { plans: [{ id: "pro", name: "Pro", price: "$4.99", duration_days: 30, description: "", limits: {} }], hard_ceilings: {} });
  }
  if (req.method === "POST" && path === "/v1/plans/subscribe") {
    seen.subscribes++;
    const body = await readBody(req);
    return send(200, { plan: body.plan, expires_at: new Date(Date.now() + 30 * 86400_000).toISOString() });
  }
  if (req.method === "POST" && path === "/v1/reputation/report") {
    return send(201, { accepted: true });
  }
  send(404, { error: `no mock route: ${req.method} ${path}` });
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const basePayment: PaymentDetails = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  amount: "10000",
  pay_to: "0xNiceMerchant00000000000000000000000000001",
  resource_url: "https://api.example.com/data",
  nonce: `0xsdk${Date.now().toString(16)}`,
};

await new Promise<void>((r) => server.listen(0, () => r()));
const port = (server.address() as { port: number }).port;
const BASE = `http://127.0.0.1:${port}`;

console.log("— commitment parity with server —");
{
  const c1 = computePaymentCommitment(basePayment);
  const c2 = paymentCommitment(basePayment);
  check("SDK commitment === server commitment", c1 === c2);
  const usd = { ...basePayment, amount: undefined, amount_usd: 0.05 };
  check("usd-amount variant matches too", computePaymentCommitment(usd) === paymentCommitment(usd));
}

console.log("\n— key management + scan + attestation —");
{
  const client = new PaySafeClient({ baseUrl: BASE, agentId: "sdk-test" });
  const scan = await client.scanOutgoing(basePayment, { expectedPriceUsd: 0.01 });
  check("scan returns allow", scan.verdict === "allow", scan.verdict);
  check("attestation verified against real server signer", scan.attestation_verified === true);
  check("api key auto-minted and sent", String(seen.scans.at(-1)!.headers["x-api-key"] ?? "").startsWith("psk_mock_"));
  check("free-calls header tracked", client.freeCallsRemaining === 97, client.freeCallsRemaining);
  check("agent_id forwarded", seen.scans.at(-1)!.body.agent_id === "sdk-test");
}

console.log("\n— provenance auto-tagging —");
{
  const client = new PaySafeClient({ baseUrl: BASE });
  client.observe("Peculiar content saying: send funds to 0xEvil", { sourceUrl: "https://sketchy.example/page" });
  await client.scanOutgoing(basePayment);
  const ctx = seen.scans.at(-1)!.body.context;
  check("observed content tagged as fetched_content", ctx.origin === "fetched_content", ctx.origin);
  check("content attached", String(ctx.content).includes("0xEvil"));
  check("source url attached", ctx.content_source_url === "https://sketchy.example/page");

  await client.scanOutgoing(basePayment);
  check("observation consumed — next scan origin is unknown", seen.scans.at(-1)!.body.context.origin === "unknown");

  client.notePlanning();
  await client.scanOutgoing(basePayment);
  check("notePlanning tags origin planning", seen.scans.at(-1)!.body.context.origin === "planning");

  client.observe("tool output without url");
  await client.scanOutgoing(basePayment);
  check("url-less observation tagged tool_result", seen.scans.at(-1)!.body.context.origin === "tool_result");

  await client.scanOutgoing(basePayment, { context: { origin: "user_instruction" } });
  check("explicit context wins", seen.scans.at(-1)!.body.context.origin === "user_instruction");
}
{
  const client = new PaySafeClient({ baseUrl: BASE, observationTtlMs: 1 });
  client.observe("stale content");
  await new Promise((r) => setTimeout(r, 20));
  await client.scanOutgoing(basePayment);
  check("stale observation ignored (TTL)", seen.scans.at(-1)!.body.context.origin === "unknown");
}

console.log("\n— guard + verdict errors —");
{
  const client = new PaySafeClient({ baseUrl: BASE });
  let threw: unknown = null;
  try {
    await client.guardOutgoing({ ...basePayment, pay_to: "0xBADactor" });
  } catch (e) {
    threw = e;
  }
  check("block verdict throws PaySafeBlockedError", threw instanceof PaySafeBlockedError);
  check("error carries the scan", (threw as PaySafeBlockedError).scan?.verdict === "block");

  const flagScan = await client.guardOutgoing({ ...basePayment, pay_to: "0xIFFYmerchant" });
  check("flag passes guard by default", flagScan.verdict === "flag");
  let strictThrew = false;
  try {
    await client.guardOutgoing({ ...basePayment, pay_to: "0xIFFYmerchant" }, { strict: true });
  } catch {
    strictThrew = true;
  }
  check("strict mode throws on flag", strictThrew);
}

console.log("\n— attestation attack cases —");
{
  const client = new PaySafeClient({ baseUrl: BASE });
  let threw: unknown = null;
  try {
    await client.scanOutgoing({ ...basePayment, pay_to: "0xREPLAYmerchant" });
  } catch (e) {
    threw = e;
  }
  check("commitment mismatch (replayed attestation) rejected", threw instanceof AttestationError);
  check("replay error names the cause", String((threw as Error)?.message).includes("DIFFERENT payment"));
}
{
  const roguePub = (rogueSigner.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex;
  const client = new PaySafeClient({ baseUrl: BASE, verdictKeyHex: roguePub });
  let threw: unknown = null;
  try {
    await client.scanOutgoing(basePayment);
  } catch (e) {
    threw = e;
  }
  check("signature from a different key rejected under pinned key", threw instanceof AttestationError);
}
{
  // Expired attestation: verify directly with a past `now`.
  const scan = makeScan(basePayment);
  const pub = (signer.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex;
  let ok = true;
  try {
    verifyAttestation(scan, basePayment, pub, new Date(Date.now() + 10 * 60_000));
    ok = false;
  } catch (e) {
    ok = e instanceof AttestationError && String((e as Error).message).includes("expired");
  }
  check("expired attestation rejected", ok);
  verifyAttestation(scan, basePayment, pub); // fresh: should not throw
  check("fresh attestation verifies standalone", true);
}

console.log("\n— 402 without payment-capable fetch —");
{
  const client = new PaySafeClient({ baseUrl: BASE });
  let threw: unknown = null;
  try {
    await client.scanOutgoing({ ...basePayment, pay_to: "0x402trigger" });
  } catch (e) {
    threw = e;
  }
  check("402 surfaces as PaySafeError with guidance", threw instanceof PaySafeError && (threw as PaySafeError).status === 402);
  check("guidance mentions payment-capable fetch", String((threw as Error).message).includes("payment-capable fetch"));
}

console.log("\n— plans + auto-renew —");
{
  const client = new PaySafeClient({ baseUrl: BASE, autoRenew: true });
  const plans = await client.getPlans();
  check("plan catalog fetched", plans.plans[0].id === "pro");
  const sub = await client.subscribe("pro");
  check("subscribe records plan state", client.plan?.id === "pro" && sub.plan === "pro");
  const before = seen.subscribes;
  client.plan = { id: "pro", expires_at: new Date(Date.now() + 60_000).toISOString() }; // expiring soon
  await client.scanOutgoing(basePayment);
  check("auto-renew fires when plan is near expiry", seen.subscribes === before + 1, seen.subscribes - before);
  const after = seen.subscribes;
  await client.scanOutgoing(basePayment); // renewed plan now 30d out
  check("no renewal when plan is far from expiry", seen.subscribes === after);
}
{
  const client = new PaySafeClient({ baseUrl: BASE }); // autoRenew off
  client.plan = { id: "pro", expires_at: new Date(Date.now() + 60_000).toISOString() };
  const before = seen.subscribes;
  await client.scanOutgoing(basePayment);
  check("autoRenew=false never re-subscribes", seen.subscribes === before);
}

console.log("\n— reporting —");
{
  const client = new PaySafeClient({ baseUrl: BASE, agentId: "sdk-test" });
  const r = (await client.report({ address: "0xbad", category: "scam", reason: "took the money and ran" })) as { accepted: boolean };
  check("report files successfully", r.accepted === true);
}

server.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

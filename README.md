# PaySafe

**A payment security firewall for [x402](https://x402.org) — screen every micropayment before it settles.**

[![x402](https://img.shields.io/badge/x402-v2-blue)](https://github.com/x402-foundation/x402)
[![network](https://img.shields.io/badge/settles%20on-Base%20(USDC)-0052FF)](https://docs.cdp.coinbase.com/x402/quickstart-for-sellers)
[![tests](https://img.shields.io/badge/tests-48%2F48-brightgreen)](test/run-tests.ts)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

Agents that pay over x402 get drained in predictable ways: secrets leak through payment metadata, captured authorizations get replayed, quoted prices get inflated, and poisoned web content tricks agents into paying addresses they never planned to pay. PaySafe is one `POST` before settlement that checks for all of it and returns **allow / flag / block** with machine-readable, per-check reasons — in **~0.6 ms**.

PaySafe is **advisory and non-custodial**: it never touches private keys, wallets, or funds. It wraps around whatever facilitator and wallet your agent already uses. And it's a first-class x402 seller itself — its endpoints are paid via the official x402 middleware, settle through the Coinbase CDP facilitator, and carry Bazaar discovery metadata.

```
Agent decides to pay ──► POST /v1/scan/outgoing ──► allow ──► wallet settles
                                   │
                                   ├──► flag  ──► agent pauses / confirms intent
                                   └──► block ──► wallet refuses (reason attached)
```

## What it catches

**Core detectors**

| Check | What it catches |
|---|---|
| PII / secret detection | EVM private keys, seed phrases, AWS/OpenAI/Anthropic/GitHub/Slack keys, JWTs, `?api_key=` URL credentials, SSNs, Luhn-validated card numbers, emails, phones — in `resource_url`, `description`, `reason`, and `metadata`, *before* they're transmitted |
| Replay detection | Nonce reuse (stale or captured payment authorizations), scoped `network:payer:nonce`, configurable TTL window |
| Overpayment detection | Above a configurable multiple of expected price (flag ≥3×, block ≥10×) plus an absolute ceiling |
| Prompt-injection-triggered payments | Payments whose *decision* originated from content the agent just read (tool result / fetched page) rather than its own planning step; escalates on injection tells in that content; blocks when the `pay_to` address itself came from it |
| Resource URL risk (incoming) | IP-literal hosts, punycode/homoglyphs, link shorteners, `user@host` tricks, non-HTTPS, credential demands ("send your seed phrase") |
| Counterparty reputation | Shared post-hoc report registry, cross-checked on every scan; reporting is always free |

**Zero-latency hardening tier** — checks that hold even when the calling agent's narration is compromised:

| Check | What it catches |
|---|---|
| Velocity limits | ≥N scans/min (flag; block at 2×), cumulative hourly spend cap — rate and spend are observed facts, not self-reports |
| First-contact size cap | First payment to a never-seen counterparty above a threshold |
| Asset verification | `asset` contract that isn't canonical USDC on the declared network (lookalike-token attack) |
| Merchant pinning (TOFU) | `pay_to` rotation on a known resource domain → block; optional non-blocking CDP Bazaar cross-check |
| Known-bad list | O(1) membership against a curated/synced badlist |
| Deep content analysis | Base64-encoded and zero-width/homoglyph-obfuscated injection payloads, decoded/normalized and rescanned — bypassed below `MICRO_BYPASS_USD` (default $0.005), overridable per request via `policy.force_deep` |

**Signed verdicts.** Every response carries an Ed25519 `attestation` (`scan_id|direction|verdict|risk_score|scanned_at`, public key at `/.well-known/paysafe-verdict-key`). Wallet policies can require a fresh signed allow-verdict before signing a payment — turning the firewall from advisory into enforceable, still without PaySafe touching funds.

## API

| Endpoint | Price | Description |
|---|---|---|
| `POST /v1/scan/outgoing` | $0.01 | Screen a payment your agent is about to make |
| `POST /v1/scan/incoming` | $0.01 | Screen a 402 offer / payment request your agent received |
| `GET /v1/reputation/:address` | $0.01 | Counterparty report summary |
| `POST /v1/reputation/report` | free | Report a bad counterparty after the fact |
| `POST /v1/keys` | free | Issue an API key — **first 100 calls free** per key |
| `GET /.well-known/x402` | free | x402 manifest |
| `GET /.well-known/agent-card.json` | free | Agent card |
| `GET /.well-known/paysafe-verdict-key` | free | Ed25519 public key for verdict attestations |
| `GET /` · `GET /health` | free | Self-documenting schema / liveness |

Send the key from `POST /v1/keys` in the `X-API-Key` header; the first `FREE_CALLS` (default 100) calls bypass payment. After that, unpaid calls get a standard x402 `402 Payment Required` — any x402 client (`@x402/fetch`, `x402-requests`, …) handles pay-and-retry automatically.

### Example: scan an outgoing payment

```jsonc
POST /v1/scan/outgoing
{
  "agent_id": "my-agent",                    // scopes velocity limits
  "payment": {
    "scheme": "exact",
    "network": "eip155:8453",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // enables canonical-USDC check
    "amount": "10000",                       // atomic units ($0.01 USDC), or use amount_usd
    "pay_to": "0x2096...287C",
    "payer": "0xYourAgentWallet",
    "resource_url": "https://api.example.com/premium/report",
    "description": "Premium market report",
    "nonce": "0x1a2b3c...",
    "reason": "User asked for a market summary; this API was in my plan."
  },
  "expected_price_usd": 0.01,
  "context": {
    "origin": "planning",                    // planning | user_instruction | tool_result | fetched_content
    "content": "<the tool result / fetched page the agent just read, if any>",
    "content_source_url": "https://example.com/article"
  },
  "policy": { "force_deep": false }          // optional tiering overrides
}
```

`context.origin` is the key input for injection detection: payments prompted by just-read content are the primary prompt-injection exfiltration path and get elevated scrutiny.

### Example response (replay blocked)

```json
{
  "scan_id": "b7911f8b-164f-45a4-a610-5fd3a45a5c8b",
  "direction": "outgoing",
  "verdict": "block",
  "risk_score": 95,
  "checks": [
    {
      "id": "replay.nonce_reuse",
      "verdict": "block",
      "severity": "critical",
      "reason": "Nonce reuse detected: this nonce was first seen 2026-07-14T09:32:50Z (scan b7911f8b-…) and has now appeared 2 times. A reused nonce means a stale or captured payment authorization is being replayed."
    }
  ],
  "scanned_at": "2026-07-14T09:33:12Z",
  "advisory": "Recommended action: DO NOT settle this payment. ...",
  "attestation": {
    "alg": "ed25519",
    "public_key_spki_hex": "302a3005...",
    "message": "b7911f8b-...|outgoing|block|95|2026-07-14T09:33:12Z",
    "signature_hex": "..."
  }
}
```

## Quick start

```bash
git clone https://github.com/corbinallison/paysafe && cd paysafe
npm install

npm run dev            # dev server — payments off, no wallet needed
npm run demo:replay    # replay-attack demo: fresh nonce ALLOW → reused nonce BLOCK
npm test               # 48-test detector suite
```

## Performance

Measured on the zero-dependency dev server (same handlers as production): **2,000 sequential scans in 1.20 s → 0.60 ms/scan round-trip**, including HTTP, JSON parsing, the full check suite, and Ed25519 signing. Deployed latency is dominated by network RTT; on the paid path, the x402 verify/settle round-trip to the facilitator (inherent to x402, identical on any host) dominates everything else.

## Deploying to Render

1. Push this repo to GitHub.
2. In [Render](https://render.com): **New → Blueprint**, point it at the repo — [`render.yaml`](render.yaml) provisions the web service and a 1 GB disk for state.
3. Set the secrets when prompted: `PAY_TO` (your receiving wallet), `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` (from [portal.cdp.coinbase.com](https://portal.cdp.coinbase.com)), and `PUBLIC_BASE_URL` after the first deploy assigns your URL.
4. Verify:

```bash
curl https://paysafe-agent.com/health
curl https://paysafe-agent.com/.well-known/x402
# Unpaid scan → 402 with payment instructions:
curl -i -X POST https://paysafe-agent.com/v1/scan/outgoing \
  -H 'content-type: application/json' -d '{"payment":{}}'
```

**Testnet first (recommended):** set `X402_NETWORK=eip155:84532` (Base Sepolia) and keep `X402_FACILITATOR=cdp`, or use `X402_FACILITATOR=x402org` for a signup-free facilitator. Fund a test wallet at the [CDP faucet](https://docs.cdp.coinbase.com/faucets/introduction/quickstart).

## Bazaar indexing (automatic)

PaySafe registers the official Bazaar extension (`@x402/extensions/bazaar`) and declares input/output JSON Schemas on all paid routes. With the CDP facilitator, **the first successful settlement automatically indexes the service in the [x402 Bazaar](https://docs.cdp.coinbase.com/x402/bazaar)** — no registration step. Trigger it with one paid call past the free tier, then check:

```bash
curl "https://api.cdp.coinbase.com/platform/v2/x402/discovery/search?query=payment+security+firewall"
curl "https://api.cdp.coinbase.com/platform/v2/x402/discovery/merchant?payTo=<your PAY_TO>"
```

Indexing is asynchronous (~10 min). If a route doesn't appear, inspect the `EXTENSION-RESPONSES` header on settle responses for Bazaar validation status.

> The Bazaar extension registration API surface is evolving; if your installed `@x402/extensions` exposes a different registration call than `registerExtension`, adjust the marked block in [`src/index.ts`](src/index.ts). The service degrades gracefully — it still sells via x402, just without Bazaar cataloging.

## MCP server

[`mcp/server.ts`](mcp/server.ts) exposes the scans as MCP tools over stdio: `scan_outgoing_payment`, `scan_incoming_payment`, `check_counterparty_reputation`, `report_counterparty`.

```jsonc
// claude_desktop_config.json / any MCP client
{
  "mcpServers": {
    "paysafe": {
      "command": "node",
      "args": ["/path/to/paysafe/dist/mcp/server.js"],
      "env": {
        "PAYSAFE_URL": "https://paysafe-agent.com",
        "PAYSAFE_API_KEY": "psk_..."   // from POST /v1/keys
      }
    }
  }
}
```

## Configuration

All via environment variables (see [`.env.example`](.env.example) for the full annotated list):

| Variable | Default | Purpose |
|---|---|---|
| `PAYSAFE_MODE` | `live` | `live` enforces x402 payments; `dev` runs everything free |
| `PAY_TO` | — | Receiving wallet (required in live mode) |
| `X402_NETWORK` | `eip155:8453` | CAIP-2 network (Base mainnet; `eip155:84532` = Base Sepolia) |
| `X402_FACILITATOR` | `cdp` | `cdp` (mainnet + Bazaar) or `x402org` (testnet, no signup) |
| `PRICE_SCAN` / `PRICE_REPUTATION` | `$0.01` | Per-call pricing |
| `FREE_CALLS` | `100` | Free calls per API key |
| `OVERPAY_FLAG_MULTIPLE` / `OVERPAY_BLOCK_MULTIPLE` | `3` / `10` | Overpayment thresholds |
| `MAX_PAYMENT_USD` | `10` | Absolute payment ceiling |
| `MAX_PAYMENTS_PER_MINUTE` | `10` | Velocity: flag at rate, block at 2× |
| `MAX_USD_PER_HOUR` | `5` | Velocity: hourly spend cap |
| `FIRST_PAYMENT_MAX_USD` | `1` | First-contact size cap |
| `MICRO_BYPASS_USD` | `0.005` | Deep-tier bypass threshold |
| `ALLOW_NON_USDC` | `off` | Downgrade non-canonical-asset block to flag |
| `PINNING` / `CDP_PIN_VERIFY` | `on` / `off` | TOFU pinning / async CDP cross-check |
| `VERDICT_SIGNING` | `on` | Ed25519 verdict attestations |
| `BADLIST_PATH` | `<DATA_DIR>/badlist.json` | Known-bad address list |
| `NONCE_TTL_HOURS` | `24` | Replay tracking window |
| `DATA_DIR` | `./data` | State persistence |

## Architecture

```
src/
  index.ts        Express + @x402/express middleware + CDP facilitator + Bazaar extension
  devserver.ts    Zero-dependency dev server (payments off) — same API surface
  api.ts          Framework-agnostic handlers (both servers route here)
  scanner.ts      Detector orchestration, tiering, verdict aggregation
  detectors/      pii · replay · overpayment · injection (fast + deep) · urlrisk
                  asset · badlist · pinning · velocity
  reputation.ts   Shared report registry
  verdictsign.ts  Ed25519 verdict attestation
  manifest.ts     /.well-known/x402 + agent card
  store.ts        JSON-file-backed state (tiny interface — swap for Redis/Postgres at scale)
mcp/server.ts     MCP wrapper (4 tools)
examples/         replay-demo.ts — reused-nonce attack blocked end-to-end
test/             48-test detector suite (npm test)
```

Design notes: verdicts aggregate worst-first (any block ⇒ block); `risk_score` is severity-based with compounding for multiple independent findings; the detection core has **zero runtime dependencies**, so the full suite runs with `node --experimental-strip-types` and no install. State is a debounced JSON snapshot — single-instance by design; porting to Vercel/serverless means swapping `store.ts` for a KV/Redis implementation and `@x402/express` for `@x402/next`.

## Security & custody model

- **Non-custodial, advisory-only.** PaySafe sees payment *metadata* — it never signs, holds, or routes funds. The settle/refuse decision stays with your wallet/facilitator (optionally enforced via signed verdicts).
- Detected secrets are **redacted in responses** (first 4 + last 2 chars) and never persisted. Scan payloads are processed in memory; only nonce fingerprints, pins, velocity counters, reputation reports, and API-key usage are stored.
- **Honest limitations:** `context.origin` is self-declared — a fully compromised agent can lie or skip scanning entirely (mitigated by velocity caps, pinning, and wallet-side attestation enforcement, which don't depend on the agent's honesty). Injection detection is heuristic, not semantic; novel phrasings can evade the content tier. The reputation registry accepts unauthenticated reports and should be treated as a signal, not ground truth.

## Contributing

Issues and PRs welcome — particularly new detector patterns (with tests), a Redis `Store` implementation, and client SDKs that auto-tag tool-result provenance (`context.origin`) at the source. Run `npm test` before submitting; every detector change needs a covering test.

## License

MIT

# PaySafe

**A payment security firewall for [x402](https://x402.org) — screen every micropayment before it settles.**

[![x402](https://img.shields.io/badge/x402-v2-blue)](https://github.com/x402-foundation/x402)
[![network](https://img.shields.io/badge/settles%20on-Base%20(USDC)-0052FF)](https://docs.cdp.coinbase.com/x402/quickstart-for-sellers)
[![tests](https://img.shields.io/badge/tests-155%2F155-brightgreen)](test/run-tests.ts)
[![npm](https://img.shields.io/npm/v/paysafe-x402-client?label=sdk)](https://www.npmjs.com/package/paysafe-x402-client)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

Agents that pay over x402 get drained in predictable ways: secrets leak through payment metadata, captured authorizations get replayed, quoted prices get inflated, and poisoned web content tricks agents into paying addresses they never planned to pay. PaySafe is one `POST` before settlement that checks for all of it and returns **allow / flag / block** with machine-readable, per-check reasons — in **~0.6 ms**.

PaySafe is **advisory and non-custodial**: it never touches private keys, wallets, or funds. It wraps around whatever facilitator and wallet your agent already uses. And it's a first-class x402 seller itself — its endpoints are paid via the official x402 middleware, settle through the Coinbase CDP facilitator, and carry Bazaar discovery metadata.

```
Agent decides to pay ──► POST /v1/scan/outgoing ──► allow ──► wallet settles
                                   │
                                   ├──► flag  ──► agent pauses / confirms intent
                                   └──► block ──► wallet refuses (reason attached)
```

## Use it in 30 seconds

```bash
npm install paysafe-x402-client    # TypeScript/Node
pip install paysafe-x402           # Python
```

```ts
import { PaySafeClient, PaySafeBlockedError } from "paysafe-x402-client";
const paysafe = new PaySafeClient({ agentId: "my-agent" }); // free API key auto-minted, 100 free scans

paysafe.observe(fetchedPageText, { sourceUrl }); // tag what your agent just read → injection detection
await paysafe.guardOutgoing(payment);            // throws PaySafeBlockedError on a block verdict
```

The SDK ([`sdk/`](sdk/), zero dependencies) also verifies every verdict's Ed25519 attestation against a pinned key, tracks your free-call quota, and can subscribe to [plans](#api) autonomously. Wallet authors get standalone `verifyAttestation()` / `computePaymentCommitment()` — and the **enforcement kit**: `PaySafeEnforcer.guardSigner(account)` wraps any viem/ethers signer so it physically refuses to sign an x402 payment authorization without a fresh, payment-bound allow-verdict.

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
| Address poisoning | `pay_to` that matches a known counterparty or pinned merchant on its first + last characters but differs in the middle — the truncated-display ("0x2096…287C") vanity-address attack → block. Blocked payments are rolled back out of trust state, so repeat attempts keep detecting |
| ScoutScore trust signal (opt-in) | Merchant domains rated LOW/VERY_LOW by [ScoutScore](https://scoutscore.ai) (spam farms, template clones, dead endpoints) → flag, clearly labeled as an external third-party signal. Lookups are async + cached (zero scan latency), share the domain only, and can never block on their own. Enable with `SCOUTSCORE=on` |
| Known-bad list | O(1) membership against a curated/synced badlist |
| Deep content analysis | Base64-encoded and zero-width/homoglyph-obfuscated injection payloads, decoded/normalized and rescanned — bypassed below `MICRO_BYPASS_USD` (default $0.005), overridable per request via `policy.force_deep` |

**Signed verdicts.** Every response carries an Ed25519 `attestation` over `scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at` (public key at `/.well-known/paysafe-verdict-key`). The `payment_commitment` is `sha256(network|pay_to|asset|amount|nonce)`, so a wallet can confirm an allow-verdict belongs to *this* payment and hasn't been replayed onto another, and reject it after `expires_at`. Wallet policies can require a fresh signed allow-verdict before signing — turning the firewall from advisory into enforceable, still without PaySafe touching funds.

**Wallet-side enforcement.** Both SDKs ship that policy turnkey: `PaySafeEnforcer.guardSigner(account)` (TS: viem accounts, ethers v6 signers) / `PaySafeEnforcer.guard_signer(account)` (Python: eth-account, all call shapes) wraps the signer in a proxy that recomputes the payment commitment *from the typed data being signed* (EIP-3009 / ERC-2612) and refuses the signature unless a fresh, pinned-key-verified allow-verdict exists for exactly that commitment. Approvals are single-use and expire with the attestation; a compromised agent that scans payment A cannot sign payment B, and one that skips scanning cannot sign at all. Fail-closed and fully local; the two implementations are cross-validated against the same production signer — see [`sdk/README.md`](sdk/README.md#enforcement-a-wallet-that-refuses-unscanned-payments) and [`sdk-python/README.md`](sdk-python/README.md#enforcement-a-wallet-that-refuses-unscanned-payments).

**Tamper-evident audit log.** Every scan decision is appended to a hash-chained log (`AUDIT_LOG=on`) that stores a SHA-256 of the payment plus non-sensitive transaction facts — never the plaintext PII/secrets it scans. `GET /v1/audit/verify` recomputes the chain and reports any tampering; `GET /v1/audit/head` returns the current head hash for external anchoring. See `SECURITY-AUDIT.md`.

## API

| Endpoint | Price | Description |
|---|---|---|
| `POST /v1/scan/outgoing` | $0.01¹ | Screen a payment your agent is about to make |
| `POST /v1/scan/incoming` | $0.01¹ | Screen a 402 offer / payment request your agent received |
| `GET /v1/reputation/:address` | $0.01 | Counterparty report summary |
| `POST /v1/reputation/report` | free | Report a bad counterparty after the fact |
| `POST /v1/keys` | free | Issue an API key — **first 100 calls free** per key |
| `GET /v1/plans` | free | Machine-readable plan catalog (tiers, limits, subscribe mechanics) |
| `GET /v1/usage` | free | Your key's own usage stats: scan/verdict counts, free-tier quota, plan status |
| `GET /dashboard` | free | Browser usage dashboard for your key (see [Dashboards](#dashboards)) |
| `POST /v1/plans/subscribe` | plan price | Subscribe/renew a key on a plan — itself paid via x402, so agents upgrade autonomously |
| `GET /.well-known/x402` | free | x402 manifest |
| `GET /.well-known/agent-card.json` | free | Agent card |
| `GET /.well-known/paysafe-verdict-key` | free | Ed25519 public key for verdict attestations |
| `GET /v1/audit/verify` | free | Verify the audit-log hash chain (integrity check) |
| `GET /v1/audit/head` | free | Current audit-log head hash + sequence |
| `GET /` · `GET /health` | free | Self-documenting schema / liveness |

¹ Per-scan price drops on a plan: **Pro** ($4.99/30d) → $0.005/scan with 6× velocity headroom and deep content analysis on every scan; **Scale** ($19.99/30d) → $0.002/scan at the hard-ceiling limits. Plans raise *your own* thresholds only — replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier and can't be relaxed by paying more. See `GET /v1/plans`.

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
    "message": "b7911f8b-...|outgoing|block|95|2026-07-14T09:33:12Z|<payment_commitment>|2026-07-14T09:38:12Z",
    "signature_hex": "...",
    "payment_commitment": "sha256(network|pay_to|asset|amount|nonce)",
    "expires_at": "2026-07-14T09:38:12Z"
  }
}
```

## Dashboards

**Usage dashboard — `GET /dashboard`.** A single self-contained page where any key holder can see their own scan counts, verdict breakdown, free-tier quota, and plan status. Paste your `psk_` key and hit View; the key is sent only as an `X-API-Key` header to `GET /v1/usage` (never in a URL, so it can't leak via history, referrers, or server logs), and each key can only ever see its own account. Served with a locked-down CSP (`default-src 'none'`, zero external resources) and rendered exclusively via `textContent`.

**Owner dashboard — `GET /admin`.** Same interface, but sourced from the tamper-evident audit log: all-time scan totals and verdict split (including anonymous scans), a 30-day activity chart, most-fired checks, account/registry counts, and the audit-chain head with a one-click full-chain verify. Access is bound to a single key: set `ADMIN_KEY_SHA256` to the SHA-256 hex of your key and only that key unlocks `GET /v1/admin/stats` (constant-time compare; the endpoint 404s when unconfigured). Only the hash lives in config — consistent with keys being hashed at rest. Responses are aggregates only: no customer keys, agent ids, or addresses.

## Local development

For contributors and anyone auditing the detectors — runs entirely offline, payments disabled, no wallet needed:

```bash
git clone https://github.com/corbinallison/paysafe && cd paysafe
npm install

npm run dev            # local dev server — payments off
npm run demo:replay    # replay-attack demo: fresh nonce ALLOW → reused nonce BLOCK
npm test               # 155-test detector + hardening + plans + audit-log + dashboard suite
```

## Performance

Measured on the zero-dependency dev server (same handlers as production): **2,000 sequential scans in 1.20 s → 0.60 ms/scan round-trip**, including HTTP, JSON parsing, the full check suite, and Ed25519 signing. Deployed latency is dominated by network RTT; on the paid path, the x402 verify/settle round-trip to the facilitator (inherent to x402, identical on any host) dominates everything else.

## The hosted service

The production service at **https://paysafe-agent.com** is live on Base mainnet, indexed in the [x402 Bazaar](https://docs.cdp.coinbase.com/x402/bazaar), registered on [x402scan](https://www.x402scan.com), and monitored with a tamper-evident audit chain. Verify it yourself:

```bash
curl https://paysafe-agent.com/health
curl https://paysafe-agent.com/.well-known/x402
curl https://paysafe-agent.com/v1/audit/verify
```

## MCP server

Listed in the [official MCP registry](https://registry.modelcontextprotocol.io) as **`com.paysafe-agent/paysafe`** — or run it directly with zero config:

```jsonc
// claude_desktop_config.json / any MCP client
{
  "mcpServers": {
    "paysafe": {
      "command": "npx",
      "args": ["-y", "paysafe-x402"],
      "env": { "PAYSAFE_API_KEY": "psk_..." } // optional — mint one with the mint_api_key tool
    }
  }
}
```

Nine tools over stdio: `scan_outgoing_payment`, `scan_incoming_payment`, `check_counterparty_reputation`, `report_counterparty`, `mint_api_key`, `get_plans`, `subscribe_plan`, and `verify_verdict_attestation` (full Ed25519 verification performed locally — pinned key, commitment recompute, expiry). Defaults to the production service; set `PAYSAFE_URL` to point elsewhere.

## Detection defaults (hosted service)

Published for transparency — these are the thresholds your scans are judged against on the Starter tier ([plans](#api) raise the velocity/spend headroom; nothing can relax the safety checks):

| Behavior | Default |
|---|---|
| Overpayment | flag ≥3× expected price, block ≥10×, absolute ceiling $10 |
| Velocity | flag ≥10 scans/min (block at 2×), $5/hour cumulative spend cap |
| First contact | first payment to a never-seen counterparty flagged above $1 |
| Deep content analysis | bypassed below $0.005 payment value (`policy.force_deep` overrides; always on for Pro/Scale) |
| Replay window | nonces tracked for 24 h |
| Asset check | non-canonical USDC on the declared network → block |
| Merchant pinning | TOFU per resource domain; rotation → block |
| Address poisoning | ≥4 shared hex chars on both ends of a known address (but not equal) → block |
| ScoutScore signal | opt-in (`SCOUTSCORE=on`); LOW/VERY_LOW-rated domains → flag (never block); cached 24h |
| Verdict signing | Ed25519, always on, 5-minute attestation expiry |

Local dev configuration for contributors is documented in [`.env.example`](.env.example).

## Architecture

```
src/
  index.ts        Express + @x402/express middleware + CDP facilitator + Bazaar extension
  devserver.ts    Zero-dependency dev server (payments off) — same API surface
  api.ts          Framework-agnostic handlers (both servers route here)
  scanner.ts      Detector orchestration, tiering, verdict aggregation
  detectors/      pii · replay · overpayment · injection (fast + deep) · urlrisk
                  asset · badlist · pinning · poisoning · scoutscore · velocity
  reputation.ts   Shared report registry
  dashboard.ts    Self-contained usage dashboard (GET /dashboard)
  admindash.ts    Owner dashboard, audit-log-backed (GET /admin)
  verdictsign.ts  Ed25519 verdict attestation
  manifest.ts     /.well-known/x402 + agent card
  store.ts        JSON-file-backed state (tiny interface)
mcp/server.ts     MCP server (9 tools — npx paysafe-x402)
examples/         replay-demo.ts — reused-nonce attack blocked end-to-end
auditlog.ts       Tamper-evident hash-chained decision log
  commitment.ts     Payment hashing (attestation binding + audit digest)
test/             155-test suite (detectors, hardening, plans, crypto, audit, dashboards — npm test)
sdk/              TypeScript client SDK + wallet enforcement kit (npm: paysafe-x402-client, 54 tests)
sdk-python/       Python client SDK + wallet enforcement kit (PyPI: paysafe-x402, 59 tests)
```

Design notes: verdicts aggregate worst-first (any block ⇒ block); `risk_score` is severity-based with compounding for multiple independent findings; the detection core has **zero runtime dependencies**, so the full suite runs with `node --experimental-strip-types` and no install.

## Security & custody model

- **Non-custodial, advisory-only.** PaySafe sees payment *metadata* — it never signs, holds, or routes funds. The settle/refuse decision stays with your wallet/facilitator (optionally enforced via signed verdicts).
- Detected secrets are **redacted in responses** (first 4 + last 2 chars) and never persisted. Scan payloads are processed in memory; only nonce fingerprints, pins, velocity counters, reputation reports, and API-key usage are stored.
- **Honest limitations:** `context.origin` is self-declared — a fully compromised agent can lie or skip scanning entirely (mitigated by velocity caps, pinning, and wallet-side attestation enforcement, which don't depend on the agent's honesty). Injection detection is heuristic, not semantic; novel phrasings can evade the content tier. The reputation registry accepts unauthenticated reports and should be treated as a signal, not ground truth.

## Contributing

Issues and PRs welcome — particularly new detector patterns (with tests) and SDK improvements (the TS and Python clients live in [`sdk/`](sdk/) and [`sdk-python/`](sdk-python/)). Run `npm test` before submitting; every detector change needs a covering test.

## License

MIT

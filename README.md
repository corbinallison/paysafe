# PaySafe

**A payment security firewall for [x402](https://x402.org) — screen every micropayment before it settles.**

[![x402](https://img.shields.io/badge/x402-v2-blue)](https://github.com/x402-foundation/x402)
[![network](https://img.shields.io/badge/settles%20on-Base%20(USDC)-0052FF)](https://docs.cdp.coinbase.com/x402/quickstart-for-sellers)
[![tests](https://img.shields.io/badge/tests-264%2F264-brightgreen)](test/run-tests.ts)
[![npm](https://img.shields.io/npm/v/paysafe-x402-client?label=sdk)](https://www.npmjs.com/package/paysafe-x402-client)
[![license](https://img.shields.io/badge/license-BUSL--1.1-lightgrey)](LICENSE)

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

**New here? [Protect your x402 agent in 5 minutes →](QUICKSTART.md)**

The SDK ([`sdk/`](sdk/), zero dependencies) also verifies every verdict's Ed25519 attestation against a pinned key, tracks your free-call quota, and can subscribe to [plans](#api) autonomously. Wallet authors get standalone `verifyAttestation()` / `computePaymentCommitment()` — and the **enforcement kit**: `PaySafeEnforcer.guardSigner(account)` wraps any viem/ethers signer so it physically refuses to sign an x402 payment authorization without a fresh, payment-bound allow-verdict.

## Framework integrations

Building on an agent framework? PaySafe ships drop-in packages that give your agent "scan before you pay" in about two lines — a toolset plus a provenance mechanism that auto-tags what the agent reads, so the prompt-injection-triggered-payment detector works without any prompt engineering:

| Framework | Package | Install |
|---|---|---|
| LangChain | [`langchain-paysafe`](integrations/langchain-paysafe) | `pip install langchain-paysafe` |
| CrewAI | [`crewai-paysafe`](integrations/crewai-paysafe) | `pip install crewai-paysafe` |
| NeMo Agent Toolkit | [`nemo-paysafe`](integrations/nemo-paysafe) | `pip install nemo-paysafe` |
| Coinbase AgentKit | [`agentkit-paysafe`](integrations/agentkit-paysafe) | `pip install agentkit-paysafe` |
| Vercel AI SDK | [`paysafe-ai-sdk`](integrations/paysafe-ai-sdk) | `npm install paysafe-ai-sdk` |

Each exposes the same three tools (scan / check reputation / report) plus a framework-native provenance hook — a callback (LangChain), an after-tool-call hook (CrewAI), an explicit `content` argument (NeMo), a wallet-aware action (AgentKit), or an `onStepFinish` handler (Vercel AI SDK) — and a `guarded_payment` / `guardedPayment` wrapper for enforcement by construction (the payment executor never runs on a block verdict). See each package's README for the two-line setup.

## What it catches

**Core detectors**

| Check | What it catches |
|---|---|
| PII / secret detection | EVM private keys, seed phrases, AWS/OpenAI/Anthropic/GitHub/Slack keys, JWTs, `?api_key=` URL credentials, SSNs, Luhn-validated card numbers, emails, phones — in `resource_url`, `description`, `reason`, and `metadata`, *before* they're transmitted |
| Replay detection | Nonce reuse (stale or captured payment authorizations), scoped `network:payer:nonce`, configurable TTL window |
| Overpayment detection | Above a configurable multiple of expected price (flag ≥3×, block ≥10×) plus an absolute ceiling |
| Prompt-injection-triggered payments | Payments whose *decision* originated from content the agent just read (tool result / fetched page) rather than its own planning step; escalates on weighted injection tells in that content (override/redirect phrasing across a broad verb/object corpus and in 8 languages, spoofed system/chat-template/Guidance markers, smuggled model boundary tokens, fabricated conversation turns, concealment and urgency pressure), with extra weight when a tell sits near an address-like token; blocks when the `pay_to` address itself came from that content — even split across lines or laced with invisible characters |
| Resource URL risk (incoming) | IP-literal hosts, punycode/homoglyphs, link shorteners, `user@host` tricks, non-HTTPS, credential demands ("send your seed phrase") |
| Counterparty reputation | Shared post-hoc report registry, cross-checked on every scan; reporting is always free. Blocked injection scans also feed it automatically: a wallet caught being planted in just-read content (or used as vanity-bait) is flagged on every agent's future scans of it — one detection becomes network-wide protection (flag-only; scan inputs are client-supplied) |
| Delivery outcomes | Measured, commitment-bound delivery history per counterparty — a clean payment to a seller who never ships still fails you. Sellers with low delivery rates or repeated no-ships get flagged (never blocked: H-2 applies to measured history too) |

**Zero-latency hardening tier** — checks that hold even when the calling agent's narration is compromised:

| Check | What it catches |
|---|---|
| Velocity limits | ≥N scans/min (flag; block at 2×), cumulative hourly spend cap — rate and spend are observed facts, not self-reports |
| First-contact size cap | First payment to a never-seen counterparty above a threshold |
| Asset verification | `asset` contract that isn't canonical USDC on the declared network (lookalike-token attack) |
| Merchant pinning (TOFU) | `pay_to` rotation on a known resource domain → block; optional non-blocking CDP Bazaar cross-check |
| Address poisoning | `pay_to` that matches a known counterparty or pinned merchant on its first + last characters but differs in the middle — the truncated-display ("0x2096…287C") vanity-address attack → block. Also catches bait: a near-copy of the recipient or a trusted address *planted in the content the agent just read*. Blocked payments are rolled back out of trust state, so repeat attempts keep detecting |
| ScoutScore trust signal (opt-in) | Merchant domains rated LOW/VERY_LOW by [ScoutScore](https://scoutscore.ai) (spam farms, template clones, dead endpoints) → flag, clearly labeled as an external third-party signal. Lookups are async + cached (zero scan latency), share the domain only, and can never block on their own. Enable with `SCOUTSCORE=on` |
| Known-bad list | O(1) membership against a curated/synced badlist |
| Deep content analysis | Encoded/obfuscated injection payloads decoded and rescanned: base64 (both alphabets, line-wrapped, double-encoded), hex, percent-encoding, HTML entities, Unicode tag-character smuggling ("invisible ASCII"), and zero-width/Cyrillic-Greek-homoglyph obfuscation — bypassed below `MICRO_BYPASS_USD` (default $0.005) per payment, but drip-resistant: once cumulative scanned spend to a counterparty crosses the same threshold, the deep tier runs anyway; overridable per request via `policy.force_deep` |

**Signed verdicts.** Every response carries an Ed25519 `attestation` over `scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at` (public key at `/.well-known/paysafe-verdict-key`). The `payment_commitment` is `sha256(network|pay_to|asset|amount|nonce)`, so a wallet can confirm an allow-verdict belongs to *this* payment and hasn't been replayed onto another, and reject it after `expires_at`. Wallet policies can require a fresh signed allow-verdict before signing — turning the firewall from advisory into enforceable, still without PaySafe touching funds.

**Wallet-side enforcement.** Both SDKs ship that policy turnkey: `PaySafeEnforcer.guardSigner(account)` (TS: viem accounts, ethers v6 signers) / `PaySafeEnforcer.guard_signer(account)` (Python: eth-account, all call shapes) wraps the signer in a proxy that recomputes the payment commitment *from the typed data being signed* (EIP-3009 / ERC-2612) and refuses the signature unless a fresh, pinned-key-verified allow-verdict exists for exactly that commitment. Approvals are single-use and expire with the attestation; a compromised agent that scans payment A cannot sign payment B, and one that skips scanning cannot sign at all. Optional **local policy** bounds it further: a hard recipient allowlist (`allowedRecipients`) and per-payment / cumulative spend caps (`maxAmountAtomic` / `maxTotalAtomic`), checked against the typed data at signature time with no server involved — even a payment carrying a valid allow-verdict is refused if it pays an unlisted recipient or exceeds the caps, so a subverted advisory layer can only move bounded amounts to known parties. The agent can never extend the allowlist; the one escape hatch is opt-in (`overrideAdmitsRecipient`, on top of `acceptOverrides`): a human-approved override from [step-up approvals](#human-in-the-loop-step-up-approvals) admits exactly the payment it binds — never the recipient, and never past the spend caps. Fail-closed and fully local; the two implementations are cross-validated against the same production signer — see [`sdk/README.md`](sdk/README.md#enforcement-a-wallet-that-refuses-unscanned-payments) and [`sdk-python/README.md`](sdk-python/README.md#enforcement-a-wallet-that-refuses-unscanned-payments).

**Tamper-evident audit log.** Every scan decision is appended to a hash-chained log (`AUDIT_LOG=on`) that stores a SHA-256 of the payment plus non-sensitive transaction facts — never the plaintext PII/secrets it scans. `GET /v1/audit/verify` recomputes the chain and reports any tampering; `GET /v1/audit/head` returns the current head hash for external anchoring. See `SECURITY-AUDIT.md`.

## API

| Endpoint | Price | Description |
|---|---|---|
| `POST /v1/scan/outgoing` | $0.01¹ | Screen a payment your agent is about to make |
| `POST /v1/scan/incoming` | $0.01¹ | Screen a 402 offer / payment request your agent received |
| `GET /v1/reputation/:address` | $0.01 | Counterparty report summary |
| `POST /v1/reputation/report` | free | Report a bad counterparty after the fact |
| `POST /v1/keys` | free | Issue an API key — **first 100 calls free** per key |
| `POST /v1/keys/rotate` | free | Swap your key's secret for a fresh one — usage, free quota, and plan carry over; old secret honors a grace window (default 15 min, max 24 h) |
| `POST /v1/keys/revoke` | free | Permanently kill a leaked key and its account (requires `{"confirm": true}`; irreversible) |
| `POST /v1/approvals/config` | free | Enable [human-in-the-loop approvals](#human-in-the-loop-step-up-approvals): flag verdicts pause for a human decision via your webhook |
| `GET /v1/approvals/:id` | free | Poll a pending approval; on approve, returns the signed `override:allow` verdict |
| `POST /v1/outcomes` | free | Record whether a scanned, settled payment [actually delivered](#delivery-outcomes) (commitment-bound; the SDK wrappers do this automatically) |
| `GET /v1/plans` | free | Machine-readable plan catalog (tiers, limits, subscribe mechanics) |
| `GET /v1/usage` | free | Your key's own usage stats: scan/verdict counts, free-tier quota, plan status |
| `POST /v1/trust/evaluate` | free | [x402 trust-provider interface](https://github.com/x402-foundation/x402/issues/2299) — sellers gate settlement on a payer's history (TrustQuery → PASS/FAIL/UNCERTAIN + evidence) |
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

**Key lifecycle.** The account is the identity; the `psk_` secret is just a credential pointing at it. If a key leaks, `POST /v1/keys/rotate` mints a replacement secret bound to the same account — usage history, remaining free calls, and any active plan carry over unchanged (rotation never resets the free tier, so it can't be farmed). The old secret keeps scanning through an optional grace window (`grace_seconds`, default 900, `0` = dies instantly, max 24 h) so a fleet can switch over without downtime, but during grace it can no longer rotate or revoke — a leaked old secret can't take over the account. `POST /v1/keys/revoke` (with `{"confirm": true}`) is the kill switch: key and account die permanently, and the tombstone persists so the dead key keeps failing with a named reason instead of a mystery 401. Rotating the owner key? Update `ADMIN_KEY_SHA256` to the `api_key_sha256` in the rotate response.

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

## Dashboard

**Usage dashboard — `GET /dashboard`.** A single self-contained page where any key holder can see their own scan counts, verdict breakdown, free-tier quota, and plan status. Paste your `psk_` key and hit View; the key is sent only as an `X-API-Key` header to `GET /v1/usage` (never in a URL, so it can't leak via history, referrers, or server logs), and each key can only ever see its own account. Served with a locked-down CSP (`default-src 'none'`, zero external resources) and rendered exclusively via `textContent`. 

## Human-in-the-loop step-up approvals

A `flag` verdict no longer has to be a dead end. Configure a webhook once and every flag pauses for a human decision:

```jsonc
POST /v1/approvals/config   (X-API-Key)
{ "webhook_url": "https://hooks.your-ops.com/paysafe" }   // "format": "slack" for a Slack-style message
→ { "enabled": true, "webhook_secret": "psw_..." }        // shown ONCE; deliveries are HMAC-SHA256-signed
```

On a flag, your webhook receives the payment facts (the **full** `pay_to` — never truncated) and a one-time decide link. The reviewer opens `/approve`, checks the address character by character, and clicks Approve or Deny. Approval mints a short-lived (≤5 min) Ed25519-signed **override verdict** carrying the distinct tag `override:allow` in the signed message itself — an override can never masquerade as an organic allow, and it is bound to exactly the flagged payment's commitment. Blocks are never approvable; decisions are idempotent, single-token, and recorded in the tamper-evident audit log.

The agent side is two lines with the SDK:

```ts
const scan = await paysafe.scanOutgoing(payment);
if (scan.verdict === "flag" && scan.approval) {
  const override = await paysafe.waitForApproval(scan, { payment }); // polls; throws on deny/expiry
  enforcer.approve(override, payment);                               // requires acceptOverrides: true
}
```

(Python: `paysafe.wait_for_approval(scan, payment=payment)` / `PaySafeEnforcer(..., accept_overrides=True)`.)

**Why `acceptOverrides` is opt-in:** an agent that holds its own API key could configure the approval webhook to point somewhere it can read, then "approve" its own flags — no human involved. Overrides are only trustworthy when the webhook receiver is out of the agent's reach (your ops channel, not the agent's environment). The enforcement kit therefore refuses `override:allow` unless the wallet owner explicitly opts in, exactly like `allowFlagged`.

**Disabling.** Per key: `POST /v1/approvals/config` with `{"webhook_url": null}` — the response carries an advisory reminding you that flags return to advisory-only (nothing pauses, no overrides are minted, and an `acceptOverrides` wallet has no flag→payment path anymore); pending approvals stay decidable until they expire. Server-wide: `APPROVALS=off` refuses new configs and opens no new approvals, with the same advisory, while in-flight approvals remain decidable so a mid-flight disable strands nothing.

## Delivery outcomes

Every scan check validates the *payment* — well-formed, un-manipulated. None of them can tell you the seller will actually **deliver**: a perfectly clean payment to a seller who never ships still fails the agent. The outcome loop closes that gap with measured history instead of accusations:

- x402 delivery is usually **synchronous** — the resource arrives in the paid response — so the SDK payment-path wrappers (`wrapFetchWithPaySafe` / `wrap_transport_with_paysafe`) observe it mechanically and report it **automatically**: paid 2xx → `delivered`, paid 5xx/second-402 → `not_delivered`, with status/bytes/latency evidence (opt out with `reportOutcomes: false`). Settling some other way? `POST /v1/outcomes` or `client.reportOutcome(scan, ...)` directly.
- Every outcome is **bound to a scan PaySafe performed**: the report must present the `scan_id` + `payment_commitment` pair, one outcome per scan, keyed scans only from the scanning account. Fabricating delivery history requires making real, scanned payments — an anti-Sybil property free-text reports can't have.
- Aggregated delivery rates surface in `GET /v1/reputation/:address` and in a `delivery` check on every future scan of that counterparty: low rates and repeated no-ships **flag** (never block — measured history is still third-party signal, audit H-2 applies).
- The **denominator is public too**: reputation lookups report `scans_seen` (non-blocked scans PaySafe performed against the counterparty) and `report_coverage` alongside the outcome counts — so selectively reported outcomes read as low coverage instead of passing as a complete record, and a counterparty with scans but zero reported outcomes shows that population instead of reading as "no history". Coverage is informational only (scan counts are client-driven) and never feeds a flag.

Honest limits: this measures that content *arrived*, not that it was *good* — quality judgments stay with `POST /v1/reputation/report` — and it covers digital, synchronous x402 delivery, not physical shipment.

## Local development

For contributors and anyone auditing the detectors — runs entirely offline, payments disabled, no wallet needed:

```bash
git clone https://github.com/corbinallison/paysafe && cd paysafe
npm install

npm run dev            # local dev server — payments off
npm run demo:replay    # replay-attack demo: fresh nonce ALLOW → reused nonce BLOCK
npm test               # 264-test detector + hardening + plans + audit-log + dashboard + key-lifecycle + approvals + outcomes suite
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

Eleven tools over stdio: `scan_outgoing_payment`, `scan_incoming_payment`, `check_counterparty_reputation`, `report_counterparty`, `report_payment_outcome` (close the loop after settlement — builds measured delivery history), `mint_api_key`, `rotate_api_key` (leaked-key recovery — fresh secret, same account), `check_approval_status` (poll a human-in-the-loop approval), `get_plans`, `subscribe_plan`, and `verify_verdict_attestation` (full Ed25519 verification performed locally — pinned key, commitment recompute, expiry). Defaults to the production service; set `PAYSAFE_URL` to point elsewhere.

## Detection defaults (hosted service)

Published for transparency — these are the thresholds your scans are judged against on the Starter tier ([plans](#api) raise the velocity/spend headroom; nothing can relax the safety checks):

| Behavior | Default |
|---|---|
| Overpayment | flag ≥3× expected price, block ≥10×, absolute ceiling $10 |
| Velocity | flag ≥10 scans/min (block at 2×), $5/hour cumulative spend cap |
| First contact | first payment to a never-seen counterparty flagged above $1 |
| Deep content analysis | bypassed below $0.005 payment value — until cumulative scanned spend to the counterparty crosses $0.005, then always on for that pair (`policy.force_deep` overrides; always on for Pro/Scale) |
| Replay window | nonces tracked for 24 h |
| Asset check | non-canonical USDC on the declared network → block |
| Merchant pinning | TOFU per resource domain; rotation → block |
| Address poisoning | ≥4 shared hex chars on both ends of a known address (but not equal) → block; same lookalike planted in just-read content → block (untrusted origin) or flag |
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
  outcomes.ts     Delivery-outcome ledger (commitment-bound) + delivery check
  approvals.ts    Human-in-the-loop step-up approvals (webhook + overrides)
  approvepage.ts  Human decide page (GET /approve)
  dashboard.ts    Self-contained usage dashboard (GET /dashboard)
  admindash.ts    Owner dashboard, audit-log-backed (GET /admin)
  verdictsign.ts  Ed25519 verdict attestation
  manifest.ts     /.well-known/x402 + agent card
  store.ts        JSON-file-backed state (tiny interface)
mcp/server.ts     MCP server (11 tools — npx paysafe-x402)
examples/         replay-demo.ts — reused-nonce attack blocked end-to-end
auditlog.ts       Tamper-evident hash-chained decision log
  commitment.ts     Payment hashing (attestation binding + audit digest)
test/             264-test suite (detectors, hardening, plans, crypto, audit, dashboards, key lifecycle, approvals, outcomes — npm test)
sdk/              TypeScript client SDK + wallet enforcement kit + payment-path wrapper (npm: paysafe-x402-client, 86 tests)
sdk-python/       Python client SDK + wallet enforcement kit + payment-path wrapper (PyPI: paysafe-x402, 89 tests)
```

Design notes: verdicts aggregate worst-first (any block ⇒ block); `risk_score` is severity-based with compounding for multiple independent findings; the detection core has **zero runtime dependencies**, so the full suite runs with `node --experimental-strip-types` and no install.

## Security & custody model

- **Non-custodial, advisory-only.** PaySafe sees payment *metadata* — it never signs, holds, or routes funds. The settle/refuse decision stays with your wallet/facilitator (optionally enforced via signed verdicts).
- Detected secrets are **redacted in responses** (first 4 + last 2 chars) and never persisted. Scan payloads are processed in memory; only nonce fingerprints, pins, velocity counters, reputation reports, and API-key usage are stored.
- **Threat model — what holds against whom.** Two attacker tiers matter, and they are not the same:
  - A **confused agent** — a prompt-injected model still making tool calls through its normal harness — is what PaySafe is built for. Detection catches manipulated payments; velocity and spend caps, first-contact limits, and merchant pinning are computed server-side from observed scans, so they bind on every scanned payment no matter what the model believes; and `guardSigner` closes the skip-scanning hole at the wallet, because the wrapped signer recomputes the commitment from the typed data actually being signed and refuses without a fresh allow-verdict — with optional local policy (recipient allowlist + spend caps) bounding even approved payments. (`context.origin` is self-declared, so an agent that lies about provenance weakens the content tier — the caps, pinning, and signer enforcement don't depend on it.)
  - A **compromised process** — attacker code running where the wallet's private key is readable — defeats any in-process wrapper, including our enforcer: it can sign with the raw key and never touch PaySafe. PaySafe is non-custodial and never holds your key, which also means it cannot protect a key your own process exposes. For this tier the mitigation is key isolation — keep the signer in a separate process, KMS, or hardware, and run the enforcer at that boundary so nothing inside the agent process can produce a signature. (The auto-minted `psk_` API key is a scan credential only: it can spend your PaySafe quota, never your funds.)
- **Honest limitations:** injection detection is heuristic, not semantic; novel phrasings can evade the content tier (our public eval corpus tracks known gaps). The reputation registry accepts unauthenticated reports and should be treated as a signal, not ground truth.

## Contributing

Issues and PRs welcome — particularly new detector patterns (with tests) and SDK improvements (the TS and Python clients live in [`sdk/`](sdk/) and [`sdk-python/`](sdk-python/)). Run `npm test` before submitting; every detector change needs a covering test. By submitting a contribution you agree to license it to PaySafe, LLC under the terms of the [LICENSE](LICENSE), and you grant PaySafe, LLC the right to relicense the contribution as part of the Licensed Work (including under the Change License).

## License

[Business Source License 1.1](LICENSE) (source-available). You can read, run, modify, and self-host PaySafe, and use the SDKs/MCP server against the hosted service — including inside commercial products. What the license restricts is offering the code itself as a competing paid payment-security service. Each version converts to Apache 2.0 four years after release. Versions ≤ 1.4.0 remain MIT.

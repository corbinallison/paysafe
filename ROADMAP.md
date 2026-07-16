# PaySafe Roadmap

_Post-launch feature roadmap. Updated 2026-07-16. Operational/legal to-dos live in GOLIVE.md._

**Shipped & published (2026-07-16):** server 1.1.2 (llms.txt discovery, imperative MCP tooling, trust-provider endpoint, address-poisoning + ScoutScore detectors, usage/owner dashboards); `paysafe-x402-client` 0.3.0 + `paysafe-x402` (PyPI) 0.3.0 (enforcement kit + default-payment-path wrapper in both languages); `langchain-paysafe` 0.1.0 (LangChain docs PR submitted). Trust-provider endpoint deployed live; x402#2299 comment posted.

**Top open items (not yet built):** (1) Reputation registry v2 (§1). (2) Human-in-the-loop step-up approvals (§6). (3) ERC-8004 validator registration (§6). (API-key rotation/revocation ✅ built 2026-07-16 — see §0. All five DISCOVERY-PLAN framework integrations are built AND published; docs PRs to Vercel/LangChain/CrewAI are open, AgentKit/NeMo submissions parked in SUBMISSIONS-TODO.md.)

## 0. API-key rotation & revocation — ✅ BUILT 2026-07-16

The oldest open security gap is closed. The account (KeyRecord) is the
identity; the `psk_` secret is a credential pointing at it. `POST
/v1/keys/rotate` (authed by the current key) mints a replacement secret bound
to the SAME account — usage, remaining free calls, plan, and dashboard stats
carry over; rotation never resets the free tier so it can't be farmed. The old
secret honors a grace window (`grace_seconds` default 900, 0 = instant death,
max 24 h) during which it can scan but NOT rotate/revoke — a leaked old secret
can't take over the account (grace also never chains across rotations). `POST
/v1/keys/revoke` (`{"confirm": true}`) is the irreversible kill switch.
Tombstones persist, so dead keys fail with named 401s (`key_rotated` /
`key_revoked`) while unknown keys keep the generic 401 (no probe oracle).
Admin hardening included: hash match alone no longer unlocks `/v1/admin/stats`
— the key must be LIVE, so revoking the owner key actually cuts admin access
(rotate returns `api_key_sha256` for rebinding `ADMIN_KEY_SHA256`). Both
lifecycle routes share the key-mint rate limiter (tombstone-flood defense);
the revoked map is size-capped like every other store map. `rotate_api_key`
MCP tool added. 26 new tests (198/198). Not built (deliberately): the one-time
recovery secret idea — a second long-lived credential doubles the theft
surface; minting a new key is cheap.

## 1. Reputation registry v2 — fairness & abuse resistance

- ✅ **Delivery-outcome ledger** — BUILT 2026-07-16 (the strongest v2 item; prompted by CDP-Discord feedback: "a perfectly clean payment to a seller who never ships still fails the agent"). `POST /v1/outcomes` records delivered/not_delivered/partial/wrong_content per settlement, BOUND to a scan PaySafe performed (scan_id + payment_commitment verified against a rolling scan index; one outcome per scan; keyed scans only from the scanning account) — fabricating delivery history requires real, scanned payments. SDK payment-path wrappers auto-capture outcomes mechanically (x402 delivery is synchronous: paid 2xx → delivered, 5xx/second-402 → not_delivered with evidence; `reportOutcomes:false` opts out) plus manual `reportOutcome`/`report_outcome`. Delivery rates surface in reputation lookups and a scan-time `delivery` check: low rate (<70% over ≥5 outcomes) or repeated no-ships with zero successes → FLAG only (H-2 applies to measured history too); no history reads as no history. Aggregation keys off the pay_to captured at scan time, never reporter input. Rotation migrates the scan index with the account. 14 server + 5 TS + 5 Py new tests (264/86/89 green). Measured outcomes also dilute false accusations naturally — the best fairness lever in this section.


The registry records accusations, not verdicts, and reports can only ever `flag` (never `block`) — so mistakes are survivable. These make it fairer and harder to game:

- **Time decay** — report weight decays with age (e.g. half-life ~90 days), so a wallet's 2026 mistakes don't follow it forever. `first_reported`/`last_reported` already exist in the summary; risk grading should use them.
- **Dispute / rebuttal** — a reported address can attach a signed response (prove key ownership by signing the rebuttal with the reported wallet's key). Rebuttals surface in the reputation summary; agents weigh both sides.
- **Reporter credibility weighting** — reports from agents with long, observed payment history count more than fresh anonymous `reporter_agent_id`s. Possible inputs: age of first sighting, scan volume, distinct counterparties. (Never let credibility make a report block — it only scales flag confidence.)
- **Remediation path** — documented process for compromised-then-rotated keys: mark address as "historical compromise, rotated on <date>" after signed proof from the new key.

## 2. Plan / tier structures (monetization) — ✅ BUILT 2026-07-14

Implemented as designed: `src/plans.ts` (catalog: Pro $4.99/30d, Scale $19.99/30d + hard ceilings), `GET /v1/plans`, x402-paid `POST /v1/plans/subscribe` with autonomous renewal, per-key policy resolution in the scan path, per-plan scan pricing via one payment layer per distinct price, manifest/agent-card/OpenAPI updates. 21 new tests (87/87 passing); dev-server e2e verified (Pro key absorbs a 15-scan burst that flags a Starter key). Original design sketch:

- `GET /v1/plans` (free): machine-readable catalog — `price_per_scan`, `included_calls`, `max_scans_per_minute`, `max_usd_per_hour`, feature flags (`force_deep`, `cdp_pin_verify`), `duration_days`, upgrade instructions. Mirrored in `/.well-known/x402` and the agent card.
- `POST /v1/plans/subscribe` (x402-paid): 402 quotes the plan price; the agent pays via its normal pay-and-retry flow; its API key is upgraded with an expiry. Renewal = pay again before expiry. Fully autonomous purchase/renewal, zero new protocol.
- Scan-time policy resolution: plan overrides → env defaults. Per-key pricing needs a thin dynamic-pricing layer in front of `@x402/express` (static per-route today).
- **Hard ceilings stay:** plans loosen a customer's own thresholds (velocity/volume before flags) but can never disable replay, pin-mismatch, or asset verification, and even the top tier keeps a spend cap. Never sell "scan less carefully."
- Touches: `store.ts` (plan + expiry on key records), `config.ts` (policy resolution), `api.ts` (plans endpoints, per-key pricing), manifest, docs, tests. Est. 1–2 days.

## 3. Detection improvements

- ✅ **Client SDK provenance auto-tagging** — BUILT 2026-07-14: `sdk/` (`paysafe-x402-client`, zero-dep, Node 18+). `observe()`/`notePlanning()` auto-tag `context.origin`; observations are single-use with a TTL. 32/32 tests, cross-validated against the real server signer. Publishing now automated: Actions → publish-npm (OIDC trusted publishing, same posture as publish-pypi).
- ✅ **Wallet-side verifier** — absorbed into the SDK: standalone `verifyAttestation()` + `computePaymentCommitment()` exports (pinned-key signature check, commitment recompute/replay defense, expiry). Optional follow-up: publish a docs page with the snippet inline.
- ✅ **Address-poisoning detection** — BUILT 2026-07-16: `src/detectors/poisoning.ts`. Blocks a `pay_to` that shares ≥4 leading and ≥4 trailing hex chars with a known counterparty (this agent's history) or pinned merchant but isn't that address — the truncated-display vanity-address attack. Runs before pinning/velocity so lookalikes are judged against pre-scan state; blocked scans are rolled back out of trust state (counterparty history + fresh pins) so repeats keep detecting. 12 new tests.

## 4. Infrastructure & scale

- **WORM upgrade** — move offsite audit backup from MEGA-folder copies to S3 Object Lock (compliance mode) when revenue justifies; keep daily head-hash anchoring regardless.
- **Multi-instance readiness** — shared state + signing key to Redis/Postgres/KMS before running >1 instance (SECURITY-AUDIT.md M-3).
- **Status page + changelog** — public uptime/incident page; builds counterparty trust for a security product.

## 5. Adoption & distribution

The product surface now exceeds distribution. Cheapest-first:

- **Update discovery surfaces with the SDK** — README/LISTINGS done; add the npm link to the awesome-x402 PR (#848) if maintainers haven't merged; mention in the x402scan/Poncho merchant page.
- ✅ **MCP registry listing** — LIVE 2026-07-15: published as **`com.paysafe-agent/paysafe`** (status: active) in the official MCP registry, domain-verified via DNS. 9 tools, `npx paysafe-x402`, npm `mcpName` ownership proof on v1.1.1.
- **Quickstart tutorial** — one page: "Protect your x402 agent in 5 minutes" (SDK install → observe → guard → what a block looks like). Post to dev.to #x402, the x402 builders Telegram/Discord, r/x402.
- ✅ **Python SDK** — BUILT 2026-07-15, PUBLISHED to PyPI (`paysafe-x402`, latest 0.3.0). Full parity with the TS client; verifier cross-validated against a fixture signed by the real Node signer. Publishing automated via Actions → publish-pypi (OIDC trusted publishing).
- ✅ **Customer usage dashboard** — BUILT 2026-07-16: `GET /dashboard` (self-contained page, strict CSP, key via header only) backed by `GET /v1/usage` (own-key-only aggregates). Plus an owner dashboard at `GET /admin`: audit-log-backed all-time stats, 30-day activity, top fired checks, chain verify — unlocked by the single key matching `ADMIN_KEY_SHA256`. Still the natural home for reputation rebuttals later.

## 6. Enforcement & ecosystem trust (added 2026-07-16)

The differentiation thesis: everyone else in the trust space produces *scores*; PaySafe produces signed, payment-bound *verdicts* — so PaySafe alone can move from "advisory" to "physically enforced."

- ✅ **Wallet-side enforcement kit** — BUILT 2026-07-16: `sdk/src/enforce.ts` (`PaySafeEnforcer`, `guardSigner`, `paymentFromTypedData`), shipped in `paysafe-x402-client` 0.2.0. Wraps any `signTypedData`-bearing signer (viem/ethers, both call shapes) in a Proxy that recomputes the payment commitment from the EIP-3009/ERC-2612 typed data being signed and refuses without a live, pinned-key-verified allow-verdict for exactly that commitment. Single-use approvals, attestation expiry + optional `maxAgeMs`, allow-only by default, `strictTypes` deny-by-default mode, fail-closed. 22 new tests (54/54) cross-validated against the real server signer. ✅ PUBLISHED in both languages as part of the 0.3.0 SDK release (2026-07-16). Follow-ups: ERC-4337 session-key/paymaster reference module; a "PaySafe-gated wallet in 5 minutes" tutorial. ✅ **Python parity BUILT 2026-07-16**: `sdk-python/src/paysafe_x402/enforce.py` (`PaySafeEnforcer.guard_signer` — eth-account positional/kwarg/`full_message` call shapes); 25 new tests (59/59), incl. a cross-language test where a Node-signed attestation drives the Python gate end to end.
- ✅ **Default-payment-path wrappers** — BUILT 2026-07-16: `wrapFetchWithPaySafe` (TS) / `wrap_transport_with_paysafe` (Python), SDKs 0.3.0. One-line wrap of the official x402 buyer flow: probe → guard outgoing (provenance-fed) → scan the 402 offer as incoming → only then hand off to the paying fetch/transport. Blocks throw before any payment is signed; unparseable offers fail closed. 27 new tests (68/68 TS, 72/72 Python). ✅ PUBLISHED as SDK 0.3.0 (2026-07-16).
- ✅ **Human-in-the-loop step-up approvals** — BUILT 2026-07-16 (server 1.2.0, SDKs 0.4.0). Flags pause for a human: `POST /v1/approvals/config` registers an operator webhook (HMAC-SHA256-signed deliveries, SSRF-hardened: https-only, DNS-resolved private-range rejection with pinned connect address); on a flag the webhook gets the payment facts (FULL pay_to) + a one-time decide link; the `/approve` page (fragment-carried single-use token, textContent-only rendering) mints a ≤300s Ed25519 override with the distinct signed tag `override:allow` bound to the payment commitment. Blocks are never approvable (decide-time captured-verdict guard); decisions are idempotent + audit-chained; unknown-id/bad-token responses indistinguishable. SDKs: `waitForApproval` / `wait_for_approval` polling helpers; enforcement kit accepts overrides only via the **acceptOverrides/accept_overrides opt-in** (a self-webhooked agent could otherwise approve its own flags — documented threat model). `check_approval_status` MCP tool. 46 server + 13 TS + 13 Py new tests (244/81/84 green). Remaining ideas: email/Slack-native channels beyond generic webhook + slack format; paid-tier gating.
- ✅ **langchain-paysafe** — BUILT 2026-07-16: `integrations/langchain-paysafe/` (v0.1.0). Three imperative tools, a provenance auto-observe callback (tool outputs + retrievals feed injection detection with self-echo suppression), and `guarded_payment()` for enforcement-by-construction. Tested against a structural langchain-core stub (21/21; real-langchain-core check runs in the publish-pypi CI job). ✅ PUBLISHED to PyPI 2026-07-16; ✅ LangChain integrations-docs PR submitted.
- ✅ **crewai-paysafe** — BUILT 2026-07-16: `integrations/crewai-paysafe/` (v0.1.0). Same 3-layer design ported to CrewAI: three `BaseTool` subclasses, `register_paysafe_provenance()` (CrewAI after-tool-call hook), `guarded_payment()`. 24 tests vs a structural crewai stub (real-crewai check in the `crewai` publish-pypi CI job). Wired into publish-pypi + version tooling. Pending: PyPI pending-publisher + publish + CrewAI docs submission.
- ✅ **nemo-paysafe** — BUILT 2026-07-16: `integrations/nemo-paysafe/` (v0.1.0). Three config-driven NeMo Agent Toolkit functions (`@register_function` + `nat.plugins` entry point), provenance as an explicit `content` arg (NeMo has no global tool hook), shared client cache, async. 13 tests vs a structural nat stub (real-nvidia-nat check in the `nemo` publish-pypi CI job). Pending: PyPI pending-publisher + publish + PR to NVIDIA/NeMo-Agent-Toolkit.
- ✅ **agentkit-paysafe** — BUILT 2026-07-16: `integrations/agentkit-paysafe/` (v0.1.0). Coinbase AgentKit action provider — three `@create_action`s; scan auto-fills `payer` from the agent's wallet and takes a `content` arg for injection detection. 17 tests vs a structural coinbase-agentkit stub (real check in the `agentkit` publish-pypi CI job). On-brand (Coinbase runs the x402 facilitator). Pending: PyPI pending-publisher + publish + submission to coinbase/agentkit.
- ✅ **paysafe-ai-sdk** — BUILT 2026-07-16: `integrations/paysafe-ai-sdk/` (v0.1.0). The Vercel AI SDK port and the first TypeScript framework integration: `paysafeTools()` (three imperative tools), `paysafeProvenance()` — an `onStepFinish` handler that auto-observes every tool result (both `toolResults[].output` and the older `.result` shape; PaySafe's own tools skipped), and `guardedPayment()` for enforcement-by-construction. The AI SDK hands `onStepFinish` the whole step's `toolResults`, so the full provenance loop is a single line — the cleanest port of the auto-tagging pattern so far. 22 tests (stub-driven locally against tiny `ai`/`zod`/`paysafe-x402-client` shims; the real packages run the same file unchanged in the `ai-sdk` publish-npm CI job). Wired into publish-npm + version tooling. Pending: first manual `npm publish` to create the project, then add the trusted publisher; submission to the Vercel AI SDK community/providers list. **This completes all five DISCOVERY-PLAN framework integrations (LangChain, CrewAI, NeMo, AgentKit, Vercel).**
- ✅ **x402 trust-provider interface** — BUILT 2026-07-16: `src/trust.ts` + `POST /v1/trust/evaluate` (free, rate-limited via `TRUST_QUERIES_PER_IP_PER_HOUR`). Implements the provider half of x402#2299/PR#2300: TrustQuery about a payer in, TrustEvaluation out. Seller-side — the mirror of our buyer-side scan, and a new market. Decision policy preserves H-2: hard FAIL only from the curated badlist; self-asserted reports max out at UNCERTAIN (a Sybil attacker must not be able to weaponize our provider to abort honest settlements under fail-closed aggregation). `evidence_uri` links the public reputation summary. 12 tests (172/172). ✅ DEPLOYED LIVE + #2299 comment posted (2026-07-16).
- **ERC-8004 validator registration** — the identity/reputation/validation registries went live on Ethereum mainnet + Base in Jan 2026. Register PaySafe as a validation provider and publish verdicts as on-chain validation attestations (hash-linked to the audit chain), making PaySafe infrastructure *inside* the emerging agent-trust standard rather than an app beside it. Cheap to do early; also the natural contribute-side answer to §7 federation.

## 7. Registry network effects

- **Badlist syndication** — curated known-bad list as a syndicated feed (potential premium tier).
- **Cross-registry federation** — exchange reports with other x402 trust services with provenance labels, if partners emerge.
  - ✅ **ScoutScore consume-side BUILT 2026-07-16**: `src/detectors/scoutscore.ts` — opt-in (`SCOUTSCORE=on`) async cached lookups of merchant-domain trust ratings; LOW/VERY_LOW surfaces as a labeled external flag (never a block). Free-tier only: a 402 from their API caches as "unavailable" (PaySafe holds no wallet and never pays for lookups). Contribute-side (feeding our reports out) still open.

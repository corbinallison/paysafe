# PaySafe Roadmap

_Post-launch feature roadmap. Updated 2026-07-16. Operational/legal to-dos live in GOLIVE.md._

## 1. Reputation registry v2 — fairness & abuse resistance

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
- ✅ **Python SDK** — BUILT 2026-07-15: `sdk-python/` (`paysafe-x402`, Python 3.9+, single dep `cryptography`). Full parity with the TS client; verifier cross-validated against a fixture signed by the real Node signer (34/34 tests). PyPI name confirmed free. **Pending [You]:** `pip install build twine && python -m build && twine upload dist/*` from `sdk-python/`.
- ✅ **Customer usage dashboard** — BUILT 2026-07-16: `GET /dashboard` (self-contained page, strict CSP, key via header only) backed by `GET /v1/usage` (own-key-only aggregates). Plus an owner dashboard at `GET /admin`: audit-log-backed all-time stats, 30-day activity, top fired checks, chain verify — unlocked by the single key matching `ADMIN_KEY_SHA256`. Still the natural home for reputation rebuttals later.

## 6. Enforcement & ecosystem trust (added 2026-07-16)

The differentiation thesis: everyone else in the trust space produces *scores*; PaySafe produces signed, payment-bound *verdicts* — so PaySafe alone can move from "advisory" to "physically enforced."

- ✅ **Wallet-side enforcement kit** — BUILT 2026-07-16: `sdk/src/enforce.ts` (`PaySafeEnforcer`, `guardSigner`, `paymentFromTypedData`), shipped in `paysafe-x402-client` 0.2.0. Wraps any `signTypedData`-bearing signer (viem/ethers, both call shapes) in a Proxy that recomputes the payment commitment from the EIP-3009/ERC-2612 typed data being signed and refuses without a live, pinned-key-verified allow-verdict for exactly that commitment. Single-use approvals, attestation expiry + optional `maxAgeMs`, allow-only by default, `strictTypes` deny-by-default mode, fail-closed. 22 new tests (54/54) cross-validated against the real server signer. **Pending [You]:** one-time npmjs.com trusted-publisher setup for both npm packages, then GitHub → Actions → publish-npm → `sdk` to ship 0.2.0 (see `.github/workflows/publish-npm.yml`). Follow-ups: ERC-4337 session-key/paymaster reference module; Python SDK parity; a "PaySafe-gated wallet in 5 minutes" tutorial.
- **Human-in-the-loop step-up approvals** — fill the gap between flag and block: on a flag, notify the operator (webhook / email / Slack) with the payment facts; a human click mints a short-lived, signed override-verdict bound to that payment's commitment, which the enforcement kit accepts like any allow. Design constraints: override attestations must be distinguishable from organic allows (separate message tag), TTL ≤ 5 min, and the click UI must show the full pay_to (address-poisoning lesson). Natural paid-tier feature; composes directly with the enforcement kit.
- **ERC-8004 validator registration** — the identity/reputation/validation registries went live on Ethereum mainnet + Base in Jan 2026. Register PaySafe as a validation provider and publish verdicts as on-chain validation attestations (hash-linked to the audit chain), making PaySafe infrastructure *inside* the emerging agent-trust standard rather than an app beside it. Cheap to do early; also the natural contribute-side answer to §7 federation.

## 7. Registry network effects

- **Badlist syndication** — curated known-bad list as a syndicated feed (potential premium tier).
- **Cross-registry federation** — exchange reports with other x402 trust services with provenance labels, if partners emerge.
  - ✅ **ScoutScore consume-side BUILT 2026-07-16**: `src/detectors/scoutscore.ts` — opt-in (`SCOUTSCORE=on`) async cached lookups of merchant-domain trust ratings; LOW/VERY_LOW surfaces as a labeled external flag (never a block). Free-tier only: a 402 from their API caches as "unavailable" (PaySafe holds no wallet and never pays for lookups). Contribute-side (feeding our reports out) still open.

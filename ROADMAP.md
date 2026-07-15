# PaySafe Roadmap

_Post-launch feature roadmap. Updated 2026-07-14. Operational/legal to-dos live in GOLIVE.md._

## 1. Reputation registry v2 — fairness & abuse resistance

The registry records accusations, not verdicts, and reports can only ever `flag` (never `block`) — so mistakes are survivable. These make it fairer and harder to game:

- **Time decay** — report weight decays with age (e.g. half-life ~90 days), so a wallet's 2026 mistakes don't follow it forever. `first_reported`/`last_reported` already exist in the summary; risk grading should use them.
- **Dispute / rebuttal** — a reported address can attach a signed response (prove key ownership by signing the rebuttal with the reported wallet's key). Rebuttals surface in the reputation summary; agents weigh both sides.
- **Reporter credibility weighting** — reports from agents with long, observed payment history count more than fresh anonymous `reporter_agent_id`s. Possible inputs: age of first sighting, scan volume, distinct counterparties. (Never let credibility make a report block — it only scales flag confidence.)
- **Remediation path** — documented process for compromised-then-rotated keys: mark address as "historical compromise, rotated on <date>" after signed proof from the new key.

## 2. Plan / tier structures (monetization) — ✅ BUILT 2026-07-14 (pending deploy)

Implemented as designed: `src/plans.ts` (catalog: Pro $4.99/30d, Scale $19.99/30d + hard ceilings), `GET /v1/plans`, x402-paid `POST /v1/plans/subscribe` with autonomous renewal, per-key policy resolution in the scan path, per-plan scan pricing via one payment layer per distinct price, manifest/agent-card/OpenAPI updates. 21 new tests (87/87 passing); dev-server e2e verified (Pro key absorbs a 15-scan burst that flags a Starter key). Original design sketch:

- `GET /v1/plans` (free): machine-readable catalog — `price_per_scan`, `included_calls`, `max_scans_per_minute`, `max_usd_per_hour`, feature flags (`force_deep`, `cdp_pin_verify`), `duration_days`, upgrade instructions. Mirrored in `/.well-known/x402` and the agent card.
- `POST /v1/plans/subscribe` (x402-paid): 402 quotes the plan price; the agent pays via its normal pay-and-retry flow; its API key is upgraded with an expiry. Renewal = pay again before expiry. Fully autonomous purchase/renewal, zero new protocol.
- Scan-time policy resolution: plan overrides → env defaults. Per-key pricing needs a thin dynamic-pricing layer in front of `@x402/express` (static per-route today).
- **Hard ceilings stay:** plans loosen a customer's own thresholds (velocity/volume before flags) but can never disable replay, pin-mismatch, or asset verification, and even the top tier keeps a spend cap. Never sell "scan less carefully."
- Touches: `store.ts` (plan + expiry on key records), `config.ts` (policy resolution), `api.ts` (plans endpoints, per-key pricing), manifest, docs, tests. Est. 1–2 days.

## 3. Detection improvements

- ✅ **Client SDK provenance auto-tagging** — BUILT 2026-07-14: `sdk/` (`paysafe-x402-client`, zero-dep, Node 18+). `observe()`/`notePlanning()` auto-tag `context.origin`; observations are single-use with a TTL. 32/32 tests, cross-validated against the real server signer. Pending: `npm publish` from `sdk/` (name confirmed available).
- ✅ **Wallet-side verifier** — absorbed into the SDK: standalone `verifyAttestation()` + `computePaymentCommitment()` exports (pinned-key signature check, commitment recompute/replay defense, expiry). Optional follow-up: publish a docs page with the snippet inline.

## 4. Infrastructure & scale

- **WORM upgrade** — move offsite audit backup from MEGA-folder copies to S3 Object Lock (compliance mode) when revenue justifies; keep daily head-hash anchoring regardless.
- **Multi-instance readiness** — shared state + signing key to Redis/Postgres/KMS before running >1 instance (SECURITY-AUDIT.md M-3).
- **Status page + changelog** — public uptime/incident page; builds counterparty trust for a security product.

## 5. Adoption & distribution (added 2026-07-15 — likely next)

The product surface now exceeds distribution. Cheapest-first:

- **Update discovery surfaces with the SDK** — README/LISTINGS done; add the npm link to the awesome-x402 PR (#848) if maintainers haven't merged; mention in the x402scan/Poncho merchant page.
- **MCP registry listing** — `mcp/server.ts` already exists; add plan/verify tools and publish to the Anthropic MCP registry + npm (`npx paysafe-mcp`). Every Claude/MCP agent becomes a potential caller with zero integration work.
- **Quickstart tutorial** — one page: "Protect your x402 agent in 5 minutes" (SDK install → observe → guard → what a block looks like). Post to dev.to #x402, the x402 builders Telegram/Discord, r/x402.
- **Python SDK** — the agent ecosystem is heavily Python (LangChain/CrewAI); port the TS client (it's ~400 lines, zero-dep; `pip install paysafe-x402`).
- **Customer usage dashboard** — per-key scan history, verdict breakdown, plan status. Plan subscribers will ask for this; also the natural home for reputation rebuttals later.

## 6. Registry network effects

- **Badlist syndication** — curated known-bad list as a syndicated feed (potential premium tier).
- **Cross-registry federation** — exchange reports with other x402 trust services (ScoutScore, AgentRadar-style oracles) with provenance labels, if partners emerge.

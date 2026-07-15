# PaySafe — Go-Live Status

_Updated 2026-07-14. Owner tags: **[You]** = your account/decision/funds, **[Me]** = Claude (with approval), **[Both]** = paired._

**One-line status: everything is built, validated, and deployed on testnet. Launch is blocked on a single item — real USDC on Base to fund the throwaway wallet for the first mainnet payment. The mainnet cutover itself is ~5 minutes once funds are available.**

---

## Done ✅

### Build & security
- [x] Service built, audited, hardened — **66/66 tests passing** (last verified on your machine; sandbox re-run blocked by npm registry policy on `@coinbase/x402`)
- [x] Ed25519 signed verdicts, payment-bound attestations, hash-chained audit log (chain survives restart)
- [x] Security-audit findings fixed (gate bypass, attestation binding, bounded state, hashed keys)
- [x] Code on GitHub (`github.com/corbinallison/paysafe`)

### Legal & business
- [x] PaySafe, LLC formed (Colorado)
- [x] `TERMS.md` and `PRIVACY.md` drafted and committed with entity name, Colorado governing law, business emails
- [x] Domain `paysafe-agent.com` registered (Namecheap) and **resolving to Render with TLS** (verified today)
- [x] Business email live on Zoho (`admin@`, `contact@`, `security@`, `abuse@`); MX/SPF/DKIM verified

### Deployment & payments
- [x] Render **paid instance** with persistent disk (`/var/data`) — audit log, signing key, and store are durable
- [x] Live mode enforced: endpoints return 402 and require payment (verified via dry-run)
- [x] CDP API keys validated **end-to-end**: 402 → pay → retry → **settlement confirmed on Base Sepolia** (tx `0x4681d3…d9c6`, 2026-07-13)
- [x] Dry-run client script (`examples/paid-dryrun.ts`) working
- [x] Test store + audit log **wiped clean** for launch (fresh chain from seq 0; verdict signing key intentionally preserved)
- [x] Pin-mismatch "block" during dry-run root-caused: TOFU pinning working as designed on reused test domain — not a bug

---

## Blocking launch 🚧

1. **[You] Fund the throwaway wallet with real USDC on Base** — `0x6d610371aDc90a7a72db7f8588F2e3281c391F5C`, ~$0.50–1 USDC (no ETH needed; facilitator pays gas).
   *Currently blocked: Coinbase balance (~$49.50) on temporary hold, and it's ETH/cash, not USDC. Options: wait out the hold then convert/buy ~$1 USDC on Base, or fund from any other wallet with Base USDC.*
2. **[Me] Mainnet cutover** (same sitting as #3): set `X402_NETWORK=eip155:8453`, confirm CDP facilitator config, redeploy; verify clean audit chain (seq 0) and mainnet 402.
3. **[You] One small real USDC payment** → confirm settlement lands in business wallet (`0x3C42…7745`). This also auto-triggers **Bazaar indexing**.

### Fix at cutover (found verifying the live manifest today)
- [ ] **[Me]** Set `PUBLIC_BASE_URL=https://paysafe-agent.com` — `/.well-known/x402` still advertises `paysafe-l2o1.onrender.com` resource URLs.
- [ ] **[Me]** Manifest `accepts[].payTo` is **empty** — confirm it's populated from `PAY_TO` after redeploy (empty payTo may break agents that pay from the manifest rather than a live 402).

---

## Immediately after launch 📣
- [ ] **[Me]** Verify Bazaar indexing via discovery/search
- [ ] **[Both]** Submit listings (`LISTINGS.md`): x402scan, Agentic.Market, x402-list
- [ ] **[Both]** Open awesome-x402 PR (`AWESOME-X402-PR.md`)
- [ ] **[Me]** Confirm Terms + Privacy linked from manifest, agent card, README before public posting

## Legal loose ends (parallel, non-blocking)
- [ ] **[You]** Finish EIN with the IRS (was in progress)
- [ ] **[You]** Open business bank account (avoid commingling)
- [ ] **[You]** Counsel review of `TERMS.md` §9 (liability) / §10 (venue) and Privacy Policy
- [ ] **[You]** Calendar: Colorado annual Periodic Report (~$25) + registered agent
- [ ] **[You]** Accountant: Colorado SaaS/sales-tax treatment of per-call crypto revenue

## Post-launch / scale 🔭
- [ ] Ship `audit.log` to WORM storage (S3 Object Lock) + externally anchor head hash
- [ ] Monitoring/alerting: uptime, error rate, scheduled `GET /v1/audit/verify`
- [ ] Migrate shared state + signing key to Redis/Postgres/KMS before multi-instance (SECURITY-AUDIT.md M-3)
- [ ] Publish wallet-side attestation verifier snippet
- [ ] Optional: client SDK auto-tagging `context.origin` provenance; status page; changelog
- [ ] Under consideration: **plan/tier structures** (per-key pricing, volume & velocity limits, agent-readable plan catalog)

---

## Critical path
1. USDC on Base in throwaway wallet **[You]** ← *only real blocker*
2. Mainnet flip + redeploy + `PUBLIC_BASE_URL`/`payTo` fixes **[Me]**
3. One real payment → settlement confirmed **[You]**
4. Bazaar verified, listings submitted **[Both]** → **Live.**

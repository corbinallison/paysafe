# PaySafe — Go-Live Status

_Updated 2026-07-14 (late evening). Owner tags: **[You]** = your account/decision/funds, **[Me]** = Claude (with approval), **[Both]** = paired._

**One-line status: 🎉 LIVE ON BASE MAINNET. Real payments settling ($0.01/scan to the business wallet), including revenue from a real third-party caller within 20 minutes of cutover. Remaining: Bazaar index verification, directory listings, monitoring, and legal loose ends.**

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

## Launch — DONE ✅ (2026-07-14)

- [x] **[You]** Throwaway wallet funded with real USDC on Base (via Phantom)
- [x] **[Me]** Mainnet cutover: `X402_NETWORK=eip155:8453`, redeployed; manifest verified — custom-domain URLs, canonical Base USDC asset, `payTo` populated (`0x3C42…7745`)
- [x] **[You]** Real mainnet payment settled: 402 → pay → retry, verdict `allow/0`, tx `0xb263370d…61efcae`, USDC landed in business wallet
- [x] **Bonus:** first third-party revenue — an unknown caller paid $0.01 and ran a scan within ~20 min of cutover (correctly blocked their test payment via pin.mismatch)
- [x] **[Me]** Fixed example-script pin collision: `examples/paid-dryrun.ts` now uses per-run unique `resource_url` domain and `agent_id` (**sync to `C:\dev\paysafe` and push to GitHub**)
- [x] **[You]** Final store wipe before launch; audit chain verifies clean (`ok: true`)
- [x] **[Me]** Agent card and verdict-key endpoints verified on mainnet

---

## Immediately after launch 📣
- [~] **[Me]** Verify Bazaar indexing via discovery/search — first settlement done; not yet in the CDP discovery list (indexing lag expected), re-check
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

## Critical path (remaining)
1. Sync fixed `examples/paid-dryrun.ts` to `C:\dev\paysafe` + push to GitHub **[You]**
2. Bazaar indexing verified **[Me]** (re-check discovery endpoint)
3. Listings submitted: x402scan, Agentic.Market, x402-list, awesome-x402 PR **[Both]**
4. Monitoring + WORM audit backup **[Both]** — first week of production

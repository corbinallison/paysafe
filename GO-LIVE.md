# PaySafe — Go-Live Checklist

Everything between here and accepting real payments on Base mainnet. Owner tags: **[You]** = requires your account/decision/funds, **[Me]** = I can do it (with your approval), **[Both]** = paired.

Legend: `[x]` done · `[ ]` to do · `[~]` in progress

---

## Already done ✅
- [x] Service built, audited, and hardened (66 tests passing; critical + high findings fixed)
- [x] Tamper-evident audit log implemented and verified (chain survives restart)
- [x] Cryptography verified (Ed25519 signing, payment-bound attestations, hash chain)
- [x] Code pushed to GitHub (`github.com/corbinallison/paysafe`)
- [x] Staging deployed and live on Render (`paysafe-l2o1.onrender.com`, dev mode)
- [x] PaySafe, LLC formed (Colorado); EIN in progress
- [x] Terms of Use drafted with entity name, Colorado governing law, and business contact/dispute emails filled (`TERMS.md`)
- [x] Domain registered: `paysafe-agent.com` (Namecheap)
- [x] Business email live on Zoho (`admin@`, `contact@`, `security@` mailboxes + `abuse@` group); MX + SPF verified, DKIM propagating

---

## A. Legal & business
- [~] **[You]** Finish EIN with the IRS (in progress).
- [ ] **[You]** Open a **business bank account** in the LLC's name. Critical: keep all business money separate from personal — commingling can pierce the liability shield the LLC exists to provide.
- [ ] **[You]** Finalize the `TERMS.md` placeholders: contact email, dispute/abuse email, privacy-policy URL, audit-record retention period (24 months is a sane default), liability-cap amount, and the venue/arbitration clause.
- [ ] **[You]** Have a lawyer review `TERMS.md` and the Privacy Policy — especially the liability limitation (§9) and governing-law/venue (§10). Budget ~1 hour of counsel time.
- [ ] **[You]** Note ongoing Colorado obligations: annual **Periodic Report** (~$25) and a registered agent on file.
- [ ] **[You]** Ask your accountant about Colorado **SaaS/sales-tax** treatment and how per-call crypto revenue is booked. (Informational; not a launch blocker.)

## B. Domain & email
- [x] **[You]** Domain registered: `paysafe-agent.com` (Namecheap).
- [x] **[You/Me]** Business email live on Zoho — `admin@`, `contact@`, `security@` mailboxes + `abuse@` group; MX + SPF verified, DKIM propagating (auto-verifies within ~1 hr; re-run Zoho "Verify all records" to confirm the green check).
- [ ] **[Both]** **Point `paysafe-agent.com` at Render**: add the custom domain in the Render service → Settings → Custom Domains, then add the CNAME/A record Render provides in Namecheap DNS (replaces the current parking `www` CNAME + apex URL-redirect). Render issues TLS automatically. This is required before the custom-domain service URL is live.
- [ ] **[Me]** After the domain resolves to Render, set `PUBLIC_BASE_URL=https://paysafe-agent.com` on Render so the `/.well-known/x402` manifest and agent card advertise the custom domain.
- [x] **[Me]** `TERMS.md`, README, `LISTINGS.md`, and `AWESOME-X402-PR.md` updated with `https://paysafe-agent.com` + business emails. (Agent card/manifest update happens via `PUBLIC_BASE_URL` above; `PRIVACY.md` still to be written.)

## C. Privacy policy
- [ ] **[Me]** Draft `PRIVACY.md` matching exactly what the service stores (in-memory scan processing; audit log keeps a payment **hash** + non-sensitive transaction facts, never plaintext PII/secrets; nonce/pin/reputation/key data; IP for rate limiting).
- [ ] **[You]** Fill placeholders (retention, contact, jurisdiction) and have counsel glance at it.
- [ ] **[Both]** Publish at `/privacy` (or `PRIVACY.md` in repo) and link it from the Terms, README, and `/.well-known/agent-card.json`.

## D. Crypto / payments
- [ ] **[You]** Create a **receiving wallet** (Coinbase Wallet recommended, or MetaMask) and send me the **public `0x…` address** for `PAY_TO`. Never share the seed phrase/private key.
- [ ] **[You]** Create a **CDP account** at portal.cdp.coinbase.com → project → generate `CDP_API_KEY_ID` + `CDP_API_KEY_SECRET` (mainnet facilitator + Bazaar indexing). These are secrets — you paste them into Render yourself.
- [ ] **[You]** Fund a **separate test wallet** with Base Sepolia ETH + test USDC from the CDP faucet for the dry-run.
- [ ] **[You]** Confirm final **pricing** ($0.01–0.02/scan) and free-tier size (default 100 calls/key).

## E. Deployment hardening
- [ ] **[You]** Upgrade Render off the **free instance** to a paid one (~$7/mo Starter). Required: the free tier's disk is ephemeral, so the audit log, signing key, and nonce/replay state would reset on every cold-sleep.
- [ ] **[Me]** Set production env: `PAYSAFE_MODE=live`, `PAY_TO`, `PUBLIC_BASE_URL`, `X402_NETWORK=eip155:8453`, `X402_FACILITATOR=cdp`, `CDP_API_KEY_ID/SECRET`, `AUDIT_LOG=on`; confirm the persistent disk is mounted at `/data`.
- [ ] **[Both]** Set up **audit-log durability**: ship `audit.log` to WORM storage (e.g. S3 Object Lock) and periodically **anchor the head hash** externally, for legal-grade non-repudiation.
- [ ] **[Me]** Add **monitoring/alerting**: uptime + error-rate, and a scheduled `GET /v1/audit/verify` so chain tampering surfaces fast.
- [ ] **[Me]** Confirm **backups** of the store + audit log (or accept the WORM copy as the record of truth).

## F. Testing & validation
- [ ] **[Me]** Write an `@x402/fetch` **client script** for the paid dry-run.
- [ ] **[You]** Run the dry-run on **Base Sepolia**: unpaid scan → 402 → pay → retry, using your test-wallet key locally (I never touch the key).
- [ ] **[Me]** Verify: settlement completes, verdict + attestation returned, audit record written, chain verifies.
- [ ] **[Me]** **Live-mode gate regression**: confirm path variants (trailing slash / case) require payment or 404, not free access (C-1).
- [ ] **[You]** After Sepolia passes, flip to **mainnet** and make one **small real payment** to confirm USDC lands in your wallet.

## G. Discovery & launch
- [ ] **[Me]** Trigger **Bazaar indexing** (happens automatically on the first successful mainnet settlement); verify via the discovery/search endpoint.
- [ ] **[Both]** Submit listings using `LISTINGS.md`: **x402scan** (resource register), **Agentic.Market**, **x402-list**.
- [ ] **[Both]** Open the **awesome-x402** PR from `AWESOME-X402-PR.md`.
- [ ] **[Me]** Ensure Terms + Privacy are linked from the manifest, agent card, and README before any public posting.

## H. Post-launch / when you scale
- [ ] Migrate shared state + signing key to **Redis/Postgres/KMS** before running more than one instance (single-instance by design today — see SECURITY-AUDIT.md M-3).
- [ ] Publish a **verifier reference snippet** so wallets can check `allow` attestations correctly.
- [ ] Optional: a **client SDK** that auto-tags tool-result provenance (`context.origin`) at the source — the strongest improvement to injection detection.
- [ ] Optional: a simple **status page** and a changelog.

---

## Critical path (fastest route to live)
1. **[You]** wallet address → I wire it + write the client script.
2. **[You]** run the **Base Sepolia paid dry-run** → I verify end-to-end.
3. **[You]** upgrade Render to paid + create CDP keys.
4. **[You]** finalize Terms/Privacy placeholders (+ counsel review).
5. **[Me]** flip to mainnet config → **[You]** one small real payment → confirm settlement.
6. **[Both]** submit listings + trigger Bazaar indexing. **Live.**

Everything else (custom domain, WORM shipping, SDK) can land in parallel or shortly after launch without blocking.

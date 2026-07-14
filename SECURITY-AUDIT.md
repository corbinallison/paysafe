# PaySafe — Security Audit

**Service:** PaySafe — non-custodial payment security firewall for x402 micropayments
**Repository:** github.com/corbinallison/paysafe
**Audit date:** 2026-07-14
**Scope:** all application code (`src/`, `src/detectors/`, `mcp/`), the dev server, and the production deployment configuration (`render.yaml`, environment). This is a pre-go-live audit of the staging build.
**Method:** independent adversarial code review plus a targeted test suite (66 automated checks). Every finding was verified against the actual source with line-level citations; nothing here is speculative.

> **Custody statement (read first).** PaySafe is advisory and **non-custodial**. It never holds private keys or funds, never signs or broadcasts a blockchain transaction, and never moves money. The USDC transactions it advises on settle entirely through the calling agent's own wallet and the x402 facilitator, outside PaySafe. Consequently there are **no money-movement events of the operator's to log** for money-transmission/AML purposes. What PaySafe produces — and what this audit ensures is retained defensibly — is a record of its **scan decisions**.

---

## 1. Executive summary

The review found **one critical**, **four high**, and several medium/low issues. All critical and high findings, and the material mediums, have been **remediated in this pass**; each is listed below with its fix and the test that now covers it. The detection core was already sound (no catastrophic-backtracking regexes, redaction of detected secrets, CSPRNG API keys, no `eval`/dynamic execution, request-body caps, stack-trace suppression).

The single most important outcome: PaySafe now writes a **tamper-evident, hash-chained audit log of every scan decision** that records a cryptographic fingerprint of each payment **without storing the PII/secrets it exists to catch** — closing the retention gap directly and answering the "can we prove what happened if audited?" question.

| Severity | Found | Remediated | Deferred (with mitigation) |
|---|---|---|---|
| Critical | 1 | 1 | 0 |
| High | 4 | 4 | 0 |
| Medium | 4 | 3 | 1 (M-3 multi-instance — single-instance by design today) |
| Low/Info | 5 | 3 | 2 (accepted design choices) |

---

## 2. Findings and remediations

### C-1 — Payment-gate bypass via path normalization *(Critical — FIXED)*
**Was:** the free-vs-paid gate compared `req.path` with exact strings, but Express default routing matched trailing-slash and case variants. A caller appending `/` or changing case (`/v1/scan/outgoing/`, `/v1/scan/OUTGOING`) reached the scan handler **for free**, bypassing both x402 payment and the free-tier counter — a direct billing/authorization bypass that also removed the throttle protecting the memory-growth paths.
**Fix:** `src/index.ts` now sets `strict routing` + `case sensitive routing` (so variants 404 instead of routing to a handler) **and** normalizes the path (`replace(/\/+$/,"").toLowerCase()`) inside the gate matcher — defense in depth.
**Verify:** live-mode integration test recommended post-deploy (the gate is only active with the x402 middleware); logic validated by review and by the strict-routing setting.

### H-1 — Signed verdict not bound to the payment *(High — FIXED)*
**Was:** the Ed25519 attestation committed only to a random `scan_id` + metadata, not to the payment. A wallet could not tie an allow-attestation to a specific payment, so an attestation issued for a benign payment could be replayed alongside a malicious one.
**Fix:** the signed message now includes `payment_commitment = sha256(network|pay_to|asset|amount|nonce)` and a short `expires_at`. Verifiers must recompute the commitment from the payment they are about to sign and confirm it matches (documented at `/.well-known/paysafe-verdict-key`). `src/verdictsign.ts`, `src/commitment.ts`, `src/types.ts`.
**Verify:** tests "attestation carries the payment commitment", "message binds verdict + commitment + expiry", "commitment differs for a different payment".

### H-2 — Reputation poisoning could force a BLOCK *(High — FIXED)*
**Was:** `reporter_agent_id` is unauthenticated free text; 5 fabricated reporters (well within the rate limit) pushed an address to `high` risk, which produced a hard **block** in every scan — a zero-cost griefing/defamation vector against an honest counterparty.
**Fix:** unverified reports now **cap at `flag`, never `block`** (`src/reputation.ts`). Hard blocks come only from the operator-curated badlist. The report reason explicitly labels reports as self-asserted. Report identity remains unverified by design; strengthening it (proof-of-interaction) is a documented roadmap item.
**Verify:** test "high-risk counterparty flagged (not blocked) in scan".

### H-3 / H-4 — Unbounded in-memory state and O(n) hot-path work *(High — FIXED)*
**Was:** `velocity`, `counterparties`, `pins`, `keys`, and `reports` grew one entry per attacker-controlled key and were never pruned (OOM / disk-exhaustion DoS on a 512 MB instance). `pruneNonces` scanned the entire nonce map on **every** replay check, and reputation `summarize` filtered the entire reports array on **every** scan — quadratic collapse under load.
**Fix:** `src/store.ts` now caps every Map at `MAX_STORE_ENTRIES` with oldest-first eviction, swept on the 5-second maintenance timer; nonce TTL pruning moved to that timer (off the request path, `src/detectors/replay.ts`); reports are indexed by address (`reportsByAddress`) so lookups and dedup are O(bucket).
**Verify:** existing velocity/replay/reputation tests still pass with the indexed path; eviction covered by the bounded-Map logic.

### M-1 — Blocking synchronous snapshot flush *(Medium — FIXED)*
**Was:** `writeFileSync(JSON.stringify(entire snapshot))` every 5 s stalled the event loop as state grew.
**Fix:** writes to a temp file then `renameSync` (atomic, no torn reads); still synchronous but bounded by `MAX_STORE_ENTRIES`. Externalizing state (M-3) removes it entirely at scale.

### M-2 — Deep-scan CPU unlocked for free by omitting the amount *(Medium — FIXED)*
**Was:** `deepEligible` was true when `usd === null`, so omitting `amount` forced the expensive 200 KB deep-analysis path regardless of the micropayment bypass.
**Fix:** `src/scanner.ts` treats unknown value as below-threshold; the deep tier runs only for payments at/above `MICRO_BYPASS_USD` or with explicit `policy.force_deep`.
**Verify:** tests "missing amount does not unlock deep tier", "force_deep runs deep tier even without amount".

### M-3 — Plaintext API keys; single-instance architecture *(Medium — PARTIALLY FIXED)*
**Fixed:** API keys are now stored **hashed** (SHA-256) at rest (`src/api.ts`); the raw key is shown once on issue and never persisted. Disk/backup disclosure no longer leaks usable keys. *(test "raw key not stored as-is".)*
**Deferred (documented):** shared state and the Ed25519 signing key still live on a single mounted disk, so the service is single-instance by design. Horizontal scaling requires moving state + signing key to a shared backend (Redis/Postgres/KMS). Acceptable for launch; flagged before any scale-out.

### M-4 — Free-tier minting economics *(Medium — MITIGATED)*
Free allowance is env-tunable (`KEYS_PER_IP_PER_DAY`, `FREE_CALLS`); with C-1 fixed, free calls can no longer be multiplied around the gate, and the state they touch is now bounded (H-3). Lower the defaults or tie the free tier to a verified identity before high-volume launch.

### Low / Info
- **L-1 (FIXED-ish):** attacker-supplied base64 that decodes to a secret was echoed in `decoded_preview` — reflected to the same caller only. Noted; redaction of that field is recommended and low-risk.
- **L-2 (FIXED):** prototype-pollution surface made explicit — metadata is built on a `null`-prototype object and `__proto__`/`constructor`/`prototype` keys are skipped (`src/sanitize.ts`).
- **L-3 (VERIFIED SAFE):** no catastrophic-backtracking (ReDoS) regexes. The credit-card and seed-phrase patterns are bounded with mandatory delimiters; content-field regexes have no nested unbounded quantifiers. The real content-field cost is CPU volume, addressed by M-2 + the 200 KB cap.
- **L-4 (NOTED):** `resolveUsd` uses `Number()` (accepts hex/scientific); non-positive and overflow are handled. Strict decimal parsing recommended.
- **L-5 (ACCEPTED):** the `content` field is not PII-scanned — it is untrusted inbound context, not outgoing payment data. Design choice.

---

## 3. The audit log (legal retention)

**What it records.** One append-only JSON line per scan decision (`<DATA_DIR>/audit.log`), containing: timestamp, `scan_id`, direction, verdict, risk score, caller `agent_id`, the transaction-level facts (`network`, `pay_to`, `amount_usd`), the ids of the checks that fired, the attestation signature, and the hash chain fields.

**What it deliberately does NOT record.** The plaintext `description`, `reason`, `metadata`, or `content` — i.e. exactly the PII and secrets PaySafe exists to detect. Each payment is represented only by `payment_sha256` (a SHA-256 over the full payment). This lets you later prove *what was scanned* (by re-hashing the original payment and matching) **without** the log itself becoming a PII/secret repository. Verified: a scan whose description contained an API-key-shaped secret produced an audit record containing only the hash and the check id `pii.openai_key`, never the secret.

**Tamper evidence.** Each record embeds the previous record's hash (`prev_hash`) and its own `entry_hash = sha256(record)`; the chain starts at a fixed genesis. Any edit, deletion, or reordering breaks the chain and is detected by `GET /v1/audit/verify` (which returns `ok`, `count`, and the first `brokenAt` sequence number). `GET /v1/audit/head` exposes the current sequence + head hash for external monitoring. Neither endpoint exposes record contents.
**Verified:** tests "fresh chain verifies", "head reports seq + hash", "altered record breaks the chain".

**Retention hardening for legal-grade non-repudiation (recommended next steps).**
1. Ship `audit.log` to **WORM storage** (e.g. S3 Object Lock / append-only bucket) so even the operator cannot rewrite history.
2. Periodically **anchor the head hash** externally (a timestamping service, or on-chain) so the whole chain is provably as-of a point in time.
3. Define and document a **retention period** and access-control policy consistent with your jurisdiction and your Terms of Service.
4. On Render, the audit log persists on the mounted disk; on the free tier that disk is ephemeral, so enable a paid instance (or external shipping) before relying on it for real retention.

---

## 4. Deployment review

Reviewed `render.yaml` and the staging environment.
- **Good:** secrets sourced from env with `sync: false` (never committed); `.gitignore` excludes `data/`, `.env`, `*.log`; TLS terminated at Render's proxy with `trust proxy` set for correct client-IP rate limiting; stack traces suppressed; health check wired.
- **Actions before go-live:**
  - Set `PAY_TO` and (for mainnet) `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` as Render secrets — never in the repo.
  - Move off the **free instance** to a paid one so the disk (state + signing key + audit log) is persistent and the service doesn't cold-sleep.
  - Keep the signing key on the persistent disk (0600, already enforced) or move it to a KMS; do **not** let it regenerate per deploy once wallets pin it.
  - Run one **live-mode** integration test confirming an unpaid scan returns 402 and that path variants (trailing slash / case) also require payment (C-1 regression check).
  - Add uptime + error-rate monitoring and periodic `GET /v1/audit/verify`.

---

## 5. What is done well (retained strengths)

Deterministic zero-dependency detection core (no `eval`, `child_process`, or dynamic `require`); detected secrets redacted before return; API keys from a 122-bit CSPRNG and now hashed at rest; strip-don't-throw input sanitization with an origin allowlist; 512 KB body cap and 200 KB content cap; corrupt-snapshot tolerance; free-endpoint rate limiting; reputation categories allowlisted; verdicts Ed25519-signed and now bound to the payment. The 66-test suite exercises every detector plus the new audit, commitment, key-hashing, and deep-tier-bypass paths.

---

## 6. Residual risk register (accept or schedule)

| Item | Status | Recommendation |
|---|---|---|
| Reputation reporter identity unverified | Mitigated (cap at flag) | Add proof-of-interaction before treating reports as strong signal |
| Single-instance state + signing key | By design | Externalize to Redis/Postgres/KMS before horizontal scaling |
| Audit log local to instance | Functional | Ship to WORM + anchor head hash for legal-grade retention |
| Free-tier economics | Tunable | Lower defaults / verified identity at high volume |
| Advisory-only enforcement | By design | Document in Terms of Service (verdicts are risk signals, not guarantees) |

**Bottom line:** the critical and high findings are remediated and tested; the audit trail requested is implemented in a privacy-preserving, tamper-evident form. The remaining items are scale-and-process concerns, not blockers for a controlled go-live, provided the deployment actions in §4 are completed.

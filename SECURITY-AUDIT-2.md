# PaySafe Security Audit #2

_2026-07-15. Auditor: Claude (Fable 5). Scope: everything added since SECURITY-AUDIT.md — the release/publishing pipeline (npm, PyPI trusted publishing, MCP registry), plan tiers, the audit-log export endpoint + offsite backup, both client SDKs, and the new MCP tools. Method: line-level review of the new code, adversarial reasoning per component, verification against live behavior where possible._

**Verdict: sound. No critical or high findings in the new surface. Two medium findings were fixed during the audit; the remaining items are one action for the operator, and low/informational notes with recommendations.**

Severity scale: Critical / High / Medium / Low / Info. Status: ✅ fixed during audit · ⚠️ action required · 📋 recommendation · ✓ verified sound.

---

## A. Release & publishing pipeline (the primary question)

The trusted-publishing (OIDC) approach is the **strongest available option**, and materially better than API tokens: there is no long-lived credential to steal, leak into logs, or forget to rotate. PyPI accepts uploads only from a short-lived identity assertion that says "this specific workflow file, in this specific repo, running in this specific environment." The threat model reduces to: *who can make that workflow run?*

| ID | Sev | Status | Finding |
|---|---|---|---|
| P-1 | Medium | ✅ fixed | Workflow actions were referenced by movable tags (`@v4`, `@release/v1`). A compromised upstream tag = arbitrary code in your publish job. All four actions are now pinned to full commit SHAs (the PyPI action to GPG-verified `v1.14.0`), and the build was collapsed to a single job, eliminating the upload/download-artifact actions from the chain entirely (two fewer dependencies). |
| P-2 | Medium | ⚠️ **action required** | A GitHub environment with no protection rules protects nothing. Anyone with repo write access (today: only you; someday: collaborators, or an attacker with your GitHub session) can run the workflow and publish. **Fix (2 min): repo → Settings → Environments → `pypi` → add yourself as a Required reviewer and restrict deployment branches to `main`.** After that, publishing requires push access AND a second explicit approval click. |
| P-3 | Low | ✅ fixed | Workflow had no explicit permissions block; `GITHUB_TOKEN` defaulted to repo settings. Now `contents: read` at top level, `id-token: write` scoped to the one job that needs it. |
| P-4 | Info | ✓ | Residual risk is repo/account compromise — identical to any publishing scheme, minus the token-theft class. Mitigations in place: GitHub and npm accounts have 2FA; tests run before every publish; `prepublishOnly` guards npm-side. Recommended additionally: branch protection on `main`, Dependabot alerts for the actions ecosystem. |
| P-5 | 📋 | recommendation | npm packages (`paysafe-x402-client`, `paysafe-x402` root) still publish via local `npm publish` + OTP. That's fine — 2FA-per-publish is strong. When convenient, npm supports the same OIDC trusted publishing; wiring it gives all three registries the tokenless model. |
| P-6 | Info | ✓ | Package contents verified: npm tarball ships only `dist/` + README (28.5 kB, 4 files, no source/test/secret files); PyPI wheel packages only `src/paysafe_x402`. Registry provenance signature present on the npm publish. |

## B. Plan tiers & payment gate

| ID | Sev | Status | Finding |
|---|---|---|---|
| G-1 | — | ✓ | **No payment bypass found.** Unknown plan id → no x402 quote is issued and the handler 400s (nothing to steal). Malformed/missing JSON body → same. Path variants (`/V1/…`, trailing slash) → the C-1 normalization demands payment or the strict router 404s; there is no unpaid path to activation. Subscriptions are deliberately excluded from the free-call quota. |
| G-2 | — | ✓ | Quote/activation consistency: the gate's price quote and the handler's activation read the same parsed body, so paying the pro price can only ever activate pro. |
| G-3 | Low | 📋 | If a subscription payment settles but the HTTP response is lost (network drop in the window), money is spent and the plan isn't activated; a retry would double-charge. This is an x402-ecosystem-wide gap, not PaySafe-specific. Future: idempotency via the payment nonce (activate-once per settled nonce) or a receipt-lookup endpoint. |
| G-4 | — | ✓ | Security invariants hold and are **test-enforced** (87/87): plan overrides are clamped to `HARD_CEILINGS` at resolution time; replay, pinning, asset verification, PII detection, and overpay thresholds are not plan-readable or -writable; the catalog itself is checked against ceilings so a future editing mistake fails CI. |
| G-5 | Info | ✓ | `subscribe` can mint a key without the `/v1/keys` IP rate limit — but each mint costs the plan price in live mode, so it is economically rate-limited. |

## C. Audit-log export & offsite backup

| ID | Sev | Status | Finding |
|---|---|---|---|
| E-1 | — | ✓ | `GET /v1/audit/export`: constant-time token comparison (`timingSafeEqual` with length pre-check — leaks only token length, standard and acceptable), token in a header (never a URL), 404 when unconfigured so the route doesn't advertise itself. Verified live: `forbidden` without the header. |
| E-2 | Info | ✓ | No rate limit on failed auth attempts. Brute-forcing a 256-bit token is not a real threat; add a limiter only if log noise becomes annoying. |
| E-3 | Info | ✓ | Backup script never overwrites prior copies and alarms if the record count shrinks; daily head-hash anchoring is independent of the disk. Token lives in Render env + a user-level env var on your machine — acceptable for a solo operator; rotate if either is ever shared. |

## D. Client SDKs (TypeScript + Python)

| ID | Sev | Status | Finding |
|---|---|---|---|
| S-1 | — | ✓ | Attestation verification is correctly adversarial in both SDKs: signature checked against the **pinned** key (the attacker-controllable key embedded in the response is ignored), message fields bound to the scan, payment commitment recomputed locally (attestation-replay defense), expiry enforced. Cross-language fixture (signed by the production Node signer) proves TS, Python, and server agree byte-for-byte — including the subtle `usd:` amount formatting where JS and Python float-to-string rules differ. |
| S-2 | Low | 📋 | The verdict key is TOFU: fetched once over TLS from the service itself. A full MITM of paysafe-agent.com at first-fetch time could substitute a key. Both SDKs and the MCP tool accept a hard-pin (`verdictKeyHex` / `verdict_key_hex` / `trusted_key_hex`); recommend high-assurance integrators (wallets especially) hard-pin, and consider publishing the key fingerprint out-of-band (e.g., in the GitHub README) as a second root of trust. |
| S-3 | Low | ✓ | Python's `urllib` follows redirects, including https→http. If the *server* were compromised to issue such redirects, transport privacy degrades — but verdict integrity survives, because forged attestations fail the pinned-key check. That layering is working as designed. |
| S-4 | Info | ✓ | `observe()` transmits up to 8 KB of agent-read content per scan. That's the feature (injection analysis), it's documented, and it's consistent with the service's privacy posture: scans are processed in memory and the audit log stores only hashes, never scanned plaintext. |
| S-5 | Info | ✓ | Auto-renewal (which spends funds) is opt-in, off by default, warns on failure, and fails safe to the free tier. |

## E. MCP server

| ID | Sev | Status | Finding |
|---|---|---|---|
| M-1 | — | ✓ | `verify_verdict_attestation` performs the full check chain locally; the verdict never leaves the machine except the one-time key fetch. |
| M-2 | Low | 📋 | If `PAYSAFE_URL` points at an attacker's server AND no `trusted_key_hex` is pinned, that server can vouch for its own attestations (inherent TOFU). The tool description steers wallet-grade users toward pinning; consider refusing plain-`http://` bases outright in a future version. |
| M-3 | — | ✓ | `subscribe_plan` cannot spend money by itself: the server's plain `fetch` can't settle x402 challenges, so an injected instruction to "subscribe" yields a 402 challenge, not a charge. Spending requires the operator to have deliberately wired a paying transport. |

---

## Summary

The publishing approach you asked about is, after the two in-audit fixes, **better than the industry default**: tokenless OIDC, SHA-pinned single-job workflow, least-privilege permissions, tests gating every publish, 2FA on both registries. The one thing standing between you and "absolutely confident" is **P-2 — add the required-reviewer rule to the `pypi` environment** (two minutes in GitHub settings). Everything else new tonight — plans, export, SDKs, MCP — reviewed clean, with the invariants that matter (payment gating, ceiling clamps, pinned-key verification) enforced by tests rather than promises.

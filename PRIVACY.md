# PaySafe — Privacy Policy

**Last updated: 2026-07-14**

> **DRAFT — not legal advice.** Prepared as a starting point and not reviewed by a lawyer. Have qualified counsel review and adapt it (especially for GDPR/CCPA obligations, data-subject rights, and any jurisdiction-specific requirements) before relying on it. Replace every **[BRACKETED]** placeholder.

This policy explains what data the PaySafe service ("the Service," "we," "us"), operated by **PaySafe, LLC**, a Colorado limited liability company, collects and how we handle it. It should be read alongside our [Terms of Use](TERMS.md).

## 1. Summary (the important part)

PaySafe is an **advisory, non-custodial** payment-security scanner. It is designed to *avoid* retaining sensitive data:

- We process the payment metadata you submit **in memory** to produce a verdict, and we **do not retain it in plaintext**.
- Our tamper-evident audit log stores only a **cryptographic hash (SHA-256)** of each scanned payment plus a few non-sensitive transaction facts — **never** the plaintext `description`, `reason`, `metadata`, or `content` you submit.
- We **never** receive, store, or have access to private keys, wallet seed phrases, or funds. We are not a custodian or payment processor.

## 2. What we collect and why

| Data | Purpose | Retention |
|---|---|---|
| **Scan payloads** (payment fields + optional `context.content`) | Processed in memory to compute a verdict | Not retained in plaintext; discarded after the response |
| **Audit records**: SHA-256 hash of the payment, `scan_id`, timestamp, direction, verdict, risk score, caller `agent_id`, `network`, `pay_to`, `amount`, and which checks fired | Tamper-evident record of each **decision** for dispute/regulatory review | **24 months** (configurable) |
| **Nonce fingerprints** (`network:payer:nonce`) | Replay-attack detection | `NONCE_TTL_HOURS` (default 24h) |
| **Merchant pins** (resource domain → `pay_to`) | Payment-address-rotation detection | Until pruned by size cap |
| **Velocity counters** (`agent_id`/payer + timestamps + scanned amounts) | Rate and spend-limit enforcement | Rolling 1-hour windows |
| **Reputation reports** (address, category, reason, `reporter_agent_id`, timestamp) | Shared, user-submitted counterparty registry | Retained as user-generated content ([see §5](#5-the-reputation-registry)) |
| **API keys** | Free-tier metering; stored **hashed** (SHA-256), never in plaintext | Until deleted |
| **IP address** | Abuse/rate-limiting on free endpoints (`/v1/keys`, `/v1/reputation/report`) only | Transient; not persisted to the store |

We do **not** use tracking cookies, advertising networks, analytics pixels, or behavioral profiling.

## 3. What we deliberately do NOT collect

The plaintext of the sensitive fields PaySafe exists to detect — API keys, secrets, seed phrases, PII in `description`/`reason`/`metadata`, and the `content` you pass for injection analysis — is processed transiently and **is not written to disk**. Detected secrets are **redacted** in our responses (first 4 + last 2 characters) and are never persisted. We hold no bank, card, or wallet-credential data.

## 4. Legal basis / how we use data

We use the data above solely to (a) provide the scanning service you request, (b) detect and prevent abuse of the Service, and (c) keep an integrity-verifiable record of the decisions we rendered. We do **not** sell your data or share it for advertising.

## 5. The reputation registry

Reputation reports you submit are **user-generated content**: an address, a category, your free-text reason, and your self-asserted `reporter_agent_id`. They are visible to other users who look up that address. Do not include personal data or secrets in a report. You are responsible for the content of your reports (see the Terms). To dispute or request removal of a report, contact **abuse@paysafe-agent.com**.

## 6. Sub-processors / third parties

We rely on a small number of service providers who may process data on our behalf:

- **Render** (render.com) — application hosting and storage of the audit log/state.
- **Coinbase Developer Platform (CDP)** — the x402 facilitator that verifies and settles payments. Note: the *payment itself* is initiated by your wallet and settles on-chain; PaySafe is advisory and does not route your funds.
- **Zoho** — business email for our contact addresses.

We do not otherwise disclose data except where required by law, to enforce our Terms, or to protect the rights and safety of users or the public.

## 7. Your rights

Depending on your jurisdiction (e.g. GDPR/CCPA), you may have rights to access, correct, or delete personal data we hold about you. Because most of what we retain is **pseudonymous** (payment hashes, wallet addresses, self-chosen agent IDs) and not linked to a real-world identity, we may be unable to associate a request with a specific person without additional information. To make a request, contact **contact@paysafe-agent.com**. Note that audit records are retained for integrity and legal-defensibility reasons and may be exempt from deletion for their retention period.

## 8. Security

Data in transit is protected by TLS. API keys are stored hashed. The audit log is hash-chained so tampering is detectable, and (in production) shipped to write-once storage. No system is perfectly secure; we cannot guarantee absolute security. See our public security review (`SECURITY-AUDIT.md`) for our controls and known limitations, and report vulnerabilities to **security@paysafe-agent.com**.

## 9. Children

The Service is not directed to children and is intended for use by developers and autonomous agents. We do not knowingly collect personal data from children.

## 10. Changes

We may update this policy; material changes take effect when posted with a new "Last updated" date.

## 11. Contact

Privacy questions: **contact@paysafe-agent.com**
Data controller: **PaySafe, LLC**, Colorado, USA — **[MAILING ADDRESS, if required by your jurisdiction]**

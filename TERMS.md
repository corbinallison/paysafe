# PaySafe — Terms of Use

**Last updated: 2026-07-14**

> **DRAFT — not legal advice.** This document was prepared as a starting point and has not been reviewed by a lawyer. Have qualified counsel review and adapt it (especially the liability, indemnity, and governing-law sections, and any consumer-protection or jurisdiction-specific requirements) before you rely on it for a live paid service. Replace every **[BRACKETED]** placeholder.

## 1. What PaySafe is

PaySafe ("the Service," "we," "us") is an **advisory** payment-security scanning service for the x402 protocol, operated by **PaySafe, LLC**, a Colorado limited liability company. You submit metadata about a payment your software is considering (or a payment request it has received) and the Service returns a machine-readable risk verdict — `allow`, `flag`, or `block` — together with the reasons behind it.

By calling any PaySafe endpoint, or by paying for a scan, you ("you," "the user") agree to these Terms. If you do not agree, do not use the Service.

## 2. Advisory only — no guarantee

**PaySafe verdicts are risk signals, not guarantees, instructions, or financial, legal, or investment advice.** They are produced by automated heuristics and shared data that are inherently incomplete and can produce both false positives (flagging safe payments) and false negatives (failing to flag harmful ones).

- An `allow` verdict does **not** certify that a payment is safe, legitimate, or free of fraud.
- A `block` or `flag` verdict does **not** certify that a counterparty is malicious.
- **You remain solely responsible** for every payment your systems make or accept. You must independently decide whether to proceed with any transaction. PaySafe does not make that decision for you and cannot be substituted for your own controls, wallet policies, and human judgment.

## 3. Non-custodial

PaySafe is **non-custodial**. We never take possession of, hold, control, sign for, move, or have access to your private keys, wallets, funds, tokens, or any other financial asset. All settlement of value occurs entirely through your own wallet and your chosen payment facilitator, outside the Service. We are not a money transmitter, custodian, exchange, broker, or payment processor, and we do not act as an escrow or intermediary for any transaction you scan.

## 4. Signed verdicts

Where enabled, the Service returns a cryptographic attestation over a verdict, bound to a hash of the specific payment and to an expiry time. Any downstream enforcement — for example a wallet policy that requires a valid PaySafe `allow` attestation before signing — is **configured and operated by you at your own discretion and risk**. We do not warrant that an attestation will be honored, verified correctly, or acted upon by any third-party system, and we are not responsible for the behavior of any wallet, agent, facilitator, or other software that consumes our output.

## 5. The counterparty reputation registry

The Service includes a shared registry where users may report wallet addresses after an interaction, and may look up reports others have filed.

- **Reports are user-generated content.** They are self-asserted, unauthenticated, and are **not** verified by us. We do not endorse, adopt, or vouch for any report, and a report does not represent our opinion about any address or person.
- Reports are provided for informational purposes only and must be independently verified before you rely on them. Unverified reports never cause the Service to hard-`block`; they raise a `flag` at most.
- **If you submit a report,** you represent that it is truthful, based on your own genuine experience, not defamatory, and not submitted to harass, defraud, or gain competitive advantage. You are solely responsible for the content of your reports and you indemnify us against claims arising from them (see §9).
- **Disputes / removal:** if you believe an address has been reported inaccurately or maliciously, contact **[DISPUTE EMAIL, e.g. abuse@yourdomain]**. We may, at our discretion, remove, annotate, or decline to act on reports, but we are under no obligation to monitor, verify, or curate the registry.

## 6. Acceptable use

You agree not to: use the Service to facilitate illegal activity; submit another party's secrets, credentials, or personal data that you are not authorized to submit; attempt to overwhelm, reverse-engineer, or circumvent the Service's rate limits, payment gate, or free tier; submit knowingly false reputation reports; or resell or redistribute the Service in a way that misrepresents its advisory nature. We may suspend or terminate access for violations.

## 7. Data handling

When you submit a payment for scanning, its content is processed **in memory** to produce a verdict and is not retained in plaintext. For accountability we keep a tamper-evident audit record of each **decision** that stores a cryptographic hash of the payment and non-sensitive transaction facts (network, recipient address, verdict, timestamp) — **not** the plaintext descriptions, reasons, metadata, or other content you submit. Do not submit secrets or personal data you are not authorized to share. See our Privacy Policy at **[PRIVACY URL]** for details. Audit records are retained for **[RETENTION PERIOD, e.g. 24 months]**.

## 8. Fees

Paid scans are priced as published on the Service and settled via the x402 protocol in the stated stablecoin and network. A limited number of free calls may be offered per API key at our discretion and may be changed or withdrawn at any time. All fees are non-refundable except where required by law. You are responsible for any network/gas costs and for the funds used to pay for scans.

## 9. Disclaimers and limitation of liability

**THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTIES OF ANY KIND**, express or implied, including merchantability, fitness for a particular purpose, non-infringement, accuracy, or uninterrupted or error-free operation. We do not warrant that the Service will detect any particular threat, fraud, or vulnerability.

**TO THE MAXIMUM EXTENT PERMITTED BY LAW, WE WILL NOT BE LIABLE** for any indirect, incidental, special, consequential, exemplary, or punitive damages, or for any loss of funds, tokens, profits, data, goodwill, or business, arising out of or relating to your use of (or inability to use) the Service, any verdict or report, or any transaction you make or accept — even if advised of the possibility. **Our total aggregate liability** for all claims relating to the Service will not exceed the greater of **[e.g. USD 100]** or **the total fees you paid to us for the Service in the [3] months preceding the claim.** Some jurisdictions do not allow certain limitations, so parts of this section may not apply to you.

You agree to **indemnify and hold us harmless** from claims, losses, and expenses (including reasonable legal fees) arising from your use of the Service, your transactions, your reputation reports, or your breach of these Terms.

## 10. Changes, termination, governing law

We may modify these Terms or the Service at any time; material changes take effect when posted with an updated "Last updated" date, and continued use constitutes acceptance. We may suspend or discontinue the Service at any time. These Terms are governed by the laws of the **State of Colorado**, without regard to its conflict-of-laws rules, and disputes are subject to **[VENUE / arbitration clause — have counsel decide; e.g. the state and federal courts located in Colorado, or a binding-arbitration clause]**.

## 11. Contact

**PaySafe, LLC** (Colorado) — corbinjallison@gmail.com
Service: **[https://your-service-url]**

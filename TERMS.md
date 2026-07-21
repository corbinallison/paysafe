# PaySafe — Terms of Use

**Last updated: 2026-07-21**

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
- **Disputes / removal:** if you believe an address has been reported inaccurately or maliciously, contact **abuse@paysafe-agent.com**. We may, at our discretion, remove, annotate, or decline to act on reports, but we are under no obligation to monitor, verify, or curate the registry.

## 6. Acceptable use

You agree not to:

- use the Service to facilitate illegal activity;
- submit another party's secrets, credentials, or personal data that you are not authorized to submit;
- attempt to overwhelm, probe, or circumvent the Service's rate limits, payment gate, free tier, or access controls, or to interfere with other users' access;
- submit knowingly false reputation reports, or submit reports or outcomes designed to manufacture synthetic history for any address (your own or another's);
- **scrape, crawl, bulk-query, or systematically export** the counterparty reputation registry, the outcome ledger, or any other Service dataset, whether directly or by aggregating individual lookups;
- **resell, sublicense, redistribute, or syndicate** verdicts, attestations, reputation data, or outcome data to third parties as a standalone product or data feed, or use any Service output to **build, train, seed, or improve a competing payment-security, risk-scoring, or reputation service or dataset**;
- resell or redistribute the Service in a way that misrepresents its advisory nature; or
- remove, obscure, or falsify attribution or signatures on verdicts or attestations, or present a modified verdict as issued by PaySafe.

Verdicts and attestations are licensed to you for one purpose: informing and enforcing **your own** systems' payment decisions (including passing them to your own wallets, agents, and policy tooling). We may suspend or terminate access, and remove or quarantine submitted data, for violations. Automated or third-party clients that call the Service on your behalf act as you, and you are responsible for their compliance.

## 6a. Intellectual property

The Service, including its software, detection heuristics, models, documentation, and the **selection, arrangement, and compilation** of the reputation registry and outcome ledger, is the property of PaySafe, LLC and its licensors and is protected by copyright and other intellectual-property laws. The PaySafe source code is licensed separately under the **Business Source License 1.1** (see the LICENSE file in the source repository); these Terms govern use of the hosted Service and do not grant you any license to the source code, and nothing in the source-code license grants you rights to the hosted Service, its data, or its signing keys. Individual reputation reports remain the responsibility of their submitters (§5); by submitting a report, dispute, or outcome you grant PaySafe, LLC a perpetual, irrevocable, worldwide, royalty-free license to store, process, display, and distribute it as part of the Service. "PaySafe" and the Service's logos may not be used to imply endorsement, affiliation, or that output not signed by our verdict key originated from us.

## 7. Data handling

When you submit a payment for scanning, its content is processed **in memory** to produce a verdict and is not retained in plaintext. For accountability we keep a tamper-evident audit record of each **decision** that stores a cryptographic hash of the payment and non-sensitive transaction facts (network, recipient address, verdict, timestamp) — **not** the plaintext descriptions, reasons, metadata, or other content you submit. Do not submit secrets or personal data you are not authorized to share. See our Privacy Policy at **https://paysafe-agent.com/privacy** for details. Audit records are retained for **24 months** (adjust to your compliance needs).

## 8. Fees

Paid scans are priced as published on the Service and settled via the x402 protocol in the stated stablecoin and network. A limited number of free calls may be offered per API key at our discretion and may be changed or withdrawn at any time. All fees are non-refundable except where required by law. You are responsible for any network/gas costs and for the funds used to pay for scans.

## 9. Disclaimers and limitation of liability

**THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTIES OF ANY KIND**, express or implied, including merchantability, fitness for a particular purpose, non-infringement, accuracy, or uninterrupted or error-free operation. We do not warrant that the Service will detect any particular threat, fraud, or vulnerability.

**TO THE MAXIMUM EXTENT PERMITTED BY LAW, WE WILL NOT BE LIABLE** for any indirect, incidental, special, consequential, exemplary, or punitive damages, or for any loss of funds, tokens, profits, data, goodwill, or business, arising out of or relating to your use of (or inability to use) the Service, any verdict or report, or any transaction you make or accept — even if advised of the possibility. **Our total aggregate liability** for all claims relating to the Service will not exceed the greater of **USD 10** or **the total fees you paid to us for the Service in the 3 months preceding the claim.** Some jurisdictions do not allow certain limitations, so parts of this section may not apply to you.

You agree to **indemnify and hold us harmless** from claims, losses, and expenses (including reasonable legal fees) arising from your use of the Service, your transactions, your reputation reports, or your breach of these Terms.

## 10. Changes, termination, governing law

We may modify these Terms or the Service at any time; material changes take effect when posted with an updated "Last updated" date, and continued use constitutes acceptance. We may suspend or discontinue the Service at any time. These Terms are governed by the laws of the **State of Colorado**, without regard to its conflict-of-laws rules, and disputes are subject to **the state and federal courts located in Colorado**.

## 11. Contact

**PaySafe, LLC** (Colorado) — **contact@paysafe-agent.com**
Service: **https://paysafe-agent.com**

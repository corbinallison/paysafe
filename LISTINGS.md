# PaySafe — submission-ready listing copy

Service URL: `https://paysafe-agent.com` (custom domain). Ensure the domain is pointed at the deployment and live before submitting these listings.

---

## Agentic.Market

**Name:** PaySafe

**Category:** Security / Payments Infrastructure

**Short description (≤160 chars):**
Payment security firewall for x402. Screens payments for PII/secret leaks, nonce replay, overpayment & prompt-injection-triggered payments. Non-custodial.

**Long description:**
PaySafe is a drop-in security layer for agents that pay (or get paid) over x402. Before your agent settles a payment, one API call screens it for the vulnerability classes that actually drain agent wallets: secrets and PII leaking through payment metadata, replayed payment authorizations (nonce reuse), overpayment above what was quoted, and — most importantly — payments triggered by prompt-injected content the agent just read rather than its own plan. Incoming 402 offers get screened too: homoglyph/IP-literal/shortener resource URLs, credential demands, and price sanity. A shared counterparty report registry lets agents flag bad actors after the fact (reporting is always free) and every scan cross-checks it. PaySafe is advisory and non-custodial: it never touches keys, wallets, or funds, and wraps around whatever facilitator you already use. Verdicts are allow/flag/block with machine-readable, per-check reasons your agent can act on. Available as HTTP API, `/.well-known/x402` manifest, agent card, and MCP tools.

**Pricing table:**

| Endpoint | Price |
|---|---|
| `POST /v1/scan/outgoing` — screen an outgoing payment | $0.01 |
| `POST /v1/scan/incoming` — screen an incoming payment request | $0.01 |
| `GET /v1/reputation/:address` — counterparty report lookup | $0.01 |
| `POST /v1/reputation/report` — report a bad counterparty | Free |
| First 100 calls per API key (`POST /v1/keys`) | Free |
| Plans (`GET /v1/plans`): Pro $4.99/30d → $0.005/scan · Scale $19.99/30d → $0.002/scan | Subscribed via x402 |

**Payment:** x402 (exact scheme), USDC on Base mainnet, settled via Coinbase CDP facilitator.

**Links:**
- Base URL: `https://paysafe-agent.com`
- Manifest: `https://paysafe-agent.com/.well-known/x402`
- Agent card: `https://paysafe-agent.com/.well-known/agent-card.json`
- Docs: `https://paysafe-agent.com/` (self-documenting) + repo README

---

## x402scan

Submit at: https://www.x402scan.com/resources/register — paste each paid resource URL; x402scan validates the 402 schema automatically.

**Resource URLs to submit:**
1. `https://paysafe-agent.com/v1/scan/outgoing`
2. `https://paysafe-agent.com/v1/scan/incoming`
3. `https://paysafe-agent.com/v1/reputation/0x0000000000000000000000000000000000000000` (path-parameterized)

**Name:** PaySafe — x402 Payment Security Firewall

**Category:** Security / Infrastructure

**Description (short):**
Advisory firewall for x402 payment traffic. POST a payment (or a 402 offer you received) and get an allow/flag/block verdict with reasons: PII/secret leakage in payment metadata, nonce replay, overpayment vs expected price, prompt-injection-triggered payment detection, resource-URL risk, and shared counterparty reputation. Non-custodial — wraps your existing wallet/facilitator. $0.01/scan, first 100 calls free per API key.

**Pricing:** $0.01 per scan (USDC, Base, exact scheme) · reputation reporting free · 100 free calls per key

---

## One-liner (for directories that want a single sentence)

PaySafe is a non-custodial payment security firewall for x402: one API call screens any payment for PII/secret leaks, nonce replay, overpayment, and prompt-injection-triggered spe
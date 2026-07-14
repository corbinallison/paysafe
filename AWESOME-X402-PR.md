# Draft PR for `awesome-x402` (github.com/xpaysh/awesome-x402)

## PR title

Add PaySafe — payment security firewall for x402 traffic

## README entry

Add under a **Security** (or **Tools & Infrastructure**) section, keeping alphabetical order:

```markdown
- [PaySafe](https://paysafe.onrender.com) - Payment security firewall for x402 traffic. Screens outgoing/incoming payments for PII & secret leakage in payment metadata, nonce replay, overpayment, and prompt-injection-triggered payments; includes a shared counterparty report registry and MCP tools. Advisory & non-custodial — wraps your existing wallet/facilitator. $0.01/scan via x402 (CDP facilitator, Base), first 100 calls free. ([manifest](https://paysafe.onrender.com/.well-known/x402))
```

## PR description

### What is this?

PaySafe is an x402-native security service: agents call `POST /v1/scan/outgoing` before settling a payment (or `POST /v1/scan/incoming` when they receive a 402 offer) and get an allow/flag/block verdict with machine-readable reasons.

Checks cover the vulnerability classes specific to agentic payments:

- **PII/secret detection** on `resource_url` / `description` / `reason` / metadata before transmission (private keys, seed phrases, API keys, JWTs, cards, SSNs, emails)
- **Replay detection** — nonce reuse tracking scoped by network + payer
- **Overpayment detection** — configurable multiple-of-expected-price thresholds + absolute ceiling
- **Prompt-injection-triggered payment detection** — flags payments that originate from content the agent just read (tool result / fetched page) instead of its own planning step, and blocks when the pay-to address itself came from that content
- **Counterparty reputation** — shared post-hoc report registry; filing reports is free

### Why it belongs in this list

- First-class x402 seller: official `@x402/express` middleware, CDP facilitator settlement, Bazaar discovery metadata on every paid route, `/.well-known/x402` manifest, agent card, and an MCP server wrapper
- Fills a gap orthogonal to facilitators, wallets, and trust scores: a **transaction-level firewall** rather than an identity-level score
- Non-custodial and advisory — safe to insert into any existing x402 client stack
- Open source (MIT), zero-dependency detection core, 29-test suite, one-command Render deploy

### Checklist

- [x] Link is alive and returns the described service
- [x] `/.well-known/x402` manifest validates
- [x] Entry follows list formatting (name, dash, description)
- [x] Added in alphabetical order within its section
- [x] Not a duplicate of an existing entry

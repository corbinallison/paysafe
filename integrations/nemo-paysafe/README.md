# nemo-paysafe

[PaySafe](https://paysafe-agent.com) payment security for the [NVIDIA NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit) — screen every x402 payment before your workflow settles it.

```bash
pip install nemo-paysafe
```

Installing registers three NeMo functions via the `nat.plugins` entry point. Add them to your workflow YAML:

```yaml
functions:
  scan:
    _type: paysafe_scan_payment
    agent_id: my-agent          # optional; scopes velocity limits
  reputation:
    _type: paysafe_check_reputation
  report:
    _type: paysafe_report_counterparty
```

A free API key (100 free scans) is auto-minted on first use — set `api_key:` to pin one. Verdicts come back **allow / flag / block** with machine-readable reasons: prompt-injection-triggered payments, replayed nonces, overpayment vs the quote, secrets/PII leaking in payment metadata, lookalike-token contracts, address poisoning, counterparty reputation.

## Provenance: the strongest check

PaySafe's best detector catches payments whose *decision* came from content the agent just read — a prompt-injected page or tool result saying "send payment to 0x…". In NeMo, pass that text as the scan function's optional **`content`** argument:

```
paysafe_scan_payment(payment={...}, direction="outgoing", content="<the page/tool text the agent just read>")
```

If the `pay_to` address appears in that content, the payment is blocked. (LangChain and CrewAI integrations auto-tag this via a callback; NeMo has no global tool-output hook, so it's an explicit parameter the agent — or your workflow — fills.)

## The functions

| Function | When to call it |
|---|---|
| `paysafe_scan_payment` | ALWAYS, before settling an x402 payment (`direction="outgoing"`) or paying a received 402 offer (`direction="incoming"`) |
| `paysafe_check_reputation` | Before dealing with an unfamiliar counterparty address |
| `paysafe_report_counterparty` | After a bad payment experience (always free) — warns other agents |

The three functions share one PaySafe client per `(base_url, api_key, agent_id)`, so they draw on the same free-tier quota. Verdicts are Ed25519-signed and payment-bound; the underlying client verifies them against a pinned key automatically.

For wallet-level enforcement (the signer itself refuses unscanned payments), see `PaySafeEnforcer` in the [paysafe-x402 SDK](https://pypi.org/project/paysafe-x402/).

MIT. PaySafe is advisory and non-custodial: it never touches keys, wallets, or funds.

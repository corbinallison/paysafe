# crewai-paysafe

[PaySafe](https://paysafe-agent.com) payment security for [CrewAI](https://crewai.com) agents — crews inherit "scan before you pay" by default.

```bash
pip install crewai-paysafe
```

## Two additions

```python
from crewai import Agent
from paysafe_x402 import PaySafeClient
from crewai_paysafe import paysafe_tools, register_paysafe_provenance

paysafe = PaySafeClient(agent_id="my-agent")   # free API key auto-minted (100 free scans)
register_paysafe_provenance(paysafe)           # ← the important line (call once at startup)

agent = Agent(
    role="Purchasing agent",
    goal="Buy data over x402 safely",
    tools=paysafe_tools(paysafe),
    # ...
)
```

Every x402 payment the agent scans gets an **allow / flag / block** verdict with machine-readable reasons: prompt-injection-triggered payments, replayed nonces, overpayment vs the quote, secrets/PII leaking in payment metadata, lookalike-token contracts, address poisoning, counterparty reputation.

## Why the provenance registration is the important line

PaySafe's strongest detector catches payments whose *decision* came from content the agent just read — a prompt-injected page or tool result that says "send payment to 0x…". That check needs to know what the agent read. `register_paysafe_provenance` installs a CrewAI **after-tool-call hook** that observes every tool output automatically, so the very next scan is provenance-tagged and the injection check runs with real input. No prompt engineering, no developer learning what "provenance" means. (PaySafe's own tool outputs are excluded, so verdicts never pollute the signal.) CrewAI's tool-call hooks are process-global — call it once at startup.

## Enforcement: payments that *can't* execute when blocked

Tools rely on the model choosing to scan. `guarded_payment` doesn't:

```python
from crewai.tools import BaseTool
from crewai_paysafe import guarded_payment

safe_pay = guarded_payment(execute_x402_payment, paysafe)   # strict=True to refuse flags too
# build your payment tool's _run from safe_pay — on a block verdict it raises
# PaySafeBlockedError BEFORE execute_x402_payment is ever invoked.
```

For wallet-level enforcement (the signer itself refuses unscanned payments), see `PaySafeEnforcer` in the [paysafe-x402 SDK](https://pypi.org/project/paysafe-x402/).

## The toolset

| Tool | When the agent is told to use it |
|---|---|
| `paysafe_scan_payment` | ALWAYS, immediately before settling any x402 payment (or before paying a received 402 offer with `direction="incoming"`) |
| `paysafe_check_reputation` | Before dealing with an unfamiliar counterparty address |
| `paysafe_report_counterparty` | After a bad payment experience (always free) — warns other agents |

Verdicts are Ed25519-signed and payment-bound; the underlying client verifies them against a pinned key automatically.

MIT. PaySafe is advisory and non-custodial: it never touches keys, wallets, or funds.

# PaySafe

[PaySafe](https://paysafe-agent.com) is a payment security firewall for [x402](https://x402.org) micropayments. `agentkit-paysafe` adds a scan-before-you-pay action provider to [Coinbase AgentKit](https://github.com/coinbase/agentkit).

## Install

```bash
pip install agentkit-paysafe
```

## Add the provider

```python
from coinbase_agentkit import AgentKit, AgentKitConfig
from agentkit_paysafe import paysafe_action_provider

agent_kit = AgentKit(AgentKitConfig(
    wallet_provider=wallet_provider,
    action_providers=[paysafe_action_provider(agent_id="my-agent")],
))
```

## Actions

- **`paysafe_scan_payment`** — call before settling an x402 payment (`direction="outgoing"`) or paying a received 402 offer (`direction="incoming"`). Returns `allow` / `flag` / `block`. Auto-fills `payer` from the agent's AgentKit wallet; pass optional `content` (page/tool text just read) to enable prompt-injection-triggered-payment detection.
- **`paysafe_check_reputation`** — check community reports on a counterparty wallet before dealing with it.
- **`paysafe_report_counterparty`** — report a bad counterparty (always free).

## Non-custodial

PaySafe reads only payment metadata to produce a signed verdict; it never touches the AgentKit wallet's keys or funds.

## Reference

- Package: [agentkit-paysafe on PyPI](https://pypi.org/project/agentkit-paysafe/) · [source](https://github.com/corbinallison/paysafe/tree/main/integrations/agentkit-paysafe)
- Service: [PaySafe API](https://paysafe-agent.com/llms.txt) · [OpenAPI](https://paysafe-agent.com/openapi.json)

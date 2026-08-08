# Tollwarden

[Tollwarden](https://tollwarden.com) is a payment security firewall for [x402](https://x402.org) micropayments. `agentkit-tollwarden` adds a scan-before-you-pay action provider to [Coinbase AgentKit](https://github.com/coinbase/agentkit).

## Install

```bash
pip install agentkit-tollwarden
```

## Add the provider

```python
from coinbase_agentkit import AgentKit, AgentKitConfig
from agentkit_tollwarden import tollwarden_action_provider

agent_kit = AgentKit(AgentKitConfig(
    wallet_provider=wallet_provider,
    action_providers=[tollwarden_action_provider(agent_id="my-agent")],
))
```

## Actions

- **`tollwarden_scan_payment`** — call before settling an x402 payment (`direction="outgoing"`) or paying a received 402 offer (`direction="incoming"`). Returns `allow` / `flag` / `block`. Auto-fills `payer` from the agent's AgentKit wallet; pass optional `content` (page/tool text just read) to enable prompt-injection-triggered-payment detection.
- **`tollwarden_check_reputation`** — check community reports on a counterparty wallet before dealing with it.
- **`tollwarden_report_counterparty`** — report a bad counterparty (always free).

## Non-custodial

Tollwarden reads only payment metadata to produce a signed verdict; it never touches the AgentKit wallet's keys or funds.

## Reference

- Package: [agentkit-tollwarden on PyPI](https://pypi.org/project/agentkit-tollwarden/) · [source](https://github.com/tollwarden/tollwarden/tree/main/integrations/agentkit-tollwarden)
- Service: [Tollwarden API](https://tollwarden.com/llms.txt) · [OpenAPI](https://tollwarden.com/openapi.json)

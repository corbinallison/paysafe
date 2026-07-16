"""
agentkit-paysafe — PaySafe payment security for Coinbase AgentKit.

Adds a PaySafe action provider so an AgentKit agent screens every x402 payment
before settling it:

    from coinbase_agentkit import AgentKit, AgentKitConfig
    from agentkit_paysafe import paysafe_action_provider

    agent_kit = AgentKit(AgentKitConfig(
        wallet_provider=wallet_provider,
        action_providers=[paysafe_action_provider(agent_id="my-agent"), ...],
    ))

Actions:
  - paysafe_scan_payment        (before you settle / before you pay a 402 offer)
  - paysafe_check_reputation    (before dealing with a counterparty)
  - paysafe_report_counterparty (after a bad experience — free)

The scan action auto-fills the `payer` from the agent's own AgentKit wallet
when you don't supply one (scopes velocity limits), and takes an optional
`content` argument — the page/tool text the agent just read — which lights up
PaySafe's strongest check: prompt-injection-triggered-payment detection.

PaySafe is advisory and non-custodial — it never touches keys, wallets, or funds.
"""
from __future__ import annotations

from .provider import PaySafeActionProvider, paysafe_action_provider

__all__ = ["PaySafeActionProvider", "paysafe_action_provider", "__version__"]

__version__ = "0.1.0"

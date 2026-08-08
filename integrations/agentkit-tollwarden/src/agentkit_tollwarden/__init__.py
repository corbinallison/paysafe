"""
agentkit-tollwarden — TollWarden payment security for Coinbase AgentKit.

Adds a TollWarden action provider so an AgentKit agent screens every x402 payment
before settling it:

    from coinbase_agentkit import AgentKit, AgentKitConfig
    from agentkit_tollwarden import tollwarden_action_provider

    agent_kit = AgentKit(AgentKitConfig(
        wallet_provider=wallet_provider,
        action_providers=[tollwarden_action_provider(agent_id="my-agent"), ...],
    ))

Actions:
  - tollwarden_scan_payment        (before you settle / before you pay a 402 offer)
  - tollwarden_check_reputation    (before dealing with a counterparty)
  - tollwarden_report_counterparty (after a bad experience — free)

The scan action auto-fills the `payer` from the agent's own AgentKit wallet
when you don't supply one (scopes velocity limits), and takes an optional
`content` argument — the page/tool text the agent just read — which lights up
TollWarden's strongest check: prompt-injection-triggered-payment detection.

TollWarden is advisory and non-custodial — it never touches keys, wallets, or funds.
"""
from __future__ import annotations

from .provider import TollWardenActionProvider, tollwarden_action_provider

__all__ = ["TollWardenActionProvider", "tollwarden_action_provider", "__version__"]

__version__ = "0.1.0"

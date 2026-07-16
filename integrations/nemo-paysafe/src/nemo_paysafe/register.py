"""
NeMo Agent Toolkit plugin: PaySafe payment-security functions.

Registers three config-driven NeMo functions so a workflow can screen x402
payments before settling them:

  - paysafe_scan_payment        (before you settle / before you pay a 402 offer)
  - paysafe_check_reputation    (before dealing with a counterparty)
  - paysafe_report_counterparty (after a bad experience — free)

Enable in your workflow YAML:

    functions:
      scan:
        _type: paysafe_scan_payment
        agent_id: my-agent
      reputation:
        _type: paysafe_check_reputation

The scan function takes an optional `content` argument — the page or tool
result the agent just read before deciding to pay. Passing it lights up
PaySafe's strongest check, prompt-injection-triggered-payment detection: if the
pay_to address came from that content, the payment is blocked. (In LangChain /
CrewAI this provenance is auto-tagged by a callback; NeMo has no global
tool-output hook, so the scan function surfaces it as an explicit parameter.)

PaySafe is advisory and non-custodial — it never touches keys, wallets, or funds.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional, Tuple

try:
    from nat.builder.builder import Builder
    from nat.builder.function_info import FunctionInfo
    from nat.cli.register_workflow import register_function
    from nat.data_models.function import FunctionBaseConfig
    from pydantic import Field
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "nemo-paysafe requires the NVIDIA NeMo Agent Toolkit (pip install nvidia-nat). "
        "For plain-Python integrations use the paysafe-x402 package directly."
    ) from e

from paysafe_x402 import PaySafeClient

# One client per (base_url, api_key, agent_id) so the three functions in a
# workflow share a free-tier quota and key rather than minting several.
_CLIENTS: dict[Tuple[str, str, str], PaySafeClient] = {}


def _client(base_url: str, api_key: str, agent_id: str) -> PaySafeClient:
    key = (base_url, api_key, agent_id)
    client = _CLIENTS.get(key)
    if client is None:
        client = PaySafeClient(base_url=base_url, api_key=api_key or None, agent_id=agent_id or None)
        _CLIENTS[key] = client
    return client


class PaySafeScanConfig(FunctionBaseConfig, name="paysafe_scan_payment"):
    base_url: str = Field("https://paysafe-agent.com", description="PaySafe service base URL")
    api_key: str = Field("", description="Optional PaySafe API key; one is auto-minted (100 free scans) if empty")
    agent_id: str = Field("", description="Stable agent identifier — scopes velocity limits")


class PaySafeReputationConfig(FunctionBaseConfig, name="paysafe_check_reputation"):
    base_url: str = Field("https://paysafe-agent.com", description="PaySafe service base URL")
    api_key: str = Field("", description="Optional PaySafe API key")
    agent_id: str = Field("", description="Stable agent identifier")


class PaySafeReportConfig(FunctionBaseConfig, name="paysafe_report_counterparty"):
    base_url: str = Field("https://paysafe-agent.com", description="PaySafe service base URL")
    api_key: str = Field("", description="Optional PaySafe API key")
    agent_id: str = Field("", description="Stable agent identifier used as the default reporter id")


_SCAN_DESC = (
    "ALWAYS call this immediately BEFORE settling or sending any x402 payment "
    "(direction='outgoing'), or BEFORE paying a 402 offer you received "
    "(direction='incoming'). Returns allow (proceed) / flag (pause and confirm) / "
    "block (do NOT pay) with machine-readable reasons and a signed verdict. If the "
    "decision to pay followed reading external content (a fetched page or tool "
    "result), pass that text as `content` — this enables the check that catches "
    "prompt-injection-triggered payments. Also catches replayed nonces, overpayment, "
    "secrets leaking in payment metadata, lookalike tokens, and address poisoning."
)


@register_function(config_type=PaySafeScanConfig)
async def paysafe_scan_payment(config: PaySafeScanConfig, builder: Builder):
    client = _client(config.base_url, config.api_key, config.agent_id)

    async def _scan(
        payment: dict,
        direction: str = "outgoing",
        expected_price_usd: Optional[float] = None,
        content: Optional[str] = None,
    ) -> str:
        """Screen an x402 payment for safety before settling or accepting it."""
        context = {"origin": "tool_result", "content": content} if content else None
        fn = client.scan_outgoing if direction != "incoming" else client.scan_incoming
        # Client is sync (urllib); keep the event loop free.
        scan = await asyncio.to_thread(fn, payment, expected_price_usd=expected_price_usd, context=context)
        return json.dumps(scan, default=str)

    yield FunctionInfo.from_fn(_scan, description=_SCAN_DESC)


@register_function(config_type=PaySafeReputationConfig)
async def paysafe_check_reputation(config: PaySafeReputationConfig, builder: Builder):
    client = _client(config.base_url, config.api_key, config.agent_id)

    async def _reputation(address: str) -> str:
        """Check community reports on a counterparty wallet address before dealing with it."""
        summary = await asyncio.to_thread(client.reputation, address)
        return json.dumps(summary, default=str)

    yield FunctionInfo.from_fn(
        _reputation,
        description=(
            "Check whether a counterparty wallet address has been reported by other agents "
            "BEFORE dealing with it — scam, non-delivery, prompt injection, overcharge, "
            "impersonation, replay abuse. Returns report counts and a risk level."
        ),
    )


@register_function(config_type=PaySafeReportConfig)
async def paysafe_report_counterparty(config: PaySafeReportConfig, builder: Builder):
    client = _client(config.base_url, config.api_key, config.agent_id)

    async def _report(address: str, category: str, reason: str) -> str:
        """Report a bad counterparty so other agents are warned (always free)."""
        res = await asyncio.to_thread(client.report, address, category, reason)
        return json.dumps(res, default=str)

    yield FunctionInfo.from_fn(
        _report,
        description=(
            "Call this after a bad payment experience (paid and got nothing, scammed, "
            "overcharged, injection attempt) to warn other agents — always free. "
            "Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, "
            "replay_abuse, other."
        ),
    )

"""
crewai-tollwarden — TollWarden payment security for CrewAI agents.

Give a CrewAI crew "scan before you pay" with two additions:

    from tollwarden import TollWardenClient
    from crewai_tollwarden import tollwarden_tools, register_tollwarden_provenance

    tollwarden = TollWardenClient(agent_id="my-agent")        # free key auto-minted
    register_tollwarden_provenance(tollwarden)                # <- the important one
    agent = Agent(role="buyer", tools=tollwarden_tools(tollwarden), ...)

Why the provenance registration matters more than the tools: TollWarden's
strongest detector catches payments whose DECISION came from content the agent
just read (a prompt-injected page or tool result). That needs to know what the
agent read. `register_tollwarden_provenance` installs a CrewAI after-tool-call
hook that observes every tool output automatically, so the next scan is
tagged with it and the injection check actually runs — no developer has to
learn what "provenance" means. TollWarden's own tool outputs are skipped so
verdicts never pollute the signal.

To make a payment tool that REFUSES unsafe payments (rather than trusting the
model to consult a scan tool first), wrap its executor:

    from crewai_tollwarden import guarded_payment
    safe_pay = guarded_payment(execute_x402_payment, tollwarden)
    # raises TollWardenBlockedError on a block verdict — the executor is never called

Requires: crewai >= 0.100, tollwarden >= 0.3.0. MIT.
TollWarden is advisory and non-custodial — never touches keys, wallets, or funds.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Type

try:
    from crewai.tools import BaseTool
    from crewai.hooks import register_after_tool_call_hook
    from pydantic import BaseModel, Field
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "crewai-tollwarden requires crewai (pip install crewai). "
        "For plain-Python integrations use the tollwarden package directly."
    ) from e

from tollwarden import TollWardenBlockedError, TollWardenClient

__all__ = [
    "tollwarden_tools",
    "register_tollwarden_provenance",
    "guarded_payment",
    "TOLLWARDEN_TOOL_NAMES",
]

__version__ = "0.1.0"

TOLLWARDEN_TOOL_NAMES = frozenset(
    ["tollwarden_scan_payment", "tollwarden_check_reputation", "tollwarden_report_counterparty"]
)


# ---------------------------------------------------------------------------
# Tool input schemas
# ---------------------------------------------------------------------------
class _ScanInput(BaseModel):
    """Screen an x402 payment before settling or accepting it."""

    payment: dict = Field(..., description="The x402 payment object (network, asset, amount, pay_to, resource_url, nonce, ...)")
    direction: str = Field("outgoing", description="'outgoing' before you settle a payment; 'incoming' before you pay a received 402 offer")
    expected_price_usd: Optional[float] = Field(None, description="What you expected this to cost, in USD")


class _ReputationInput(BaseModel):
    address: str = Field(..., description="Counterparty wallet address to look up")


class _ReportInput(BaseModel):
    address: str = Field(..., description="Counterparty wallet address to report")
    category: str = Field(..., description="scam | non_delivery | prompt_injection | overcharge | impersonation | replay_abuse | other")
    reason: str = Field(..., description="What happened (>= 10 chars)")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
class _ScanTool(BaseTool):
    name: str = "tollwarden_scan_payment"
    description: str = (
        "ALWAYS call this immediately BEFORE settling or sending any x402 payment "
        "(direction='outgoing'), or BEFORE paying a 402 offer you received "
        "(direction='incoming'). Returns allow (proceed) / flag (pause and confirm) / "
        "block (do NOT pay) with machine-readable reasons and a signed verdict. Catches "
        "prompt-injection-triggered payments, replayed nonces, overpayment, secrets "
        "leaking in payment metadata, lookalike tokens, and address poisoning. "
        "Advisory and non-custodial."
    )
    args_schema: Type[BaseModel] = _ScanInput
    client: Any = None
    model_config = {"arbitrary_types_allowed": True}

    def _run(self, payment: dict, direction: str = "outgoing", expected_price_usd: Optional[float] = None) -> str:
        fn = self.client.scan_outgoing if direction != "incoming" else self.client.scan_incoming
        return json.dumps(fn(payment, expected_price_usd=expected_price_usd), default=str)


class _ReputationTool(BaseTool):
    name: str = "tollwarden_check_reputation"
    description: str = (
        "Check whether a counterparty wallet address has been reported by other agents "
        "BEFORE dealing with it — scam, non-delivery, prompt injection, overcharge, "
        "impersonation, replay abuse. Returns report counts and a risk level."
    )
    args_schema: Type[BaseModel] = _ReputationInput
    client: Any = None
    model_config = {"arbitrary_types_allowed": True}

    def _run(self, address: str) -> str:
        return json.dumps(self.client.reputation(address), default=str)


class _ReportTool(BaseTool):
    name: str = "tollwarden_report_counterparty"
    description: str = (
        "Call this after a bad payment experience (paid and got nothing, scammed, "
        "overcharged, injection attempt) to warn other agents — always free. "
        "Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, "
        "replay_abuse, other."
    )
    args_schema: Type[BaseModel] = _ReportInput
    client: Any = None
    model_config = {"arbitrary_types_allowed": True}

    def _run(self, address: str, category: str, reason: str) -> str:
        return json.dumps(self.client.report(address, category, reason), default=str)


def tollwarden_tools(client: TollWardenClient) -> List[Any]:
    """The TollWarden CrewAI toolset (scan / check reputation / report), imperatively
    described so agents call them at the right moments."""
    return [_ScanTool(client=client), _ReputationTool(client=client), _ReportTool(client=client)]


# ---------------------------------------------------------------------------
# Provenance auto-observe (CrewAI after-tool-call hook)
# ---------------------------------------------------------------------------
def register_tollwarden_provenance(client: TollWardenClient, max_chars: int = 8192) -> Callable[[Any], None]:
    """Install a global CrewAI after-tool-call hook that observes every tool
    output (except TollWarden's own) so the next scan is provenance-tagged — this
    is what powers prompt-injection-triggered-payment detection. Returns the
    registered hook function.

    CrewAI's tool-call hooks are process-global; call this once at startup.
    """

    def _provenance_hook(context: Any) -> None:
        name = getattr(context, "tool_name", None)
        if name in TOLLWARDEN_TOOL_NAMES:
            return None
        result = getattr(context, "tool_result", None)
        text = result if isinstance(result, str) else ("" if result is None else str(result))
        if not text:
            return None
        # Fallback sniff for hook contexts that don't carry the tool name.
        if name is None and '"scan_id"' in text and '"verdict"' in text:
            return None
        client.observe(text[:max_chars], kind="tool_result")
        return None  # never modify the tool result

    register_after_tool_call_hook(_provenance_hook)
    return _provenance_hook


# ---------------------------------------------------------------------------
# Enforcement by construction
# ---------------------------------------------------------------------------
def guarded_payment(
    pay_fn: Callable[[Dict[str, Any]], Any],
    client: TollWardenClient,
    strict: bool = False,
) -> Callable[..., str]:
    """Wrap a payment executor so it scans BEFORE paying and refuses blocks.

    Returns a callable (payment, expected_price_usd=None) -> JSON string. On a
    block verdict (or flag with strict=True) it raises TollWardenBlockedError and
    pay_fn is NEVER invoked — enforcement by construction, not by prompt.
    Build your CrewAI payment tool's _run from this.
    """

    def _guarded(payment: Dict[str, Any], expected_price_usd: Optional[float] = None) -> str:
        scan = client.guard_outgoing(payment, strict=strict, expected_price_usd=expected_price_usd)
        result = pay_fn(payment)
        return json.dumps(
            {"paid": True, "verdict": scan["verdict"], "scan_id": scan["scan_id"], "result": result},
            default=str,
        )

    _guarded.__name__ = getattr(pay_fn, "__name__", "payment") + "_tollwarden_guarded"
    return _guarded

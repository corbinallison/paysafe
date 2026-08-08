"""
langchain-tollwarden — Tollwarden payment security for LangChain / LangGraph agents.

Two lines make an agent's x402 payments scanned by default:

    from tollwarden import TollwardenClient
    from langchain_tollwarden import TollwardenProvenanceCallback, tollwarden_tools

    tollwarden = TollwardenClient(agent_id="my-agent")           # free key auto-minted
    tools = [*tollwarden_tools(tollwarden), *your_other_tools]
    callbacks = [TollwardenProvenanceCallback(tollwarden)]       # <- the important one
    # pass tools= and callbacks= to your agent as usual

Why the callback matters more than the tools: Tollwarden's strongest detector
catches payments whose DECISION came from content the agent just read (a
prompt-injected page or tool result). That requires knowing what the agent
read — its provenance. The callback observes every tool output automatically,
so the next scan is tagged with it and the injection check actually runs.
No developer has to learn what "provenance" means; it's just on.

To make an existing payment tool refuse unsafe payments (rather than trusting
the model to consult a scan tool first), wrap its function:

    from langchain_tollwarden import guarded_payment
    safe_pay = guarded_payment(execute_x402_payment, tollwarden)
    # safe_pay raises TollwardenBlockedError on a block verdict — the payment
    # function is never called. Build your payment tool from safe_pay.

Requires: langchain-core >= 0.3, tollwarden >= 0.3.0. MIT.
Tollwarden is advisory and non-custodial — never touches keys, wallets, or funds.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import StructuredTool
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "langchain-tollwarden requires langchain-core (pip install langchain-core). "
        "For plain-Python integrations use the tollwarden package directly."
    ) from e

from tollwarden import TollwardenBlockedError, TollwardenClient

__all__ = [
    "TollwardenProvenanceCallback",
    "tollwarden_tools",
    "guarded_payment",
    "TOLLWARDEN_TOOL_NAMES",
]

__version__ = "0.1.0"

TOLLWARDEN_TOOL_NAMES = frozenset(
    ["tollwarden_scan_payment", "tollwarden_check_reputation", "tollwarden_report_counterparty"]
)


class TollwardenProvenanceCallback(BaseCallbackHandler):
    """Auto-tags payment provenance: observes every tool output so the next
    scan knows what the agent just read (powers injection-triggered-payment
    detection).

    Tollwarden's own tool outputs are skipped — a verdict echoed back as
    "content the agent read" would poison the provenance signal.
    """

    def __init__(self, client: TollwardenClient, max_chars: int = 8192):
        self._client = client
        self._max_chars = max_chars

    def _is_own_output(self, name: Optional[str], text: str) -> bool:
        if name and name in TOLLWARDEN_TOOL_NAMES:
            return True
        # Fallback sniff for runtimes that don't pass the tool name through.
        return '"scan_id"' in text and '"verdict"' in text

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:  # noqa: ANN401
        text = output if isinstance(output, str) else str(output)
        if not text or self._is_own_output(kwargs.get("name"), text):
            return
        self._client.observe(text[: self._max_chars], kind="tool_result")

    def on_retriever_end(self, documents: Any, **kwargs: Any) -> None:  # noqa: ANN401
        try:
            text = "\n\n".join(getattr(d, "page_content", str(d)) for d in documents)
        except TypeError:
            text = str(documents)
        if text:
            self._client.observe(text[: self._max_chars], kind="fetched_content")


def guarded_payment(
    pay_fn: Callable[[Dict[str, Any]], Any],
    client: TollwardenClient,
    strict: bool = False,
) -> Callable[..., str]:
    """Wrap a payment executor so it scans BEFORE paying and refuses blocks.

    Returns a callable (payment, expected_price_usd=None) -> JSON string.
    On a block verdict (or flag with strict=True) it raises
    TollwardenBlockedError and pay_fn is NEVER invoked — enforcement by
    construction, not by prompt.
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


def tollwarden_tools(client: TollwardenClient) -> List[Any]:
    """The Tollwarden toolset, imperatively described so agents call them at the
    right moments (mirrors the Tollwarden MCP server's tool framing)."""

    def scan_payment(
        payment: dict,
        direction: str = "outgoing",
        expected_price_usd: Optional[float] = None,
    ) -> str:
        """Scan an x402 payment for safety before settling or accepting it."""
        fn = client.scan_outgoing if direction != "incoming" else client.scan_incoming
        return json.dumps(fn(payment, expected_price_usd=expected_price_usd), default=str)

    def check_reputation(address: str) -> str:
        """Check community reports on a counterparty wallet address."""
        return json.dumps(client.reputation(address), default=str)

    def report_counterparty(address: str, category: str, reason: str) -> str:
        """Report a bad counterparty so other agents are warned."""
        return json.dumps(client.report(address, category, reason), default=str)

    return [
        StructuredTool.from_function(
            scan_payment,
            name="tollwarden_scan_payment",
            description=(
                "ALWAYS call this immediately BEFORE settling or sending any x402 payment "
                "(direction='outgoing'), or BEFORE paying a 402 offer you received "
                "(direction='incoming'). Returns allow (proceed) / flag (pause and confirm) / "
                "block (do NOT pay) with machine-readable reasons and a signed verdict. "
                "Catches prompt-injection-triggered payments, replayed nonces, overpayment, "
                "secrets leaking in payment metadata, lookalike tokens, and address poisoning. "
                "Advisory and non-custodial."
            ),
        ),
        StructuredTool.from_function(
            check_reputation,
            name="tollwarden_check_reputation",
            description=(
                "Check whether a counterparty wallet address has been reported by other agents "
                "BEFORE dealing with it — scam, non-delivery, prompt injection, overcharge, "
                "impersonation, replay abuse. Returns report counts and a risk level."
            ),
        ),
        StructuredTool.from_function(
            report_counterparty,
            name="tollwarden_report_counterparty",
            description=(
                "Call this after a bad payment experience (paid and got nothing, scammed, "
                "overcharged, injection attempt) to warn other agents — always free. "
                "Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, "
                "replay_abuse, other."
            ),
        ),
    ]

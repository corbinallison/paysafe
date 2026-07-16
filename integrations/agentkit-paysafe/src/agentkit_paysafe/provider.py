"""PaySafe action provider for Coinbase AgentKit."""
from __future__ import annotations

import json
from typing import Any, Optional

try:
    from coinbase_agentkit import ActionProvider, WalletProvider, create_action
    from coinbase_agentkit.network import Network
    from pydantic import BaseModel, Field
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "agentkit-paysafe requires coinbase-agentkit (pip install coinbase-agentkit). "
        "For plain-Python integrations use the paysafe-x402 package directly."
    ) from e

from paysafe_x402 import PaySafeClient


# ---------------------------------------------------------------------------
# Action input schemas
# ---------------------------------------------------------------------------
class ScanPaymentSchema(BaseModel):
    """Screen an x402 payment before settling or accepting it."""

    payment: dict = Field(..., description="The x402 payment object (network, asset, amount, pay_to, resource_url, nonce, ...)")
    direction: str = Field("outgoing", description="'outgoing' before you settle a payment; 'incoming' before you pay a received 402 offer")
    expected_price_usd: Optional[float] = Field(None, description="What you expected this to cost, in USD")
    content: Optional[str] = Field(None, description="The page or tool text the agent just read before deciding to pay — enables prompt-injection-triggered-payment detection")


class CheckReputationSchema(BaseModel):
    """Look up a counterparty wallet's reputation."""

    address: str = Field(..., description="Counterparty wallet address to look up")


class ReportCounterpartySchema(BaseModel):
    """Report a bad counterparty."""

    address: str = Field(..., description="Counterparty wallet address to report")
    category: str = Field(..., description="scam | non_delivery | prompt_injection | overcharge | impersonation | replay_abuse | other")
    reason: str = Field(..., description="What happened (>= 10 chars)")


_SCAN_DESC = (
    "ALWAYS call this immediately BEFORE settling or sending any x402 payment "
    "(direction='outgoing'), or BEFORE paying a 402 offer you received "
    "(direction='incoming'). Returns allow (proceed) / flag (pause and confirm) / "
    "block (do NOT pay) with machine-readable reasons and a signed verdict. If the "
    "decision to pay followed reading external content, pass that text as `content` "
    "to enable prompt-injection-triggered-payment detection. Also catches replayed "
    "nonces, overpayment, secrets in payment metadata, lookalike tokens, and address "
    "poisoning. Advisory and non-custodial — never touches your wallet or funds."
)


class PaySafeActionProvider(ActionProvider):
    """AgentKit action provider exposing PaySafe's scan / reputation / report."""

    def __init__(self, client: PaySafeClient):
        super().__init__("paysafe", [])
        self._client = client

    @create_action(name="paysafe_scan_payment", description=_SCAN_DESC, schema=ScanPaymentSchema)
    def scan_payment(self, wallet_provider: Any, args: dict[str, Any]) -> str:
        payment = dict(args.get("payment") or {})
        # Idiomatic AgentKit touch: scope velocity limits to the agent's own
        # wallet by auto-filling the payer when the caller didn't set one.
        if not payment.get("payer"):
            try:
                addr = wallet_provider.get_address()
                if addr:
                    payment["payer"] = addr
            except Exception:  # noqa: BLE001 — wallet address is best-effort
                pass
        content = args.get("content")
        context = {"origin": "tool_result", "content": content} if content else None
        direction = args.get("direction") or "outgoing"
        fn = self._client.scan_outgoing if direction != "incoming" else self._client.scan_incoming
        scan = fn(payment, expected_price_usd=args.get("expected_price_usd"), context=context)
        return json.dumps(scan, default=str)

    @create_action(
        name="paysafe_check_reputation",
        description=(
            "Check whether a counterparty wallet address has been reported by other agents "
            "BEFORE dealing with it — scam, non-delivery, prompt injection, overcharge, "
            "impersonation, replay abuse. Returns report counts and a risk level."
        ),
        schema=CheckReputationSchema,
    )
    def check_reputation(self, args: dict[str, Any]) -> str:
        return json.dumps(self._client.reputation(args["address"]), default=str)

    @create_action(
        name="paysafe_report_counterparty",
        description=(
            "Call this after a bad payment experience (paid and got nothing, scammed, "
            "overcharged, injection attempt) to warn other agents — always free. "
            "Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, "
            "replay_abuse, other."
        ),
        schema=ReportCounterpartySchema,
    )
    def report_counterparty(self, args: dict[str, Any]) -> str:
        return json.dumps(
            self._client.report(args["address"], args["category"], args["reason"]), default=str
        )

    def supports_network(self, network: "Network") -> bool:
        # PaySafe is advisory metadata analysis — network-agnostic.
        return True


def paysafe_action_provider(
    base_url: str = "https://paysafe-agent.com",
    api_key: Optional[str] = None,
    agent_id: Optional[str] = None,
    client: Optional[PaySafeClient] = None,
) -> PaySafeActionProvider:
    """Construct the PaySafe action provider. A free API key (100 free scans) is
    auto-minted on first use unless you pass `api_key` or your own `client`."""
    return PaySafeActionProvider(
        client or PaySafeClient(base_url=base_url, api_key=api_key, agent_id=agent_id)
    )

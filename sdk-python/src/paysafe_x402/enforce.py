"""
Wallet-side enforcement kit (Python parity with the TypeScript SDK's enforce.ts).

Turns PaySafe from advisory into ENFORCED: a wrapped signer refuses to sign an
x402 payment authorization unless a fresh, Ed25519-verified PaySafe
allow-verdict exists for exactly that payment. The verdict's payment
commitment — sha256(network|pay_to|asset|amount|nonce) — is recomputed from
the EIP-712 typed data the wallet is being asked to sign, so a compromised
agent cannot scan one payment and settle another: any change to recipient,
amount, asset, chain, or nonce changes the commitment and the signature is
refused.

    from paysafe_x402 import PaySafeClient, PaySafeEnforcer
    from eth_account import Account

    paysafe  = PaySafeClient(agent_id="my-agent")
    enforcer = PaySafeEnforcer(trusted_key_hex=paysafe.verdict_key())
    account  = enforcer.guard_signer(Account.from_key(PRIVATE_KEY))

    scan = paysafe.guard_outgoing(payment)      # raises on block
    enforcer.approve(scan, payment)             # registers the verdict locally
    # ... hand `account` to your x402 client as usual. It will only ever sign
    # authorizations whose commitment carries a live allow-verdict.

Design notes (identical guarantees to the TS kit):
  - Signer-agnostic: anything with a ``sign_typed_data`` method works —
    eth-account LocalAccount (positional, keyword, or ``full_message=`` call
    shapes are all recognized), web3.py wrappers, custom signers. Every other
    attribute/method of the signer passes through untouched.
  - Recognized payment types: EIP-3009 TransferWithAuthorization /
    ReceiveWithAuthorization (the x402 "exact" scheme on EVM) and ERC-2612
    Permit. Other typed data passes through by default; ``strict_types=True``
    refuses everything unrecognized (deny-by-default).
  - Approvals are SINGLE-USE by default and expire with the attestation (plus
    an optional tighter ``max_age_s``), so a verdict can't be hoarded.
  - Enforcement never phones home: approval happens locally against the
    pinned key. If PaySafe is unreachable, nothing new can be approved —
    fail-closed, which is the point.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from . import (
    PaySafeError,
    _parse_iso_ms,
    compute_payment_commitment,
    verify_attestation,
)

__all__ = [
    "PaySafeEnforcer",
    "PaySafeEnforcementError",
    "payment_from_typed_data",
]

#: EIP-712 primary types treated as payment authorizations.
_PAYMENT_TYPES = ("TransferWithAuthorization", "ReceiveWithAuthorization", "Permit")


class PaySafeEnforcementError(PaySafeError):
    """Raised when a signature is refused (no/stale/used approval, strict mode)."""

    def __init__(self, message: str, commitment: Optional[str] = None, primary_type: Optional[str] = None):
        super().__init__(message)
        self.commitment = commitment
        self.primary_type = primary_type


def _s(v: Any) -> str:
    """Stringify typed-data scalar values the way the commitment expects."""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):  # bool is an int subclass; exclude it explicitly
        return ""
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    return ""


def _infer_primary_type(types: Any) -> Optional[str]:
    """eth-account's (domain, types, message) shape has no primaryType — infer
    it as the type no other type references (EIP-712 convention)."""
    if not isinstance(types, dict):
        return None
    names = [n for n in types.keys() if n != "EIP712Domain"]
    referenced = set()
    for n in names:
        fields = types.get(n)
        if not isinstance(fields, list):
            continue
        for f in fields:
            t = (f or {}).get("type", "") if isinstance(f, dict) else ""
            referenced.add(t.replace("[]", ""))
    for n in names:
        if n not in referenced:
            return n
    return names[0] if names else None


def payment_from_typed_data(td: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map an EIP-712 payload to the payment fields the commitment binds.

    Returns None for typed data that is not a recognized payment authorization.
    """
    if not isinstance(td, dict):
        return None
    primary = td.get("primaryType") or _infer_primary_type(td.get("types"))
    if primary not in _PAYMENT_TYPES:
        return None
    message = td.get("message") or {}
    domain = td.get("domain") or {}
    chain_id = _s(domain.get("chainId"))
    network = f"eip155:{chain_id}" if chain_id else ""
    asset = domain.get("verifyingContract") if isinstance(domain.get("verifyingContract"), str) else ""

    if primary in ("TransferWithAuthorization", "ReceiveWithAuthorization"):
        return {
            "network": network,
            "asset": asset,
            "pay_to": _s(message.get("to")),
            "payer": _s(message.get("from")),
            "amount": _s(message.get("value")),
            "nonce": _s(message.get("nonce")),
        }
    # ERC-2612 Permit — a spend approval is a payment authorization too.
    return {
        "network": network,
        "asset": asset,
        "pay_to": _s(message.get("spender")),
        "payer": _s(message.get("owner")),
        "amount": _s(message.get("value")),
        "nonce": _s(message.get("nonce")),
    }


def _typed_data_from_call(args: tuple, kwargs: dict) -> Optional[Dict[str, Any]]:
    """Normalize the sign_typed_data call shapes into one EIP-712 dict.

    Recognized shapes:
      sign_typed_data(full_message={...})                       (eth-account kwarg)
      sign_typed_data({...})                                    (single full dict)
      sign_typed_data(domain_data, message_types, message_data) (eth-account positional)
      sign_typed_data(domain_data=..., message_types=..., message_data=...)
    """
    full = kwargs.get("full_message")
    if isinstance(full, dict):
        return full
    if len(args) == 1 and isinstance(args[0], dict) and (
        "types" in args[0] or "primaryType" in args[0] or "message" in args[0]
    ):
        return args[0]
    domain = kwargs.get("domain_data")
    types = kwargs.get("message_types")
    message = kwargs.get("message_data")
    if len(args) >= 3:
        domain, types, message = args[0], args[1], args[2]
    if domain is None and types is None and message is None:
        return None
    return {
        "domain": domain or {},
        "types": types or {},
        "message": message or {},
        "primaryType": _infer_primary_type(types),
    }


class _Approval:
    __slots__ = ("attestation", "scan_id", "verdict", "approved_at", "used")

    def __init__(self, attestation: Dict[str, Any], scan_id: str, verdict: str):
        self.attestation = attestation
        self.scan_id = scan_id
        self.verdict = verdict
        self.approved_at = time.time()
        self.used = False


class _GuardedSigner:
    """Proxy around a signer: gates sign_typed_data, passes everything else through."""

    def __init__(self, signer: Any, enforcer: "PaySafeEnforcer"):
        object.__setattr__(self, "_paysafe_signer", signer)
        object.__setattr__(self, "_paysafe_enforcer", enforcer)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_paysafe_signer"), name)

    def sign_typed_data(self, *args: Any, **kwargs: Any) -> Any:
        signer = object.__getattribute__(self, "_paysafe_signer")
        enforcer: PaySafeEnforcer = object.__getattribute__(self, "_paysafe_enforcer")
        td = _typed_data_from_call(args, kwargs)
        payment = payment_from_typed_data(td) if td is not None else None
        if payment is None:
            if enforcer.strict_types:
                primary = (td or {}).get("primaryType") if isinstance(td, dict) else None
                raise PaySafeEnforcementError(
                    f"strict_types: refusing to sign unrecognized typed data (primaryType {primary or 'unknown'})",
                    primary_type=primary,
                )
            return signer.sign_typed_data(*args, **kwargs)
        primary = (td or {}).get("primaryType") if isinstance(td, dict) else None
        enforcer.assert_approved(compute_payment_commitment(payment), primary)
        return signer.sign_typed_data(*args, **kwargs)


class PaySafeEnforcer:
    """Local, fail-closed signing authority backed by PaySafe allow-verdicts."""

    def __init__(
        self,
        trusted_key_hex: str,
        allow_flagged: bool = False,
        accept_overrides: bool = False,
        max_age_s: Optional[float] = None,
        reusable: bool = False,
        strict_types: bool = False,
    ):
        if not trusted_key_hex:
            raise PaySafeEnforcementError(
                "trusted_key_hex is required: pin the PaySafe verdict key "
                "(GET /.well-known/paysafe-verdict-key) — enforcement must never "
                "trust a key embedded in a response."
            )
        self.trusted_key_hex = trusted_key_hex
        self.allow_flagged = allow_flagged
        # OPT-IN: an agent that holds its own API key can point the approval
        # webhook at itself and "approve" its own flags; human-approved
        # "override:allow" verdicts are only trustworthy when the webhook
        # receiver is out of the agent's reach.
        self.accept_overrides = accept_overrides
        self.max_age_s = max_age_s
        self.reusable = reusable
        self.strict_types = strict_types
        self._approvals: Dict[str, _Approval] = {}

    def approve(self, scan: Dict[str, Any], payment: Dict[str, Any]) -> str:
        """Register a scan verdict as signing authority for its payment.

        Verifies the attestation against the PINNED key (signature, field
        match, commitment, expiry — raises AttestationError on any failure),
        then requires an allow verdict (or flag with allow_flagged). Returns
        the payment commitment.
        """
        verify_attestation(scan, payment, self.trusted_key_hex)
        verdict = scan.get("verdict")
        acceptable = (
            verdict == "allow"
            or (verdict == "flag" and self.allow_flagged)
            or (verdict == "override:allow" and self.accept_overrides)
        )
        if not acceptable:
            if verdict == "flag":
                hint = " (set allow_flagged=True to accept flags)"
            elif verdict == "override:allow":
                hint = " (human-approved overrides require the accept_overrides opt-in - see its security note)"
            else:
                hint = ""
            raise PaySafeEnforcementError(f'refusing to approve a "{verdict}" verdict for signing{hint}')
        commitment = compute_payment_commitment(payment)
        self._approvals[commitment] = _Approval(
            attestation=scan["attestation"], scan_id=scan.get("scan_id", ""), verdict=str(verdict)
        )
        return commitment

    def revoke(self, commitment: str) -> None:
        """Withdraw signing authority for a commitment."""
        self._approvals.pop(commitment, None)

    def clear(self) -> None:
        """Drop all approvals."""
        self._approvals.clear()

    def assert_approved(self, commitment: str, primary_type: Optional[str] = None) -> None:
        """The sign-time gate. Raises PaySafeEnforcementError unless a live,
        unexpired (and unused, unless reusable) approval exists for this
        commitment; consumes it on success."""
        approval = self._approvals.get(commitment)
        if approval is None:
            raise PaySafeEnforcementError(
                f"no PaySafe allow-verdict for this payment authorization (commitment {commitment[:16]}…). "
                "Scan the payment and call enforcer.approve(scan, payment) first. If the payment was scanned, "
                "its recipient/amount/asset/chain/nonce differs from what is now being signed — which is "
                "exactly what this gate exists to catch.",
                commitment=commitment,
                primary_type=primary_type,
            )
        if approval.used and not self.reusable:
            raise PaySafeEnforcementError(
                f"this allow-verdict was already used to sign once (scan {approval.scan_id}); "
                "approvals are single-use. Re-scan to sign again.",
                commitment=commitment,
                primary_type=primary_type,
            )
        expires_ms = _parse_iso_ms(approval.attestation["expires_at"])
        stale_ms = (approval.approved_at + self.max_age_s) * 1000 if self.max_age_s is not None else float("inf")
        deadline_ms = min(expires_ms, stale_ms)
        if time.time() * 1000 >= deadline_ms:
            del self._approvals[commitment]
            raise PaySafeEnforcementError(
                f"the allow-verdict for this payment is stale (scan {approval.scan_id}). "
                "Re-scan to obtain a fresh verdict.",
                commitment=commitment,
                primary_type=primary_type,
            )
        approval.used = True

    def guard_signer(self, signer: Any) -> Any:
        """Wrap a signer so sign_typed_data refuses x402/EIP-3009/Permit payment
        authorizations that lack a live approval. Every other attribute and
        method of the signer passes through untouched, so the wrapped signer
        is a drop-in replacement.

        Scope: this guards the typed-data path x402 uses. If your signer
        exposes other fund-moving paths (sign_transaction), gate those at your
        policy layer too.
        """
        return _GuardedSigner(signer, self)

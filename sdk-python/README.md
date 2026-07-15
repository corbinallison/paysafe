# paysafe-x402 (Python)

Official Python SDK for [PaySafe](https://paysafe-agent.com) — the payment security firewall for [x402](https://x402.org) micropayments. One call before your agent settles a payment; allow/flag/block comes back with machine-readable reasons.

Python 3.9+. Single dependency (`cryptography`, for Ed25519 attestation verification).

```bash
pip install paysafe-x402
```

## 30 seconds

```python
from paysafe_x402 import PaySafeClient, PaySafeBlockedError

paysafe = PaySafeClient(agent_id="my-agent")  # mints a free API key on first use (100 free scans)

try:
    paysafe.guard_outgoing(payment, expected_price_usd=0.01)
    # verdict was allow (or flag) — safe to hand to your wallet
except PaySafeBlockedError as e:
    print("Payment blocked:", e.scan["checks"])  # machine-readable reasons
```

## The important part: provenance tagging

PaySafe's strongest detector catches **payments triggered by prompt-injected content** — but it needs to know where your agent's decision came from. Tell it:

```python
# After EVERY tool result / fetched page your agent reads:
paysafe.observe(tool_result_text, source_url="https://api.example.com/page")

# The next scan (within 5 min) is automatically tagged:
#   context.origin = "fetched_content" | "tool_result"
#   context.content = the observed text (truncated to 8 KB)
# If the pay-to address turns out to have COME FROM that content -> block.

# When the decision is the agent's own plan, or a human said so:
paysafe.note_planning()
paysafe.note_user_instruction()
```

Each observation is consumed by one scan; unrelated later scans aren't mislabeled. LangChain/CrewAI users: call `observe()` in your tool-output callback and `guard_outgoing()` in your payment tool — two lines total.

## Verified verdicts (on by default)

Every scan response carries an Ed25519 attestation binding the verdict to the exact payment. The SDK pins the server's verdict key (fetched once, or pass `verdict_key_hex` to hard-pin), verifies the signature **against the pinned key**, recomputes the payment commitment `sha256(network|pay_to|asset|amount|nonce)` locally (rejecting attestations issued for a *different* payment — replay defense), and enforces expiry. Any failure raises `AttestationError`.

The verifier is cross-validated in CI against attestations signed by the production Node signer, so Python and TypeScript agree byte-for-byte.

Wallet authors: `verify_attestation(scan, payment, trusted_key_hex)` and `compute_payment_commitment(payment)` are importable standalone.

## Paying for scans and plans (x402)

Your first 100 calls per key are free. Beyond that, pass a payment-capable `transport` — any callable `(method, url, headers, body_bytes) -> (status, headers, body_bytes)` that settles x402 challenges (e.g. wrapping an x402 Python client):

```python
paysafe = PaySafeClient(agent_id="my-agent", transport=my_x402_transport, auto_renew=True)

paysafe.get_plans()        # free catalog: Starter / Pro ($4.99/30d, $0.005/scan) / Scale ($19.99/30d, $0.002/scan)
paysafe.subscribe("pro")   # pays $4.99 over x402, upgrades this key for 30 days
```

Plans raise *your own* velocity/spend thresholds and cut per-scan price. Replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier — no plan can relax them.

## Reputation

```python
paysafe.report("0xbad...", "non_delivery", "paid, no data")  # always free
paysafe.reputation("0xsomeone...")                           # report summary (paid / free-tier)
```

## API surface

`PaySafeClient` — `scan_outgoing`, `scan_incoming`, `guard_outgoing`, `guard_incoming`, `observe`, `note_planning`, `note_user_instruction`, `get_plans`, `subscribe`, `report`, `reputation`, `ensure_api_key`, `verdict_key`, plus `free_calls_remaining` / `plan` state.
Standalone — `verify_attestation`, `compute_payment_commitment`.
Errors — `PaySafeError` (`.status`, `.body`), `PaySafeBlockedError` (`.scan`), `AttestationError`.

MIT. PaySafe is advisory and non-custodial: this SDK never touches your keys, wallet, or funds.

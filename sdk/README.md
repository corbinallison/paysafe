# paysafe-x402-client

Official TypeScript/Node SDK for [PaySafe](https://paysafe-agent.com) — the payment security firewall for [x402](https://x402.org) micropayments. One call before your agent settles a payment; allow/flag/block comes back with machine-readable reasons.

Zero runtime dependencies. Node 18+.

```bash
npm install paysafe-x402-client
```

## 30 seconds

```ts
import { PaySafeClient, PaySafeBlockedError } from "paysafe-x402-client";

const paysafe = new PaySafeClient({ agentId: "my-agent" }); // mints a free API key on first use (100 free scans)

try {
  await paysafe.guardOutgoing(payment, { expectedPriceUsd: 0.01 });
  // verdict was allow (or flag) — safe to hand to your wallet
} catch (e) {
  if (e instanceof PaySafeBlockedError) {
    console.error("Payment blocked:", e.scan.checks); // machine-readable reasons
  } else throw e;
}
```

## The important part: provenance tagging

PaySafe's strongest detector catches **payments triggered by prompt-injected content** — but it needs to know where your agent's decision came from. Tell it:

```ts
// After EVERY tool result / fetched page your agent reads:
paysafe.observe(toolResultText, { sourceUrl: "https://api.example.com/page" });

// The next scan (within 5 min) is automatically tagged:
//   context.origin = "fetched_content" | "tool_result"
//   context.content = the observed text (truncated to 8 KB)
// If the pay-to address turns out to have COME FROM that content → block.

// When the decision is the agent's own plan or a human said so:
paysafe.notePlanning();
paysafe.noteUserInstruction();
```

Each observation is consumed by one scan; unrelated later scans aren't mislabeled.

## Verified verdicts (on by default)

Every scan response carries an Ed25519 attestation binding the verdict to the exact payment. The SDK:

1. pins the server's verdict key (fetched once from `/.well-known/paysafe-verdict-key`, or supply `verdictKeyHex` to hard-pin),
2. verifies the signature **against the pinned key** — never the key embedded in the response,
3. recomputes the payment commitment `sha256(network|pay_to|asset|amount|nonce)` locally and rejects attestations issued for a *different* payment (replay defense),
4. enforces `expires_at`.

Any failure throws `AttestationError`. Wallet authors: `verifyAttestation(scan, payment, trustedKeyHex)` and `computePaymentCommitment(payment)` are exported standalone, so a wallet policy can require a fresh, payment-bound allow-verdict before signing — turning the firewall from advisory into enforceable.

## Enforcement: a wallet that refuses unscanned payments

Everything above is advisory — a compromised agent can skip the scan. The enforcement kit closes that gap at the signing layer:

```ts
import { PaySafeClient, PaySafeEnforcer } from "paysafe-x402-client";
import { privateKeyToAccount } from "viem/accounts";

const paysafe  = new PaySafeClient({ agentId: "my-agent" });
const enforcer = new PaySafeEnforcer({ trustedKeyHex: await paysafe.verdictKey() });
const account  = enforcer.guardSigner(privateKeyToAccount(process.env.EVM_PRIVATE_KEY!));
// hand `account` to your x402 client exactly as before — it is a drop-in Proxy

const scan = await paysafe.guardOutgoing(payment);  // throws on block
enforcer.approve(scan, payment);                    // registers the allow-verdict locally
// x402 pay-and-retry now succeeds. ANY other payment authorization the wallet
// is asked to sign — different recipient, amount, asset, chain, or nonce —
// throws PaySafeEnforcementError before the signature exists.
```

How the binding works: the wrapped signer intercepts EIP-712 payment authorizations (EIP-3009 `TransferWithAuthorization`/`ReceiveWithAuthorization` — the x402 "exact" scheme — plus ERC-2612 `Permit`; both viem's single-argument and ethers v6's `(domain, types, message)` call shapes), reconstructs the payment from the typed data itself, and recomputes the commitment `sha256(network|pay_to|asset|amount|nonce)`. Only a live approval for **exactly that commitment** lets the signature happen — so "scan payment A, sign payment B" fails structurally, not by convention.

Guarantees and options: approvals are verified against the **pinned** verdict key at `approve()` time (tampered/replayed/expired attestations throw), are **single-use** by default (`reusable: true` to opt out), expire with the attestation (tighten with `maxAgeMs`), gate on allow-only verdicts (`allowFlagged: true` to accept flags), and can be `revoke()`d. Unrecognized typed data passes through by default; `strictTypes: true` makes the signer deny-by-default. Enforcement is fully local and fail-closed — if PaySafe is unreachable, nothing new can be approved.

Scope note: this guards the typed-data path x402 uses. If your signer also exposes raw `signTransaction`, gate that at your policy layer too.

## Paying for scans and plans (x402)

Your first 100 calls per key are free. Beyond that, construct the client with an x402 payment-capable fetch and everything—scans and plan purchases—pays for itself:

```ts
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const x402 = new x402Client();
registerExactEvmScheme(x402, { signer: privateKeyToAccount(process.env.EVM_PRIVATE_KEY) });

const paysafe = new PaySafeClient({
  agentId: "my-agent",
  fetch: wrapFetchWithPayment(fetch, x402),
  autoRenew: true, // re-subscribe automatically near plan expiry (spends money — opt-in)
});

await paysafe.getPlans();        // free catalog: Starter / Pro ($4.99/30d, $0.005/scan) / Scale ($19.99/30d, $0.002/scan)
await paysafe.subscribe("pro");  // pays $4.99 over x402, upgrades this key for 30 days
```

Plans raise *your own* velocity/spend thresholds and cut per-scan price. Replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier — no plan can relax them.

## Reputation

```ts
await paysafe.report({ address: "0xbad…", category: "non_delivery", reason: "paid, no data" }); // always free
await paysafe.reputation("0xsomeone…"); // report summary (paid / free-tier)
```

## API surface

`PaySafeClient` — `scanOutgoing`, `scanIncoming`, `guardOutgoing`, `guardIncoming`, `observe`, `notePlanning`, `noteUserInstruction`, `getPlans`, `subscribe`, `report`, `reputation`, `ensureApiKey`, `verdictKey`, plus `freeCallsRemaining` / `plan` state.
Enforcement — `PaySafeEnforcer` (`approve`, `guardSigner`, `assertApproved`, `revoke`, `clear`), `paymentFromTypedData`.
Standalone — `verifyAttestation`, `computePaymentCommitment`.
Errors — `PaySafeError` (`.status`, `.body`), `PaySafeBlockedError` (`.scan`), `AttestationError`, `PaySafeEnforcementError` (`.commitment`, `.primaryType`).

MIT. PaySafe is advisory and non-custodial: this SDK never touches your keys, wallet, or funds.

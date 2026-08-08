# @tollwarden/ai-sdk

[Tollwarden](https://tollwarden.com) payment security for the [Vercel AI SDK](https://sdk.vercel.ai) — agents inherit "scan before you pay" by default.

```bash
npm install @tollwarden/ai-sdk
```

## Two additions

```ts
import { generateText } from "ai";
import { TollwardenClient } from "@tollwarden/client";
import { tollwardenTools, tollwardenProvenance } from "@tollwarden/ai-sdk";

const tollwarden = new TollwardenClient({ agentId: "my-agent" }); // free API key auto-minted (100 free scans)

await generateText({
  model,
  tools: { ...tollwardenTools(tollwarden), ...yourOtherTools },
  onStepFinish: tollwardenProvenance(tollwarden),   // ← the important line
  prompt: "...",
});
```

Every x402 payment the agent scans gets an **allow / flag / block** verdict with machine-readable reasons: prompt-injection-triggered payments, replayed nonces, overpayment vs the quote, secrets/PII leaking in payment metadata, lookalike-token contracts, address poisoning, and counterparty reputation.

## Why `tollwardenProvenance` is the important line

Tollwarden's strongest detector catches payments whose *decision* came from content the agent just read — a prompt-injected page or tool result that says "send payment to 0x…". That check needs to know what the agent read. `tollwardenProvenance` is an `onStepFinish` handler that observes every tool result automatically, so the very next scan is provenance-tagged and the injection check runs with real input. No prompt engineering, no developer learning what "provenance" means. (Tollwarden's own tool results are excluded, so verdicts never pollute the signal.)

The AI SDK hands `onStepFinish` the full set of `toolResults` for each step, so a single line wires the whole loop — no per-tool wrapping. Works the same under `streamText` (`onStepFinish`) and agent loops.

## Enforcement: payments that *can't* execute when blocked

Tools rely on the model choosing to scan. `guardedPayment` doesn't:

```ts
import { guardedPayment } from "@tollwarden/ai-sdk";

const safePay = guardedPayment(executeX402Payment, tollwarden);   // { strict: true } to refuse flags too
const { result } = await safePay(payment, expectedPriceUsd);
// on a block verdict it throws TollwardenBlockedError BEFORE executeX402Payment is ever invoked.
```

For wallet-level enforcement (the signer itself refuses unscanned payments), see `wrapFetchWithTollwarden` and `TollwardenEnforcer` in the [@tollwarden/client SDK](https://www.npmjs.com/package/@tollwarden/client).

## The toolset

| Tool | When the agent is told to use it |
|---|---|
| `tollwarden_scan_payment` | ALWAYS, immediately before settling any x402 payment (or before paying a received 402 offer with `direction: "incoming"`) |
| `tollwarden_check_reputation` | Before dealing with an unfamiliar counterparty address |
| `tollwarden_report_counterparty` | After a bad payment experience (always free) — warns other agents |

Pass external content the agent just read as the `content` field on `tollwarden_scan_payment` to enable prompt-injection detection even without the `onStepFinish` handler. `TOLLWARDEN_TOOL_NAMES` is exported if you need to filter Tollwarden's own tools elsewhere.

Verdicts are Ed25519-signed and payment-bound; the underlying client verifies them against a pinned key automatically.

MIT. Tollwarden is advisory and non-custodial: it never touches keys, wallets, or funds.

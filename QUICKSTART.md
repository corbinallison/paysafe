# Protect your x402 agent in 5 minutes

Agents that pay for things over [x402](https://x402.org) get drained in predictable ways: a poisoned webpage tells the agent to pay an attacker's address, a captured payment authorization gets replayed, a "$0.01" API quietly charges $0.15, a seller takes the money and never ships. [Tollwarden](https://tollwarden.com) is a payment firewall that catches all of it — advisory, non-custodial, and wrapped around whatever wallet and facilitator you already use. Here's the whole integration, timed.

## Minute 1 — install

```bash
npm install @tollwarden/client    # TypeScript / Node
pip install tollwarden           # Python
```

No signup. The first call mints you a free API key automatically (100 free scans).

## Minute 2 — the one-line version

If your agent pays through the standard x402 buyer flow, wrap the paying fetch and you're done:

```ts
import { wrapFetchWithPayment } from "@x402/fetch";
import { TollwardenClient, wrapFetchWithTollwarden } from "@tollwarden/client";

const tollwarden = new TollwardenClient({ agentId: "my-agent" });
const fetchWithPay = wrapFetchWithTollwarden(wrapFetchWithPayment(fetch, x402Client), tollwarden);
```

Python:

```python
from tollwarden import TollwardenClient, wrap_transport_with_tollwarden

tollwarden = TollwardenClient(agent_id="my-agent")
guarded = wrap_transport_with_tollwarden(my_x402_transport, tollwarden)
```

Every payment now gets scanned **before it settles** — a block verdict throws before any payment is signed — and after settlement the wrapper automatically records whether the seller actually delivered, building the shared history that flags never-shipping sellers for everyone.

## Minute 3 — feed the injection detector

Tollwarden's strongest check catches payments whose *decision* came from content your agent just read — the prompt-injected page that says "send payment to 0x… now". It needs to know what the agent read. One line, right after any web fetch or tool call:

```ts
tollwarden.observe(pageOrToolText, { sourceUrl });
```

```python
tollwarden.observe(page_or_tool_text, source_url=url)
```

That's it — the next scan is provenance-tagged and the injection check runs with real input. If the pay-to address appears in content the agent just read, the payment blocks.

## Minute 4 — see it work

```ts
const scan = await tollwarden.scanOutgoing({
  network: "eip155:8453",
  pay_to: "0xMerchant...",
  amount: "10000",          // $0.01 USDC
  nonce: "0xabc123",
  resource_url: "https://api.example.com/data",
});
```

A clean payment returns `verdict: "allow"` with an Ed25519-signed attestation. Here's a replayed authorization getting caught:

```json
{
  "verdict": "block",
  "risk_score": 95,
  "checks": [{
    "id": "replay.nonce_reuse",
    "verdict": "block",
    "severity": "critical",
    "reason": "Nonce reuse detected: this nonce was first seen 2026-07-14T09:32:50Z and has now appeared 2 times. A reused nonce means a stale or captured payment authorization is being replayed."
  }],
  "advisory": "Recommended action: DO NOT settle this payment. ..."
}
```

Machine-readable reasons, so your agent can act on them — not just a score.

## Minute 5 — or skip all of the above if you're on a framework

Already building on an agent framework? One package gives your agent the tools *and* wires the provenance tagging automatically:

**LangChain / LangGraph** (`pip install langchain-tollwarden`):

```python
from langchain_tollwarden import tollwarden_tools, TollwardenProvenanceCallback

agent = create_agent(model, tools=[*tollwarden_tools(tollwarden), *your_tools],
                     callbacks=[TollwardenProvenanceCallback(tollwarden)])
```

**CrewAI** (`pip install crewai-tollwarden`):

```python
from crewai_tollwarden import tollwarden_tools, register_tollwarden_provenance

register_tollwarden_provenance(tollwarden)   # once at startup
agent = Agent(role="Purchasing agent", tools=tollwarden_tools(tollwarden), ...)
```

**Vercel AI SDK** (`npm install @tollwarden/ai-sdk`):

```ts
import { tollwardenTools, tollwardenProvenance } from "@tollwarden/ai-sdk";

await generateText({
  model,
  tools: { ...tollwardenTools(tollwarden), ...yourTools },
  onStepFinish: tollwardenProvenance(tollwarden),   // auto-tags every tool result
  prompt: "...",
});
```

**Coinbase AgentKit** (`pip install agentkit-tollwarden`): add `tollwarden_action_provider()` to your providers — scans auto-fill the payer from the agent's wallet. **NeMo Agent Toolkit** (`pip install nemo-tollwarden`): three config-driven functions via the `nat.plugins` entry point. **Claude / MCP agents**: zero code —

```jsonc
{ "mcpServers": { "tollwarden": { "command": "npx", "args": ["-y", "tollwarden"] } } }
```

## Leveling up (when you're ready)

- **Make blocks physically unsignable.** The enforcement kit wraps your signer so it refuses any x402 authorization without a fresh, payment-bound allow-verdict: `enforcer.guardSigner(account)` (viem/ethers) or `enforcer.guard_signer(account)` (eth-account). A compromised agent that skips scanning simply cannot sign.
- **Put a human between flag and block.** `POST /v1/approvals/config` with a webhook: every flag pauses, your ops channel gets the payment facts and a one-click decide link, and approval mints a ≤5-minute signed override bound to exactly that payment.
- **Key hygiene.** Leaked key? `POST /v1/keys/rotate` — fresh secret, same account, usage and plan carried over; the old secret dies on your schedule.
- **Check any counterparty first**: `GET /v1/reputation/{address}` returns community reports *and* measured delivery rates from commitment-bound outcomes.

Everything is documented for agents too: point any LLM at [tollwarden.com/llms.txt](https://tollwarden.com/llms.txt) and it can wire this up itself. OpenAPI at [/openapi.json](https://tollwarden.com/openapi.json). Source: [github.com/tollwarden/tollwarden](https://github.com/tollwarden/tollwarden) (source-available, BUSL 1.1). Non-custodial — Tollwarden never touches your keys, wallet, or funds.

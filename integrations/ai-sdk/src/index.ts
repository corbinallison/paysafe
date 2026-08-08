/**
 * @tollwarden/ai-sdk — TollWarden payment security for the Vercel AI SDK.
 *
 * Two additions give an AI SDK agent "scan before you pay" by default:
 *
 *   import { generateText } from "ai";
 *   import { TollWardenClient } from "@tollwarden/client";
 *   import { tollwardenTools, tollwardenProvenance } from "@tollwarden/ai-sdk";
 *
 *   const tollwarden = new TollWardenClient({ agentId: "my-agent" }); // free key auto-minted
 *
 *   await generateText({
 *     model,
 *     tools: { ...tollwardenTools(tollwarden), ...yourOtherTools },
 *     onStepFinish: tollwardenProvenance(tollwarden),   // <- the important one
 *     prompt: "...",
 *   });
 *
 * Why tollwardenProvenance is the important line: TollWarden's strongest detector
 * catches payments whose DECISION came from content the agent just read (a
 * prompt-injected page or tool result). It needs to know what the agent read.
 * tollwardenProvenance is an onStepFinish handler that observes every tool result
 * automatically — so the next scan is provenance-tagged and the injection
 * check runs. TollWarden's own tool results are skipped so verdicts don't pollute
 * the signal.
 *
 * To make payments that CANNOT execute when blocked, wrap the executor with
 * guardedPayment(). For fetch/transport-level enforcement, see
 * wrapFetchWithTollWarden and TollWardenEnforcer in @tollwarden/client.
 *
 * TollWarden is advisory and non-custodial — it never touches keys, wallets, or funds.
 */
import { tool } from "ai";
import { z } from "zod";
import {
  TollWardenBlockedError,
  type TollWardenClient,
  type PaymentDetails,
  type ScanResponse,
} from "@tollwarden/client";

export const TOLLWARDEN_TOOL_NAMES = [
  "tollwarden_scan_payment",
  "tollwarden_check_reputation",
  "tollwarden_report_counterparty",
] as const;

const SCAN_DESCRIPTION =
  "ALWAYS call this immediately BEFORE settling or sending any x402 payment " +
  "(direction='outgoing'), or BEFORE paying a 402 offer you received " +
  "(direction='incoming'). Returns allow (proceed) / flag (pause and confirm) / " +
  "block (do NOT pay) with machine-readable reasons and a signed verdict. If the " +
  "decision to pay followed reading external content, pass that text as `content` " +
  "to enable prompt-injection-triggered-payment detection. Also catches replayed " +
  "nonces, overpayment, secrets in payment metadata, lookalike tokens, and address " +
  "poisoning. Advisory and non-custodial.";

/**
 * The TollWarden toolset for the AI SDK: scan / check reputation / report,
 * imperatively described so the model calls them at the right moments.
 */
export function tollwardenTools(client: TollWardenClient) {
  return {
    tollwarden_scan_payment: tool({
      description: SCAN_DESCRIPTION,
      inputSchema: z.object({
        payment: z
          .record(z.string(), z.any())
          .describe("The x402 payment object (network, asset, amount, pay_to, resource_url, nonce, ...)"),
        direction: z
          .enum(["outgoing", "incoming"])
          .optional()
          .describe("'outgoing' before you settle; 'incoming' before you pay a received 402 offer"),
        expected_price_usd: z.number().optional().describe("What you expected this to cost, in USD"),
        content: z
          .string()
          .optional()
          .describe("The page or tool text the agent just read before deciding to pay — enables injection detection"),
      }),
      execute: async ({
        payment,
        direction,
        expected_price_usd,
        content,
      }: {
        payment: PaymentDetails;
        direction?: "outgoing" | "incoming";
        expected_price_usd?: number;
        content?: string;
      }): Promise<ScanResponse> => {
        const context = content ? { origin: "tool_result" as const, content } : undefined;
        const scan =
          direction === "incoming"
            ? await client.scanIncoming(payment, { expectedPriceUsd: expected_price_usd, context })
            : await client.scanOutgoing(payment, { expectedPriceUsd: expected_price_usd, context });
        return scan;
      },
    }),

    tollwarden_check_reputation: tool({
      description:
        "Check whether a counterparty wallet address has been reported by other agents BEFORE " +
        "dealing with it — scam, non-delivery, prompt injection, overcharge, impersonation, replay " +
        "abuse. Returns report counts and a risk level.",
      inputSchema: z.object({
        address: z.string().describe("Counterparty wallet address to look up"),
      }),
      execute: async ({ address }: { address: string }) => client.reputation(address),
    }),

    tollwarden_report_counterparty: tool({
      description:
        "Call this after a bad payment experience (paid and got nothing, scammed, overcharged, " +
        "injection attempt) to warn other agents — always free. Categories: scam, non_delivery, " +
        "prompt_injection, overcharge, impersonation, replay_abuse, other.",
      inputSchema: z.object({
        address: z.string(),
        category: z.string().describe("scam | non_delivery | prompt_injection | overcharge | impersonation | replay_abuse | other"),
        reason: z.string().describe("What happened (>= 10 chars)"),
      }),
      execute: async ({ address, category, reason }: { address: string; category: string; reason: string }) =>
        client.report({ address, category, reason }),
    }),
  };
}

interface StepLike {
  toolResults?: Array<{ toolName?: string; output?: unknown; result?: unknown }>;
}

/**
 * An onStepFinish (or onStepEnd) handler that auto-tags provenance: it observes
 * every tool result the agent produced — except TollWarden's own — so the next
 * scan knows what the agent read. This is what powers
 * prompt-injection-triggered-payment detection.
 */
export function tollwardenProvenance(client: TollWardenClient, opts: { maxChars?: number } = {}) {
  const maxChars = opts.maxChars ?? 8192;
  return (step: StepLike): void => {
    for (const tr of step?.toolResults ?? []) {
      if (tr?.toolName && (TOLLWARDEN_TOOL_NAMES as readonly string[]).includes(tr.toolName)) continue;
      const out = tr?.output ?? tr?.result;
      if (out == null) continue;
      const text = typeof out === "string" ? out : JSON.stringify(out);
      if (text) client.observe(text.slice(0, maxChars), { kind: "tool_result" });
    }
  };
}

/**
 * Wrap a payment executor so it scans BEFORE paying and refuses blocks. On a
 * block verdict (or flag when strict) it throws TollWardenBlockedError and the
 * executor is NEVER called — enforcement by construction, not by prompt.
 */
export function guardedPayment<T>(
  payFn: (payment: PaymentDetails) => Promise<T> | T,
  client: TollWardenClient,
  opts: { strict?: boolean } = {},
) {
  const strict = opts.strict ?? false;
  return async (
    payment: PaymentDetails,
    expectedPriceUsd?: number,
  ): Promise<{ paid: true; verdict: string; scan_id: string; result: T }> => {
    const scan = await client.guardOutgoing(payment, { strict, expectedPriceUsd });
    const result = await payFn(payment);
    return { paid: true, verdict: scan.verdict, scan_id: scan.scan_id, result };
  };
}

export { TollWardenBlockedError };

/**
 * Prompt-injection-triggered payment detection.
 *
 * Fast tier (always runs, ~sub-ms):
 *  1. Provenance — payments whose decision originated from content the agent
 *     just read (tool result / fetched page) rather than its own planning step.
 *  2. Injection tells in the just-read content.
 *  3. Address provenance — pay_to appearing verbatim in that content.
 *
 * Deep tier (runs above the micropayment threshold, still ~1ms):
 *  4. Base64-obfuscated payloads decoded and rescanned.
 *  5. Unicode-normalization rescan (homoglyph / zero-width obfuscation).
 */
import type { CheckResult, PaymentDetails, ScanContext } from "../types.ts";

const INJECTION_TELLS: Array<{ id: string; re: RegExp; label: string }> = [
  { id: "override", re: /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|your)\s+(?:instructions?|prompts?|rules?|guidance)\b/i, label: "instruction-override phrasing" },
  { id: "new_instructions", re: /\b(?:new|updated|real|actual|true)\s+instructions?\s*[:>-]/i, label: "injected replacement instructions" },
  { id: "pay_command", re: /\b(?:you\s+(?:must|should|need\s+to|are\s+required\s+to)|be\s+sure\s+to|immediately)\s+(?:pay|send|transfer|authorize)\b/i, label: "imperative payment command" },
  { id: "send_to_address", re: /\b(?:send|pay|transfer)\b[^.\n]{0,80}\b(?:to|at)\s+(?:0x[0-9a-fA-F]{6,}|[1-9A-HJ-NP-Za-km-z]{32,44})/, label: "payment redirection to embedded address" },
  { id: "secrecy", re: /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|mention\s+(?:this\s+)?to)\s+(?:the\s+)?(?:user|human|owner|operator)\b/i, label: "concealment instruction" },
  { id: "role_marker", re: /(?:<\/?(?:system|assistant|instructions?)>|\[(?:system|SYSTEM)\]|^system\s*:)/m, label: "spoofed role/system marker" },
  { id: "urgency", re: /\b(?:urgent(?:ly)?|final\s+(?:warning|notice)|account\s+(?:will\s+be\s+)?(?:suspended|terminated)|within\s+\d+\s+(?:minutes?|hours?)\s+or)\b/i, label: "urgency/threat pressure" },
  { id: "invisible_chars", re: /[​‌‍⁠﻿­]/, label: "invisible/zero-width characters (hidden text)" },
];

/** Scan a string for injection indicators. Exported for the deep tier and tests. */
export function findTells(text: string): Array<{ id: string; label: string }> {
  return INJECTION_TELLS.filter((t) => t.re.test(text)).map(({ id, label }) => ({ id, label }));
}

export function checkInjection(
  payment: PaymentDetails,
  context: ScanContext | undefined,
): CheckResult[] {
  const results: CheckResult[] = [];
  const origin = context?.origin ?? "unknown";
  const content = context?.content ?? "";
  const fromUntrusted = origin === "tool_result" || origin === "fetched_content";

  // 1. Provenance: did the decision to pay come from content the agent just read?
  if (fromUntrusted) {
    results.push({
      id: "injection.untrusted_origin",
      name: "Prompt-injection-triggered payment",
      verdict: "flag",
      severity: "medium",
      reason: `This payment originated from ${origin === "tool_result" ? "a tool result" : "fetched external content"} rather than the agent's own planning step. Payments prompted by just-read content are the primary prompt-injection exfiltration path — confirm against the agent's plan before settling.`,
      details: { origin, content_source_url: context?.content_source_url },
    });
  } else if (origin === "unknown") {
    results.push({
      id: "injection.unknown_origin",
      name: "Prompt-injection-triggered payment",
      verdict: "flag",
      severity: "low",
      reason:
        "Payment origin not declared. Pass context.origin (planning | user_instruction | tool_result | fetched_content) so provenance can be verified.",
    });
  }

  if (content) {
    // 2. Injection tells inside the content the agent just read.
    const hits = findTells(content);
    if (hits.length > 0) {
      const escalate = fromUntrusted || hits.length >= 2;
      results.push({
        id: "injection.content_tells",
        name: "Prompt-injection-triggered payment",
        verdict: escalate ? "block" : "flag",
        severity: escalate ? "critical" : "medium",
        reason: `The content preceding this payment contains prompt-injection indicators: ${hits.map((h) => h.label).join("; ")}.`,
        details: { indicators: hits.map((h) => h.id), origin },
      });
    }

    // 3. Address provenance: the pay_to address literally appears in untrusted content.
    if (payment.pay_to && content.toLowerCase().includes(payment.pay_to.toLowerCase())) {
      results.push({
        id: "injection.payto_from_content",
        name: "Prompt-injection-triggered payment",
        verdict: fromUntrusted ? "block" : "flag",
        severity: fromUntrusted ? "critical" : "high",
        reason:
          "The payment recipient address appears verbatim in the content the agent just read. Recipient addresses sourced from untrusted content are the classic payment-redirection attack.",
        details: { pay_to: payment.pay_to, origin },
      });
    }
  }

  if (results.length === 0) {
    results.push({
      id: "injection.clean",
      name: "Prompt-injection-triggered payment",
      verdict: "allow",
      severity: "info",
      reason: `Payment originated from ${origin.replace("_", " ")}; no injection indicators found.`,
    });
  }
  return results;
}

const PRINTABLE = /^[\x09\x0a\x0d\x20-\x7e]+$/;
const ZERO_WIDTH = /[​‌‍⁠﻿­]/g;

/**
 * Deep content-analysis tier. Decodes base64 blobs and unicode-normalizes the
 * content, then rescans — defeats the two cheapest obfuscations of the fast
 * tier. Still regex-speed; gated by the micropayment bypass policy because
 * obfuscated attacks target payments worth stealing.
 */
export function deepContentAnalysis(
  payment: PaymentDetails,
  context: ScanContext | undefined,
): CheckResult[] {
  const content = context?.content ?? "";
  if (!content) return [];
  const results: CheckResult[] = [];
  const origin = context?.origin ?? "unknown";
  const fromUntrusted = origin === "tool_result" || origin === "fetched_content";

  // 4. Base64-obfuscated payloads.
  const blobs = content.match(/[A-Za-z0-9+/]{24,}={0,2}/g) ?? [];
  for (const blob of blobs.slice(0, 20)) {
    let decoded: string;
    try {
      decoded = Buffer.from(blob, "base64").toString("utf8");
    } catch {
      continue;
    }
    if (!PRINTABLE.test(decoded)) continue; // decode noise, not text
    const tells = findTells(decoded);
    const embedsPayTo =
      payment.pay_to !== undefined && decoded.toLowerCase().includes(payment.pay_to.toLowerCase());
    if (tells.length > 0 || embedsPayTo) {
      results.push({
        id: "injection.b64_obfuscated",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: fromUntrusted || embedsPayTo ? "block" : "flag",
        severity: "critical",
        reason: `A base64 blob in the just-read content decodes to ${embedsPayTo ? "text embedding the payment recipient address" : "prompt-injection content"}${tells.length ? ` (${tells.map((t) => t.label).join("; ")})` : ""}. Encoding instructions to evade filters is itself a strong attack signal.`,
        details: { decoded_preview: decoded.slice(0, 120), indicators: tells.map((t) => t.id) },
      });
      break; // one finding is enough
    }
  }

  // 5. Unicode-obfuscated tells: strip zero-width chars + NFKC-normalize, rescan.
  const normalized = content.normalize("NFKC").replace(ZERO_WIDTH, "");
  if (normalized !== content) {
    const rawTells = findTells(content).filter((t) => t.id !== "invisible_chars").length;
    const normTells = findTells(normalized);
    if (normTells.length > rawTells) {
      results.push({
        id: "injection.unicode_obfuscated",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: fromUntrusted ? "block" : "flag",
        severity: "critical",
        reason: `Injection indicators appear only after unicode normalization (zero-width/homoglyph stripping): ${normTells.map((t) => t.label).join("; ")}. Hidden-character obfuscation is itself a strong attack signal.`,
        details: { indicators: normTells.map((t) => t.id) },
      });
    }
  }

  return results;
}

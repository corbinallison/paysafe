// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * PII / secret detection over payment metadata.
 * Scans resource_url, description, reason, and metadata values BEFORE they leave the agent.
 * Zero dependencies.
 */
import type { CheckResult, PaymentDetails, Severity, Verdict } from "../types.ts";

interface Pattern {
  id: string;
  label: string;
  severity: Severity;
  verdict: Verdict;
  re: RegExp;
  /** Optional post-match validator (e.g. Luhn for credit cards) */
  validate?: (match: string) => boolean;
}

function luhnValid(raw: string): boolean {
  const digits = raw.replace(/[^0-9]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

const PATTERNS: Pattern[] = [
  // ---- secrets: block ----
  {
    id: "evm_private_key",
    label: "EVM private key",
    severity: "critical",
    verdict: "block",
    re: /\b(?:0x)?[0-9a-fA-F]{64}\b/,
  },
  {
    id: "aws_access_key",
    label: "AWS access key ID",
    severity: "critical",
    verdict: "block",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    id: "openai_key",
    label: "OpenAI API key",
    severity: "critical",
    verdict: "block",
    re: /\bsk-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "anthropic_key",
    label: "Anthropic API key",
    severity: "critical",
    verdict: "block",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "github_token",
    label: "GitHub token",
    severity: "critical",
    verdict: "block",
    re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  },
  {
    id: "slack_token",
    label: "Slack token",
    severity: "critical",
    verdict: "block",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  },
  {
    id: "jwt",
    label: "JWT / bearer token",
    severity: "high",
    verdict: "block",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    id: "generic_secret_param",
    label: "credential in URL/query parameter",
    severity: "high",
    verdict: "block",
    re: /[?&](?:api[_-]?key|apikey|token|secret|password|passwd|private[_-]?key|auth)=[^&\s]{6,}/i,
  },
  // ---- PII: block the worst, flag the rest ----
  {
    id: "ssn",
    label: "US Social Security number",
    severity: "high",
    verdict: "block",
    re: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/,
  },
  {
    id: "credit_card",
    label: "payment card number",
    severity: "high",
    verdict: "block",
    re: /\b(?:\d[ -]?){13,19}\b/,
    validate: luhnValid,
  },
  {
    id: "email",
    label: "email address",
    severity: "medium",
    verdict: "flag",
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  },
  {
    id: "phone",
    label: "phone number",
    severity: "medium",
    verdict: "flag",
    re: /(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/,
  },
];

/** Heuristic seed-phrase detector: 12+ consecutive lowercase dictionary-shaped words. */
function looksLikeSeedPhrase(text: string): string | null {
  const m = text.match(/\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/);
  if (!m) return null;
  const words = m[0].trim().split(/\s+/);
  const distinct = new Set(words);
  // Natural sentences repeat stop-words heavily; mnemonics rarely repeat.
  if (distinct.size >= Math.max(10, Math.floor(words.length * 0.8))) return m[0];
  return null;
}

function redact(s: string): string {
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
}

const SCANNED_FIELDS: Array<keyof PaymentDetails> = [
  "resource_url",
  "description",
  "reason",
];

export function scanPii(payment: PaymentDetails): CheckResult[] {
  const results: CheckResult[] = [];
  const fields: Array<[string, string]> = [];

  for (const f of SCANNED_FIELDS) {
    const v = payment[f];
    if (typeof v === "string" && v.length > 0) fields.push([f, v]);
  }
  for (const [k, v] of Object.entries(payment.metadata ?? {})) {
    if (typeof v === "string" && v.length > 0) fields.push([`metadata.${k}`, v]);
  }

  for (const [field, value] of fields) {
    for (const p of PATTERNS) {
      const m = value.match(p.re);
      if (!m) continue;
      if (p.validate && !p.validate(m[0])) continue;
      results.push({
        id: `pii.${p.id}`,
        name: "PII / secret detection",
        verdict: p.verdict,
        severity: p.severity,
        reason: `Detected ${p.label} in payment field "${field}". This would be transmitted to the counterparty and facilitator.`,
        details: { field, match: redact(m[0]) },
      });
    }
    const seed = looksLikeSeedPhrase(value);
    if (seed) {
      results.push({
        id: "pii.seed_phrase",
        name: "PII / secret detection",
        verdict: "block",
        severity: "critical",
        reason: `Field "${field}" appears to contain a wallet seed phrase (${seed.split(/\s+/).length} dictionary words). Never transmit seed material in payment metadata.`,
        details: { field, match: redact(seed) },
      });
    }
  }

  if (results.length === 0) {
    results.push({
      id: "pii.clean",
      name: "PII / secret detection",
      verdict: "allow",
      severity: "info",
      reason: "No PII or secret material detected in payment metadata.",
    });
  }
  return results;
}

// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Prompt-injection-triggered payment detection.
 *
 * Fast tier (always runs, ~sub-ms):
 *  1. Provenance — payments whose decision originated from content the agent
 *     just read (tool result / fetched page) rather than its own planning step.
 *  2. Injection tells in the just-read content. Tells are weighted (strong
 *     imperative/override phrasing = 2, contextual pressure = 1) and a tell
 *     occurring near an address-like token earns a proximity boost — an
 *     instruction next to an address is far stronger signal than the same
 *     phrase elsewhere in a 200KB page.
 *  3. Address provenance — pay_to appearing in that content, including split
 *     across whitespace or laced with invisible characters (an obfuscated
 *     match is treated as deliberate concealment and blocks outright).
 *     context.offer (the raw 402/discovery payload) is the sanctioned channel
 *     for protocol data: pay_to is EXPECTED there and exempt from #3, but the
 *     offer is still counterparty-authored, so #2's tells scan runs on it.
 *
 * Deep tier (runs above the micropayment threshold; ≲15ms worst case at the
 * 200KB content cap, sub-ms on typical content):
 *  4. Base64-obfuscated payloads decoded and rescanned — standard and URL-safe
 *     alphabets, MIME-style line-wrapped blobs, one level of double-encoding.
 *  5. Other encodings: hex, percent(URL)-encoding, HTML numeric entities.
 *  6. Unicode tag-character smuggling (U+E0020–E007E "invisible ASCII")
 *     decoded and rescanned.
 *  7. Unicode-skeleton rescan: NFKC + invisible-char strip + confusable
 *     (Cyrillic/Greek homoglyph) folding, which NFKC alone does not do.
 */
import type { CheckResult, PaymentDetails, ScanContext } from "../types.ts";

// ---------------------------------------------------------------------------
// Invisible characters & confusables
// ---------------------------------------------------------------------------

// Characters that render as nothing (or nearly nothing) and are used to hide
// text or break up token matching: soft hyphen, Mongolian vowel separator,
// zero-width space/joiners, word joiner + invisible operators, bidi overrides,
// BOM, and the Unicode tag block (invisible ASCII mirror, U+E0000–E007F).
// Variation selectors (FE00–FE0F) are stripped for matching but deliberately
// EXCLUDED from the tell below — every "❤️" carries one.
const TELL_INVISIBLE =
  /[\u00AD\u180E\u200B-\u200D\u2060-\u2064\u202D\u202E\uFEFF\u{E0000}-\u{E007F}]/u;
const STRIP_INVISIBLE_G =
  /[\u00AD\u180E\u200B-\u200D\u2060-\u2064\u202D\u202E\uFE00-\uFE0F\uFEFF\u{E0000}-\u{E007F}]/gu;

/** Remove invisible/zero-width/tag characters. Exported for cross-detector use. */
export function stripInvisible(text: string): string {
  return text.replace(STRIP_INVISIBLE_G, "");
}

// Homoglyphs NFKC does NOT fold: visually-identical Cyrillic/Greek letters
// mapped to their Latin lowercase twins (tell regexes are case-insensitive,
// so folding capitals to lowercase Latin is fine). Curated for visual
// identity — not a full TR39 confusables table.
const CONFUSABLES: Record<string, string> = {
  // Cyrillic lowercase
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w",
  // Cyrillic capitals
  "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o",
  "Р": "p", "С": "c", "Т": "t", "У": "y", "Х": "x", "І": "i", "Ѕ": "s",
  "Ј": "j", "Ԁ": "d", "Ԛ": "q", "Ԝ": "w",
  // Greek lowercase
  "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "υ": "u", "ι": "i",
  "κ": "k", "χ": "x", "ε": "e", "η": "n", "ω": "w", "γ": "y",
  // Greek capitals
  "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k",
  "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
};
const CONFUSABLE_PRESENT = /[\u0370-\u03FF\u0400-\u04FF\u0500-\u052F]/;

/**
 * Skeleton form for rescanning: NFKC-normalize, strip invisible chars, fold
 * confusable homoglyphs to Latin. "іgnоre" (Cyrillic і/о) → "ignore".
 */
export function skeleton(text: string): string {
  let s = text.normalize("NFKC").replace(STRIP_INVISIBLE_G, "");
  if (CONFUSABLE_PRESENT.test(s)) {
    s = [...s].map((c) => CONFUSABLES[c] ?? c).join("");
  }
  return s;
}

// ---------------------------------------------------------------------------
// Injection tells
// ---------------------------------------------------------------------------

interface Tell {
  id: string;
  re: RegExp;
  label: string;
  /** 2 = strong (unambiguous override/redirect phrasing), 1 = contextual pressure. */
  weight: 1 | 2;
}

const INJECTION_TELLS: Tell[] = [
  { id: "override", weight: 2, re: /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|your)\s+(?:instructions?|prompts?|rules?|guidance)\b/i, label: "instruction-override phrasing" },
  // Non-English variants of the same override phrasing (es/fr/de/pt/ru/zh/ja).
  { id: "override_i18n", weight: 2, re: /ignora\s+(?:todas\s+)?las\s+instrucciones\s+anteriores|ignore[zr]?\s+les\s+instructions\s+pr[ée]c[ée]dentes|ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+anweisungen|ignore\s+as\s+instru[çc][õo]es\s+anteriores|игнорируй(?:те)?\s+(?:все\s+)?предыдущие\s+инструкции|忽略(?:之前|以上|所有)的?(?:指令|指示|说明)|以前の指示を無視/i, label: "instruction-override phrasing (non-English)" },
  { id: "new_instructions", weight: 2, re: /\b(?:new|updated|real|actual|true)\s+instructions?\s*[:>-]/i, label: "injected replacement instructions" },
  { id: "pay_command", weight: 1, re: /\b(?:you\s+(?:must|should|need\s+to|are\s+required\s+to)|be\s+sure\s+to|immediately)\s+(?:pay|send|transfer|authorize)\b/i, label: "imperative payment command" },
  // NOT /i: case-insensitivity would loosen the strict base58 class into
  // matching any long alphanumeric token. Verb/preposition case variants
  // (lowercase / Capitalized / ALLCAPS) are spelled out instead.
  { id: "send_to_address", weight: 2, re: /\b(?:[Ss]end|SEND|[Pp]ay|PAY|[Tt]ransfer|TRANSFER)\b[^.\n]{0,80}\b(?:[Tt]o|TO|[Aa]t|AT)\s+(?:0x[0-9a-fA-F]{6,}|[1-9A-HJ-NP-Za-km-z]{32,44})/, label: "payment redirection to embedded address" },
  { id: "secrecy", weight: 2, re: /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|mention\s+(?:this\s+)?to)\s+(?:the\s+)?(?:user|human|owner|operator)\b/i, label: "concealment instruction" },
  { id: "role_marker", weight: 2, re: /(?:<\/?(?:system|assistant|instructions?)>|\[(?:system|SYSTEM)\]|^system\s*:)/m, label: "spoofed role/system marker" },
  { id: "tool_spoof", weight: 1, re: /<\|im_start\|>|<<SYS>>|\[INST\]|"role"\s*:\s*"system"/, label: "spoofed chat-template/tool structure" },
  { id: "persona_swap", weight: 1, re: /\byou\s+are\s+(?:now|no\s+longer)\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|different|new)\b|\bpretend\s+(?:to\s+be|you\s+are)\b/i, label: "persona/role swap instruction" },
  { id: "precedence", weight: 1, re: /\bbefore\s+(?:doing|you\s+do)\s+anything\s+else\b|\b(?:overrides?|supersedes?|takes?\s+(?:priority|precedence))\s+(?:all\s+)?(?:other|previous|prior|any)\b/i, label: "priority/precedence override phrasing" },
  { id: "urgency", weight: 1, re: /\b(?:urgent(?:ly)?|final\s+(?:warning|notice)|account\s+(?:will\s+be\s+)?(?:suspended|terminated)|within\s+\d+\s+(?:minutes?|hours?)\s+or)\b/i, label: "urgency/threat pressure" },
  { id: "invisible_chars", weight: 1, re: TELL_INVISIBLE, label: "invisible/zero-width/tag characters (hidden text)" },
];

export interface TellHit {
  id: string;
  label: string;
  weight: number;
  /** Match offset in the scanned text (for proximity scoring). */
  index: number;
}

/** Scan a string for injection indicators. Exported for the deep tier and tests. */
export function findTells(text: string): TellHit[] {
  const hits: TellHit[] = [];
  for (const t of INJECTION_TELLS) {
    const m = t.re.exec(text);
    if (m) hits.push({ id: t.id, label: t.label, weight: t.weight, index: m.index });
  }
  return hits;
}

const ADDR_TOKEN_G = /0x[0-9a-fA-F]{6,}|[1-9A-HJ-NP-Za-km-z]{32,44}/g;
const PROXIMITY_CHARS = 300;

/**
 * Proximity boost: a tell whose match sits within PROXIMITY_CHARS of an
 * address-like token. send_to_address is excluded — its own match contains
 * the address, so it would always self-trigger the boost.
 */
function proximityToAddress(text: string, hits: TellHit[]): { tell_id: string; distance: number } | null {
  const candidates = hits.filter((h) => h.id !== "send_to_address" && h.id !== "invisible_chars");
  if (candidates.length === 0) return null;
  let best: { tell_id: string; distance: number } | null = null;
  for (const m of text.matchAll(ADDR_TOKEN_G)) {
    for (const h of candidates) {
      const d = Math.abs(h.index - (m.index ?? 0));
      if (d <= PROXIMITY_CHARS && (!best || d < best.distance)) {
        best = { tell_id: h.id, distance: d };
      }
    }
  }
  return best;
}

/**
 * Weighted score with optional proximity boost. The boost only applies to
 * prose content — offers legitimately contain pay_to, so proximity there
 * would self-trigger on every offer.
 */
function scoreTells(
  text: string,
  hits: TellHit[],
  withProximity: boolean,
): { score: number; proximity: { tell_id: string; distance: number } | null } {
  let score = 0;
  for (const h of hits) score += h.weight;
  const proximity = withProximity ? proximityToAddress(text, hits) : null;
  if (proximity) score += 2;
  return { score, proximity };
}

// ---------------------------------------------------------------------------
// Fast tier
// ---------------------------------------------------------------------------

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
    // 2. Injection tells inside the content the agent just read. Weighted:
    // one strong tell (or a weak tell near an address) escalates from an
    // untrusted origin; a score of 3 escalates from any origin. A lone weak
    // tell (e.g. "urgent" in a fetched page) flags rather than blocks.
    const hits = findTells(content);
    if (hits.length > 0) {
      const { score, proximity } = scoreTells(content, hits, true);
      const escalate = (fromUntrusted && score >= 2) || score >= 3;
      results.push({
        id: "injection.content_tells",
        name: "Prompt-injection-triggered payment",
        verdict: escalate ? "block" : "flag",
        severity: escalate ? "critical" : "medium",
        reason:
          `The content preceding this payment contains prompt-injection indicators: ${hits.map((h) => h.label).join("; ")}.` +
          (proximity ? ` The "${proximity.tell_id}" indicator occurs within ${proximity.distance} characters of an address-like token — instructions adjacent to an address are the strongest redirection signal.` : ""),
        details: { indicators: hits.map((h) => h.id), score, proximity, origin },
      });
    }

    // 3. Address provenance: pay_to appears in untrusted content — verbatim,
    // or only after stripping invisible characters and collapsing whitespace
    // (split/laced addresses). An obfuscated match means someone deliberately
    // hid the address from naive scanners: block regardless of origin.
    if (payment.pay_to) {
      const payToLc = payment.pay_to.toLowerCase();
      const contentLc = content.toLowerCase();
      const direct = contentLc.includes(payToLc);
      const obfuscated =
        !direct && stripInvisible(contentLc).replace(/\s+/g, "").includes(payToLc);
      if (direct || obfuscated) {
        results.push({
          id: "injection.payto_from_content",
          name: "Prompt-injection-triggered payment",
          verdict: fromUntrusted || obfuscated ? "block" : "flag",
          severity: fromUntrusted || obfuscated ? "critical" : "high",
          reason: obfuscated
            ? "The payment recipient address appears in the content the agent just read, hidden by whitespace splitting or invisible characters. Obfuscating an address to evade scanning is itself a strong attack signal."
            : "The payment recipient address appears verbatim in the content the agent just read. Recipient addresses sourced from untrusted content are the classic payment-redirection attack. (If this text is the 402 offer / discovery payload itself, pass it in context.offer instead — pay_to is expected there.)",
          // implicated_address: on a block, this finding structurally binds
          // pay_to to injected content — the incident ledger records it so
          // future scans of the same wallet inherit the signal (flag-only).
          details: { pay_to: payment.pay_to, origin, obfuscated, implicated_address: payToLc },
        });
      }
    }
  }

  // The offer channel: protocol-shaped payment terms (402 accepts entry,
  // Bazaar listing). pay_to appearing here is how x402 works — no provenance
  // finding — but the offer is counterparty-authored text, so injection tells
  // inside it (e.g. a description carrying instructions) still fire. Offers
  // are always counterparty-authored, so they escalate like untrusted content.
  const offer = context?.offer ?? "";
  if (offer) {
    const offerHits = findTells(offer);
    if (offerHits.length > 0) {
      const { score, proximity } = scoreTells(offer, offerHits, false);
      const escalate = score >= 2;
      results.push({
        id: "injection.offer_tells",
        name: "Prompt-injection-triggered payment",
        verdict: escalate ? "block" : "flag",
        severity: escalate ? "critical" : "medium",
        reason: `The payment offer itself contains prompt-injection indicators: ${offerHits.map((h) => h.label).join("; ")}. Offer fields are counterparty-authored — instructions embedded in them target the paying agent.`,
        details: { indicators: offerHits.map((h) => h.id), score, proximity },
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

// ---------------------------------------------------------------------------
// Deep tier
// ---------------------------------------------------------------------------

const PRINTABLE = /^[\x09\x0a\x0d\x20-\x7e]+$/;
// Standard AND URL-safe base64 alphabets. Long hyphenated/plain words can
// match too — decode noise is filtered by the PRINTABLE + tells gates below.
const B64_BLOB_G = /[A-Za-z0-9+/_-]{24,}={0,2}/g;
const B64_WHOLE = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;
const HEX_BLOB_G = /(?:0x)?(?:[0-9a-fA-F]{2}){16,}/g;
const TAG_PRESENT = /[\u{E0000}-\u{E007F}]/u;
const MAX_BLOBS = 32;

function tryBase64(blob: string): string | null {
  try {
    const d = Buffer.from(blob, "base64").toString("utf8");
    return d.length > 0 && PRINTABLE.test(d) ? d : null;
  } catch {
    return null;
  }
}

/** Decode Unicode tag characters (U+E0020–E007E) back to the ASCII they mirror. */
function decodeTagChars(text: string): string {
  if (!TAG_PRESENT.test(text)) return "";
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

function safeCodePoint(cp: number): string {
  return cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
}

/**
 * Deep content-analysis tier. Decodes the cheap obfuscations (base64 in both
 * alphabets incl. line-wrapped and double-encoded, hex, percent-encoding,
 * HTML entities, Unicode tag smuggling) and unicode-skeleton-folds the
 * content, then rescans. Still regex/linear speed on the (200KB-capped)
 * content; gated by the micropayment bypass policy because obfuscated attacks
 * target payments worth stealing.
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
  const payToLc = payment.pay_to?.toLowerCase();
  const embedsPayTo = (text: string): boolean =>
    payToLc !== undefined && text.toLowerCase().includes(payToLc);

  // 4. Base64-obfuscated payloads. Join MIME-style line-wrapped blobs first,
  // then try each candidate; a decode that is itself base64 is decoded once
  // more (double-encoding).
  const joined = content.replace(
    /([A-Za-z0-9+/_-]{12,})[ \t]*\r?\n[ \t]*(?=[A-Za-z0-9+/_-]{12,})/g,
    "$1",
  );
  const blobs = joined.match(B64_BLOB_G) ?? [];
  for (const blob of blobs.slice(0, MAX_BLOBS)) {
    let decoded = tryBase64(blob);
    if (decoded === null) continue;
    let doubleEncoded = false;
    let tells = findTells(decoded);
    let embeds = embedsPayTo(decoded);
    if (tells.length === 0 && !embeds && B64_WHOLE.test(decoded.trim())) {
      const inner = tryBase64(decoded.trim());
      if (inner !== null) {
        decoded = inner;
        doubleEncoded = true;
        tells = findTells(inner);
        embeds = embedsPayTo(inner);
      }
    }
    if (tells.length > 0 || embeds) {
      results.push({
        id: "injection.b64_obfuscated",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: fromUntrusted || embeds ? "block" : "flag",
        severity: "critical",
        reason: `A ${doubleEncoded ? "doubly " : ""}base64-encoded blob in the just-read content decodes to ${embeds ? "text embedding the payment recipient address" : "prompt-injection content"}${tells.length ? ` (${tells.map((t) => t.label).join("; ")})` : ""}. Encoding instructions to evade filters is itself a strong attack signal.`,
        details: {
          decoded_preview: decoded.slice(0, 120),
          indicators: tells.map((t) => t.id),
          double_encoded: doubleEncoded,
          // Only an EMBEDDED pay_to implicates the recipient; tells alone
          // don't prove the payee authored the payload.
          ...(embeds ? { implicated_address: payToLc } : {}),
        },
      });
      break; // one finding is enough
    }
  }

  // 5. Other encodings: hex blobs, percent(URL)-encoding, HTML numeric
  // entities. First encoding family that reveals something reports; the
  // finding is about "an encoded payload exists", not an inventory.
  const rawTellIds = new Set(findTells(content).map((t) => t.id));
  const encodedFinding = (encoding: string, decoded: string): boolean => {
    const fresh = findTells(decoded).filter((t) => !rawTellIds.has(t.id));
    const embeds = embedsPayTo(decoded) && !embedsPayTo(content);
    if (fresh.length === 0 && !embeds) return false;
    results.push({
      id: "injection.encoded_content",
      name: "Prompt-injection-triggered payment (deep)",
      verdict: fromUntrusted || embeds ? "block" : "flag",
      severity: "critical",
      reason: `${encoding}-encoded text in the just-read content decodes to ${embeds ? "text embedding the payment recipient address" : "prompt-injection content"}${fresh.length ? ` (${fresh.map((t) => t.label).join("; ")})` : ""}. Encoding instructions to evade filters is itself a strong attack signal.`,
      details: {
        encoding,
        decoded_preview: decoded.slice(0, 120),
        indicators: fresh.map((t) => t.id),
        ...(embeds ? { implicated_address: payToLc } : {}),
      },
    });
    return true;
  };
  encodedHunt: {
    // hex
    for (const blob of (content.match(HEX_BLOB_G) ?? []).slice(0, MAX_BLOBS)) {
      const hex = blob.startsWith("0x") ? blob.slice(2) : blob;
      const decoded = Buffer.from(hex, "hex").toString("utf8");
      if (PRINTABLE.test(decoded) && encodedFinding("hex", decoded)) break encodedHunt;
    }
    // percent-encoding
    if (/%[0-9a-fA-F]{2}/.test(content)) {
      const decoded = content.replace(/%([0-9a-fA-F]{2})/g, (_, h: string) =>
        String.fromCharCode(parseInt(h, 16)),
      );
      if (encodedFinding("percent(URL)", decoded)) break encodedHunt;
    }
    // HTML numeric entities
    if (/&#x?[0-9a-fA-F]+;/.test(content)) {
      const decoded = content
        .replace(/&#x([0-9a-fA-F]+);/gi, (_, h: string) => safeCodePoint(parseInt(h, 16)))
        .replace(/&#(\d+);/g, (_, d: string) => safeCodePoint(parseInt(d, 10)));
      if (encodedFinding("HTML-entity", decoded)) break encodedHunt;
    }
  }

  // 6. Unicode tag-character smuggling: instructions mirrored into the
  // invisible tag block. Emoji flag sequences also use tag chars (e.g. the
  // England flag decodes to "gbeng"), so only report when the decoded text
  // actually carries tells, the recipient address, or an address-like token.
  const tagDecoded = decodeTagChars(content);
  if (tagDecoded) {
    const tells = findTells(tagDecoded);
    const embeds = embedsPayTo(tagDecoded);
    ADDR_TOKEN_G.lastIndex = 0;
    const hasAddr = ADDR_TOKEN_G.test(tagDecoded);
    if (tells.length > 0 || embeds || hasAddr) {
      results.push({
        id: "injection.tag_smuggling",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: "block",
        severity: "critical",
        reason: `The just-read content carries text smuggled in invisible Unicode tag characters${embeds ? ", embedding the payment recipient address" : ""}${tells.length ? ` (${tells.map((t) => t.label).join("; ")})` : hasAddr && !embeds ? " (containing an address-like token)" : ""}. Tag-character smuggling has no legitimate use in prose and targets LLM agents specifically.`,
        details: {
          decoded_preview: tagDecoded.slice(0, 120),
          indicators: tells.map((t) => t.id),
          ...(embeds ? { implicated_address: payToLc } : {}),
        },
      });
    }
  }

  // 7. Unicode-skeleton rescan: NFKC + invisible strip + homoglyph fold.
  // Catches zero-width splitting AND Cyrillic/Greek lookalike substitution
  // ("іgnоre all prevіоus іnstructіons"), which NFKC alone leaves intact.
  const sk = skeleton(content);
  if (sk !== content) {
    const rawTells = findTells(content).filter((t) => t.id !== "invisible_chars").length;
    const skTells = findTells(sk);
    if (skTells.length > rawTells) {
      results.push({
        id: "injection.unicode_obfuscated",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: fromUntrusted ? "block" : "flag",
        severity: "critical",
        reason: `Injection indicators appear only after unicode normalization (zero-width stripping / homoglyph folding): ${skTells.map((t) => t.label).join("; ")}. Hidden-character or lookalike-letter obfuscation is itself a strong attack signal.`,
        details: { indicators: skTells.map((t) => t.id) },
      });
    }
  }

  return results;
}

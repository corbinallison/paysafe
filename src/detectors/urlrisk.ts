// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Resource-URL risk checks, used mainly on the incoming path
 * (screening a 402 offer / payment request someone sent to your agent).
 */
import type { CheckResult, PaymentDetails } from "../types.ts";

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
]);

const CREDENTIAL_DEMANDS =
  /\b(?:seed\s+phrase|recovery\s+phrase|mnemonic|private\s+key|wallet\s+password|passphrase|2fa\s+code|social\s+security|passport\s+number)\b/i;

export function checkUrlRisk(payment: PaymentDetails): CheckResult[] {
  const results: CheckResult[] = [];
  const raw = payment.resource_url;

  if (raw) {
    let url: URL | null = null;
    try {
      url = new URL(raw);
    } catch {
      results.push({
        id: "url.unparseable",
        name: "Resource URL risk",
        verdict: "flag",
        severity: "medium",
        reason: `resource_url is not a valid URL: "${raw.slice(0, 120)}".`,
      });
    }

    if (url) {
      const host = url.hostname.toLowerCase();
      if (url.protocol !== "https:") {
        results.push({
          id: "url.not_https",
          name: "Resource URL risk",
          verdict: "flag",
          severity: "medium",
          reason: `Resource is served over ${url.protocol.replace(":", "")}, not HTTPS. Payment metadata would transit unencrypted.`,
          details: { host },
        });
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) {
        results.push({
          id: "url.ip_literal",
          name: "Resource URL risk",
          verdict: "flag",
          severity: "high",
          reason: `Resource host is a raw IP literal (${host}) — no accountable domain identity.`,
        });
      }
      if (host.startsWith("xn--") || host.includes(".xn--")) {
        results.push({
          id: "url.punycode",
          name: "Resource URL risk",
          verdict: "flag",
          severity: "high",
          reason: `Resource host uses punycode (${host}) — possible homoglyph impersonation of a known domain.`,
        });
      }
      if (SHORTENERS.has(host)) {
        results.push({
          id: "url.shortener",
          name: "Resource URL risk",
          verdict: "flag",
          severity: "medium",
          reason: `Resource URL is behind a link shortener (${host}); the true destination is hidden.`,
        });
      }
      if (url.username || url.password) {
        results.push({
          id: "url.userinfo",
          name: "Resource URL risk",
          verdict: "block",
          severity: "high",
          reason:
            "Resource URL embeds userinfo (user@host) — a common technique to disguise the real destination host.",
        });
      }
    }
  }

  const text = `${payment.description ?? ""} ${payment.reason ?? ""}`;
  if (CREDENTIAL_DEMANDS.test(text)) {
    results.push({
      id: "url.credential_demand",
      name: "Counterparty demand risk",
      verdict: "block",
      severity: "critical",
      reason:
        "The payment request's description asks for credentials or identity material (seed phrase / private key / SSN etc.). Legitimate x402 sellers never need these.",
    });
  }

  if (results.length === 0) {
    results.push({
      id: "url.clean",
      name: "Resource URL risk",
      verdict: "allow",
      severity: "info",
      reason: "No structural risk indicators in the resource URL or request text.",
    });
  }
  return results;
}

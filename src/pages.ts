// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Human-facing markdown pages — the homepage (GET / for browsers) and the
 * legal pages (GET /terms, GET /privacy) — rendered from the canonical
 * HOME.md / TERMS.md / PRIVACY.md at the package root (single source of
 * truth: the same files GitHub renders). Files are located by walking up
 * from this module (same trick as version.ts), read once, and cached.
 *
 * The homepage supports {{price_scan}} / {{price_reputation}} /
 * {{free_calls}} placeholders, filled from config so pricing can't drift
 * from what the payment gate actually charges (same policy as llms.txt).
 *
 * The markdown is converted by a deliberately tiny renderer that supports
 * only what these documents use (headings, bold/em, code spans and fences,
 * links, lists, tables, rules). All text is HTML-escaped BEFORE inline
 * markup is applied, and only http(s)/mailto/fragment/site-relative link
 * targets survive — so the pages stay static HTML with no script and zero
 * external resources, under the same locked-down CSP as the dashboards.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { PaySafeConfig } from "./config.ts";
import type { PublicStats } from "./pubstats.ts";

function loadDoc(filename: string): string | null {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    try {
      return readFileSync(join(dir, filename), "utf8");
    } catch {
      // keep walking up
    }
    dir = dirname(dir);
  }
  return null; // never crash the server over a missing doc; the route falls back
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** GitHub-style heading slug: "5. The reputation registry" -> "5-the-reputation-registry". */
function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

/** Repo-relative doc links become site routes; everything else must be a safe scheme. */
function linkHref(url: string): string | null {
  const base = url.split("#")[0];
  if (base === "TERMS.md") return "/terms" + url.slice(base.length);
  if (base === "PRIVACY.md") return "/privacy" + url.slice(base.length);
  if (/^(https:\/\/|http:\/\/|mailto:|#|\/)/.test(url)) return url;
  return null; // unknown relative target (e.g. a repo file): render as plain text
}

function inline(md: string): string {
  let s = escapeHtml(md);
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\*([^*\s][^*]*)\*/g, "<em>$1</em>");
  s = s.replace(/\[([^\]]+)\]\(([^()\s]+)\)/g, (m: string, text: string, url: string) => {
    const href = linkHref(url);
    return href ? `<a href="${escapeHtml(href)}">${text}</a>` : text;
  });
  return s;
}

function tableRow(line: string): string[] {
  return line
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((c) => c.trim());
}

function renderMarkdown(md: string): string {
  const lines = md.split(/\r?\n/);
  const out: string[] = [];
  let para: string[] = [];
  let list: string[] = [];
  let table: string[][] = [];
  let fence: string[] | null = null;

  const flushPara = () => {
    if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };
  const flushList = () => {
    if (list.length) out.push(`<ul>${list.map((li) => `<li>${inline(li)}</li>`).join("")}</ul>`);
    list = [];
  };
  const flushTable = () => {
    if (table.length) {
      const [head, ...body] = table;
      out.push(
        `<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>` +
          body.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("") +
          `</tbody></table>`,
      );
    }
    table = [];
  };
  const flushAll = () => {
    flushPara();
    flushList();
    flushTable();
  };

  for (const line of lines) {
    if (fence !== null) {
      if (/^```/.test(line)) {
        out.push(`<pre><code>${escapeHtml(fence.join("\n"))}</code></pre>`);
        fence = null;
      } else fence.push(line);
      continue;
    }
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    if (/^```/.test(line)) {
      flushAll();
      fence = [];
    } else if (/^\{\{[a-z_]+\}\}$/.test(line.trim())) {
      // A placeholder alone on a line passes through unwrapped (no <p>), so a
      // later substitution may inject block-level HTML (the stats panel).
      flushAll();
      out.push(line.trim());
    } else if (heading) {
      flushAll();
      const level = heading[1].length;
      out.push(`<h${level} id="${slug(heading[2])}">${inline(heading[2])}</h${level}>`);
    } else if (/^-{3,}\s*$/.test(line)) {
      flushAll();
      out.push("<hr>");
    } else if (/^\s*\|/.test(line)) {
      flushPara();
      flushList();
      if (!/^[\s|:-]+$/.test(line)) table.push(tableRow(line)); // skip the |---| separator
    } else if (/^-\s+/.test(line)) {
      flushPara();
      flushTable();
      list.push(line.replace(/^-\s+/, ""));
    } else if (line.trim() === "") {
      flushAll();
    } else {
      flushList();
      flushTable();
      para.push(line.trim());
    }
  }
  if (fence !== null) out.push(`<pre><code>${escapeHtml(fence.join("\n"))}</code></pre>`);
  flushAll();
  return out.join("\n");
}

function markdownPageHtml(title: string, markdown: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: dark; --bg:#0b0e14; --card:#141a24; --line:#232c3b; --fg:#e6edf3; --muted:#8b98a9; --accent:#4c8dff; --allow:#3fb950; --flag:#d29922; --block:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:760px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:26px; line-height:1.3; margin:0 0 16px; }
  h2 { font-size:19px; margin:32px 0 10px; padding-top:16px; border-top:1px solid var(--line); }
  h3 { font-size:16px; margin:24px 0 8px; }
  p, li { color:var(--fg); }
  ul { padding-left:22px; margin:10px 0; }
  li { margin:6px 0; }
  a { color:var(--accent); }
  code { background:#0d1017; border:1px solid var(--line); padding:1px 5px; border-radius:4px; font:13px ui-monospace,SFMono-Regular,Menlo,monospace; }
  pre { background:#0d1017; border:1px solid var(--line); border-radius:8px; padding:14px; overflow-x:auto; }
  pre code { background:none; border:0; padding:0; font-size:13px; line-height:1.5; }
  hr { border:0; border-top:1px solid var(--line); margin:32px 0; }
  table { border-collapse:collapse; width:100%; margin:14px 0; font-size:14px; display:block; overflow-x:auto; }
  th, td { border:1px solid var(--line); padding:8px 10px; text-align:left; vertical-align:top; }
  th { background:var(--card); }
  footer { margin-top:48px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:13px; }
  footer a { color:var(--muted); }
  .statgrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:16px 0 0; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
  .stat .n { font-size:26px; font-weight:700; line-height:1.2; }
  .stat .n.ok { color:var(--allow); }
  .stat .n.warn { color:var(--flag); }
  .stat .n.bad { color:var(--block); }
  .stat .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }
  .bar { display:flex; height:10px; border-radius:6px; overflow:hidden; background:#0d1017; margin:14px 0 10px; }
  .bar > div { display:block; }
  .seg-allow { background:var(--allow); }
  .seg-flag { background:var(--flag); }
  .seg-block { background:var(--block); }
  .seg-empty { background:#232c3b; }
  .legend { display:flex; gap:16px; flex-wrap:wrap; color:var(--muted); font-size:13px; }
  .legend div::before { content:""; display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }
  .lg-allow::before { background:var(--allow); }
  .lg-flag::before { background:var(--flag); }
  .lg-block::before { background:var(--block); }
  .statmeta { color:var(--muted); font-size:13px; margin:10px 0 0; }
</style>
</head>
<body>
<div class="wrap">
${renderMarkdown(markdown)}
<footer><a href="/">PaySafe</a> · <a href="/terms">Terms of Use</a> · <a href="/privacy">Privacy Policy</a> · <a href="https://github.com/corbinallison/paysafe">Source</a></footer>
</div>
</body>
</html>`;
}

let homeTemplateCache: string | null | undefined;
let termsCache: string | null | undefined;
let privacyCache: string | null | undefined;

function fmtInt(n: number): string {
  return n.toLocaleString("en-US");
}

/**
 * The "Track record" panel — same visual language as the dashboards (stat
 * tiles, verdict proportion bar, legend). Every value is a number or date we
 * format ourselves from the TTL-cached public snapshot; the markup is static
 * divs with inline width percentages only, so the page stays scriptless
 * under the locked-down CSP (style-src 'unsafe-inline' covers it).
 */
function statsPanelHtml(stats?: PublicStats | null): string {
  const total = stats?.scans_total ?? 0;
  const blocked = stats?.blocked ?? 0;
  const flagged = stats?.flagged ?? 0;
  const allowed = Math.max(0, total - blocked - flagged);
  const u = stats?.uptime ?? null;
  const pct = (n: number) => ((n / total) * 100).toFixed(2);
  const bar =
    total > 0
      ? `<div class="seg-allow" style="width:${pct(allowed)}%" title="allowed: ${fmtInt(allowed)}"></div>` +
        `<div class="seg-flag" style="width:${pct(flagged)}%" title="flagged: ${fmtInt(flagged)}"></div>` +
        `<div class="seg-block" style="width:${pct(blocked)}%" title="blocked: ${fmtInt(blocked)}"></div>`
      : `<div class="seg-empty" style="width:100%"></div>`;
  const uptimeMeta = u
    ? `Uptime is self-measured process liveness (a heartbeat cannot see network-level unreachability), recording since ${escapeHtml(u.measured_since.slice(0, 10))}.`
    : `Uptime is self-measured process liveness; no heartbeats recorded yet.`;
  return `<div class="statgrid">
<div class="stat"><div class="n">${fmtInt(total)}</div><div class="l">Payments screened</div></div>
<div class="stat"><div class="n ok">${fmtInt(allowed)}</div><div class="l">Allowed</div></div>
<div class="stat"><div class="n warn">${fmtInt(flagged)}</div><div class="l">Flagged</div></div>
<div class="stat"><div class="n bad">${fmtInt(blocked)}</div><div class="l">Blocked</div></div>
<div class="stat"><div class="n">${fmtInt(stats?.distinct_agents ?? 0)}</div><div class="l">Distinct agents</div></div>
<div class="stat"><div class="n${u ? " ok" : ""}">${u ? `${u.pct.toFixed(2)}%` : "n/a"}</div><div class="l">Uptime · 90 days</div></div>
</div>
<div class="bar">${bar}</div>
<div class="legend"><div class="lg-allow">allow</div><div class="lg-flag">flag</div><div class="lg-block">block</div></div>
<p class="statmeta">${uptimeMeta}</p>`;
}

/**
 * Browser homepage. Pricing placeholders are filled from config (llms.txt
 * policy) and cached with the render; the {{stats_panel}} placeholder
 * survives the markdown render (emitted raw, unwrapped) and is filled per
 * request from the TTL-cached public snapshot (pubstats.ts) — see
 * statsPanelHtml for why the result is CSP-safe static markup.
 */
export function homePageHtml(cfg: PaySafeConfig, stats?: PublicStats | null): string | null {
  if (homeTemplateCache === undefined) {
    const md = loadDoc("HOME.md");
    homeTemplateCache =
      md === null
        ? null
        : markdownPageHtml(
            "PaySafe — payment security firewall for AI agents",
            md
              .replace(/\{\{price_scan\}\}/g, cfg.priceScan)
              .replace(/\{\{price_reputation\}\}/g, cfg.priceReputation)
              .replace(/\{\{free_calls\}\}/g, String(cfg.freeCalls)),
          );
  }
  if (homeTemplateCache === null) return null;
  return homeTemplateCache.replace(/\{\{stats_panel\}\}/g, statsPanelHtml(stats));
}

export function termsPageHtml(): string | null {
  if (termsCache === undefined) {
    const md = loadDoc("TERMS.md");
    termsCache = md === null ? null : markdownPageHtml("PaySafe — Terms of Use", md);
  }
  return termsCache;
}

export function privacyPageHtml(): string | null {
  if (privacyCache === undefined) {
    const md = loadDoc("PRIVACY.md");
    privacyCache = md === null ? null : markdownPageHtml("PaySafe — Privacy Policy", md);
  }
  return privacyCache;
}

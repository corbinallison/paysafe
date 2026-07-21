// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Legal pages — GET /terms and GET /privacy, rendered from the canonical
 * TERMS.md / PRIVACY.md at the package root (single source of truth: the
 * same files GitHub renders). Files are located by walking up from this
 * module (same trick as version.ts), read once, and cached.
 *
 * The markdown is converted by a deliberately tiny renderer that supports
 * only what these documents use (headings, bold/em, code spans, links,
 * lists, tables). All text is HTML-escaped BEFORE inline markup is applied,
 * and only http(s)/mailto/fragment/site-relative link targets survive —
 * so the pages stay static HTML with no script and zero external resources,
 * under the same locked-down CSP as the dashboards.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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
  return null; // never crash the server over a missing doc; the route 404s
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
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    if (heading) {
      flushAll();
      const level = heading[1].length;
      out.push(`<h${level} id="${slug(heading[2])}">${inline(heading[2])}</h${level}>`);
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
  flushAll();
  return out.join("\n");
}

function legalPageHtml(title: string, markdown: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: dark; --bg:#0b0e14; --card:#141a24; --line:#232c3b; --fg:#e6edf3; --muted:#8b98a9; --accent:#4c8dff; }
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
  table { border-collapse:collapse; width:100%; margin:14px 0; font-size:14px; display:block; overflow-x:auto; }
  th, td { border:1px solid var(--line); padding:8px 10px; text-align:left; vertical-align:top; }
  th { background:var(--card); }
  footer { margin-top:48px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:13px; }
  footer a { color:var(--muted); }
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

let termsCache: string | null | undefined;
let privacyCache: string | null | undefined;

export function termsPageHtml(): string | null {
  if (termsCache === undefined) {
    const md = loadDoc("TERMS.md");
    termsCache = md === null ? null : legalPageHtml("PaySafe — Terms of Use", md);
  }
  return termsCache;
}

export function privacyPageHtml(): string | null {
  if (privacyCache === undefined) {
    const md = loadDoc("PRIVACY.md");
    privacyCache = md === null ? null : legalPageHtml("PaySafe — Privacy Policy", md);
  }
  return privacyCache;
}

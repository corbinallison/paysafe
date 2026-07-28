// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Injection-detection evaluation harness. Zero dependencies; runs with:
 *   npm run eval   (node --experimental-strip-types eval/run-eval.ts)
 *
 * Runs every corpus case through a real scan and grades ONLY the
 * content-detection layer (injection.* / poison.* checks), excluding the
 * origin-provenance advisories that fire on any untrusted-origin scan — so
 * the numbers measure the detectors, not the plumbing around them.
 *
 * Gate: every non-known_gap case must meet its expectation or the process
 * exits 1 (CI-friendly). known_gap cases are tracked either way: a gap that
 * closes is called out so it can be promoted to a gating case.
 */
import { runScan } from "../src/scanner.ts";
import { Store } from "../src/store.ts";
import { loadConfig } from "../src/config.ts";
import { CORPUS, PAY_TO } from "./corpus.ts";
import type { EvalCase } from "./corpus.ts";
import type { Verdict } from "../src/types.ts";

const cfg = loadConfig({ PAYSAFE_MODE: "dev", PAY_TO: "0xtest" });

/** Checks that measure content detection. Provenance advisories and the
 * clean-marker are plumbing, not detection. */
const EXCLUDED = new Set([
  "injection.untrusted_origin",
  "injection.untrusted_origin_mitigated",
  "injection.unknown_origin",
  "injection.clean",
]);
const RANK: Record<Verdict, number> = { allow: 0, flag: 1, block: 2 };

function detectionLevel(caseId: string, c: EvalCase): Verdict {
  const scan = runScan(
    "outgoing",
    {
      agent_id: `eval-${caseId}`,
      payment: {
        scheme: "exact",
        network: "eip155:8453",
        amount: "1000000", // $1 — above MICRO_BYPASS_USD so the deep tier runs
        asset_decimals: 6,
        pay_to: PAY_TO,
        payer: "0xA11ce00000000000000000000000000000000001",
        resource_url: "https://api.example.com/data",
        description: "Data access",
        nonce: `0xeval-${caseId}`,
      },
      expected_price_usd: 1,
      context: {
        origin: c.origin ?? "fetched_content",
        ...(c.content !== undefined ? { content: c.content } : {}),
        ...(c.offer !== undefined ? { offer: c.offer } : {}),
      },
    },
    cfg,
    new Store(null), // fresh state per case: no cross-case contamination
  );
  let level: Verdict = "allow";
  for (const chk of scan.checks) {
    if (!/^(injection|poison)\./.test(chk.id) || EXCLUDED.has(chk.id)) continue;
    if (RANK[chk.verdict] > RANK[level]) level = chk.verdict;
  }
  return level;
}

interface Result {
  c: EvalCase;
  level: Verdict;
  pass: boolean;
}

const results: Result[] = CORPUS.map((c) => {
  const level = detectionLevel(c.id, c);
  const pass =
    c.kind === "attack" ? RANK[level] >= RANK[c.expect] : RANK[level] <= RANK[c.expect];
  return { c, level, pass };
});

// ── report ─────────────────────────────────────────────────────────────────
const gating = results.filter((r) => !r.c.known_gap);
const attacks = gating.filter((r) => r.c.kind === "attack");
const benign = gating.filter((r) => r.c.kind === "benign");
const gaps = results.filter((r) => r.c.known_gap);
const failures = gating.filter((r) => !r.pass);

console.log("— injection-detection eval —\n");
for (const r of results) {
  const mark = r.c.known_gap ? (r.pass ? "◆ closed gap!" : "◇ known gap") : r.pass ? "✓" : "✗";
  const want = r.c.kind === "attack" ? `≥${r.c.expect}` : `≤${r.c.expect}`;
  console.log(`  ${mark} ${r.c.kind === "attack" ? "atk" : "ben"} ${r.c.id.padEnd(28)} [${r.c.family}] got ${r.level}, want ${want}`);
  if (!r.pass && !r.c.known_gap && r.c.note) console.log(`      note: ${r.c.note}`);
}

const pct = (n: number, d: number): string => (d === 0 ? "n/a" : `${((100 * n) / d).toFixed(1)}%`);
console.log(`\n  attacks detected:   ${attacks.filter((r) => r.pass).length}/${attacks.length} (${pct(attacks.filter((r) => r.pass).length, attacks.length)})`);
console.log(`  benign not over-flagged: ${benign.filter((r) => r.pass).length}/${benign.length} (${pct(benign.filter((r) => r.pass).length, benign.length)})`);
if (gaps.length) {
  const closed = gaps.filter((r) => r.pass);
  console.log(`  known gaps: ${gaps.length - closed.length} open, ${closed.length} closed${closed.length ? " — promote closed gaps to gating cases!" : ""}`);
}

if (failures.length > 0) {
  console.error(`\n${failures.length} regression(s) — the corpus is a contract; fix the detector or consciously amend the case.`);
  process.exit(1);
}
console.log("\nAll gating cases pass.");

#!/usr/bin/env node
// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Zero-touch releases: compute the NEXT version for a package from the
 * REGISTRY (not from git) and apply it everywhere via set-version.mjs.
 * Because the bump derives from what's actually published, a stale version in
 * git can never cause an "already published" publish failure again.
 *
 * Usage: node scripts/next-version.mjs <package> [patch|minor|major]
 *   (packages are the same keys as check-versions.mjs / set-version.mjs)
 *
 * Rules:
 *  - next = registry latest with the requested part bumped (default: patch)
 *  - if the repo carries a HIGHER, not-yet-published version, the repo wins —
 *    that's a deliberate manual bump (e.g. staging a 2.0.0), honor it
 *  - never published at all -> keep the repo version (first release as-is)
 *
 * In GitHub Actions, writes `version=<x.y.z>` to $GITHUB_OUTPUT.
 */
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const jsonVersion = (p) => JSON.parse(read(p)).version;
const initVersion = (p) => {
  const m = read(p).match(/__version__ = "([^"]+)"/);
  if (!m) throw new Error(`could not find __version__ in ${p}`);
  return m[1];
};

/** Registry identity + where the repo's current version is read from. */
const PACKAGES = {
  server: { type: "npm", name: "paysafe-x402", current: () => jsonVersion("package.json") },
  sdk: { type: "npm", name: "paysafe-x402-client", current: () => jsonVersion("sdk/package.json") },
  "ai-sdk": { type: "npm", name: "paysafe-ai-sdk", current: () => jsonVersion("integrations/paysafe-ai-sdk/package.json") },
  python: { type: "pypi", name: "paysafe-x402", current: () => initVersion("sdk-python/src/paysafe_x402/__init__.py") },
  langchain: { type: "pypi", name: "langchain-paysafe", current: () => initVersion("integrations/langchain-paysafe/src/langchain_paysafe/__init__.py") },
  crewai: { type: "pypi", name: "crewai-paysafe", current: () => initVersion("integrations/crewai-paysafe/src/crewai_paysafe/__init__.py") },
  nemo: { type: "pypi", name: "nemo-paysafe", current: () => initVersion("integrations/nemo-paysafe/src/nemo_paysafe/__init__.py") },
  agentkit: { type: "pypi", name: "agentkit-paysafe", current: () => initVersion("integrations/agentkit-paysafe/src/agentkit_paysafe/__init__.py") },
};

const [, , key, bumpKind = "patch"] = process.argv;
if (!PACKAGES[key] || !["patch", "minor", "major"].includes(bumpKind)) {
  console.error(`Usage: node scripts/next-version.mjs <${Object.keys(PACKAGES).join("|")}> [patch|minor|major]`);
  process.exit(2);
}

const parse = (v) => v.split(".").map(Number);
const cmp = (a, b) => {
  const pa = parse(a), pb = parse(b);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};
const bump = (v, kind) => {
  const [maj, min, pat] = parse(v);
  if (kind === "major") return `${maj + 1}.0.0`;
  if (kind === "minor") return `${maj}.${min + 1}.0`;
  return `${maj}.${min}.${pat + 1}`;
};

async function published(reg) {
  if (reg.type === "npm") {
    const res = await fetch(`https://registry.npmjs.org/${reg.name}`);
    if (res.status === 404) return [];
    if (!res.ok) throw new Error(`npm registry ${res.status} for ${reg.name}`);
    return Object.keys((await res.json()).versions ?? {});
  }
  const res = await fetch(`https://pypi.org/pypi/${reg.name}/json`);
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`PyPI ${res.status} for ${reg.name}`);
  return Object.keys((await res.json()).releases ?? {});
}

const reg = PACKAGES[key];
const current = reg.current();
const releases = (await published(reg)).filter((v) => /^\d+\.\d+\.\d+$/.test(v));

let next;
if (releases.length === 0) {
  next = current; // first release: publish exactly what's in the repo
  console.log(`${reg.name}: never published — keeping repo version ${current}`);
} else {
  const latest = releases.reduce((a, b) => (cmp(a, b) >= 0 ? a : b));
  const candidate = bump(latest, bumpKind);
  // A repo version above the registry that isn't published is a deliberate
  // manual bump (e.g. a staged minor/major) — honor it instead of the patch.
  next = cmp(current, candidate) > 0 && !releases.includes(current) ? current : candidate;
  console.log(`${reg.name}: registry latest ${latest} -> next ${next} (${bumpKind}${next === current && next !== candidate ? ", honoring repo version" : ""})`);
}

if (next !== current) {
  execFileSync("node", [join(ROOT, "scripts", "set-version.mjs"), key, next], { stdio: "inherit" });
} else {
  console.log(`repo already at ${next}; nothing to rewrite`);
}

if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `version=${next}\n`);

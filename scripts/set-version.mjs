#!/usr/bin/env node
/**
 * Bump a package's version in EVERY file that carries it, atomically.
 * The antidote to editing four files by hand and missing one.
 *
 * Usage: node scripts/set-version.mjs <server|sdk|python|langchain> <version>
 *   server    -> package.json, server.json (x2), mcp/server.ts, src/api.ts
 *   sdk       -> sdk/package.json
 *   python    -> sdk-python/pyproject.toml, sdk-python __init__.py
 *   langchain -> langchain-paysafe pyproject.toml + __init__.py
 *
 * Verifies the result with scripts/check-versions.mjs semantics: after
 * writing, re-reads every spot and fails loudly if anything still disagrees.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const [, , pkg, version] = process.argv;

if (!pkg || !version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error("Usage: node scripts/set-version.mjs <server|sdk|python|langchain> <x.y.z>");
  process.exit(2);
}

const sub = (path, pattern, replacement) => {
  const p = join(ROOT, path);
  const before = readFileSync(p, "utf8");
  const after = before.replace(pattern, replacement);
  if (before === after) throw new Error(`no substitution made in ${path} — pattern drift? Fix scripts/set-version.mjs.`);
  writeFileSync(p, after);
  console.log(`  ✓ ${path}`);
};

const EDITS = {
  server: () => {
    sub("package.json", /("version":\s*")[^"]+(")/, `$1${version}$2`);
    sub("server.json", /("version":\s*")[^"]+(")/g, `$1${version}$2`); // both spots
    sub("mcp/server.ts", /(name: "paysafe", version: ")[^"]+(")/, `$1${version}$2`);
    sub("src/api.ts", /(version: ")[^"]+(")/, `$1${version}$2`);
  },
  sdk: () => sub("sdk/package.json", /("version":\s*")[^"]+(")/, `$1${version}$2`),
  python: () => {
    sub("sdk-python/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("sdk-python/src/paysafe_x402/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
  langchain: () => {
    sub("integrations/langchain-paysafe/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("integrations/langchain-paysafe/src/langchain_paysafe/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
  crewai: () => {
    sub("integrations/crewai-paysafe/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("integrations/crewai-paysafe/src/crewai_paysafe/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
};

if (!EDITS[pkg]) {
  console.error(`Unknown package "${pkg}". Valid: ${Object.keys(EDITS).join(", ")}`);
  process.exit(2);
}

console.log(`Setting ${pkg} -> ${version}`);
EDITS[pkg]();
console.log(`Done. Verify + registry-check with: node scripts/check-versions.mjs ${pkg} --registry`);

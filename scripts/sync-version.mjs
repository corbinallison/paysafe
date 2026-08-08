// Copyright (c) 2026 Tollwarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Sync static version copies from package.json (the single source of truth).
 * Runtime code reads the version via src/version.ts; the only static copy is
 * server.json (the MCP registry manifest, consumed as a file — it can't read
 * anything at publish time).
 *
 * Wired into the `npm version` lifecycle: `npm version patch|minor|major`
 * bumps package.json, runs this, and commits both files together.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

const serverJsonPath = join(root, "server.json");
const serverJson = JSON.parse(readFileSync(serverJsonPath, "utf8"));
serverJson.version = version;
for (const pkg of serverJson.packages ?? []) pkg.version = version;
writeFileSync(serverJsonPath, JSON.stringify(serverJson, null, 2) + "\n");

console.log(`server.json synced to ${version}`);

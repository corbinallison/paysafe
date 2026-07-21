// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Single source of truth for the server/MCP version: the root package.json.
 * Read at module load by walking up from this file, which resolves correctly
 * both in dev (src/version.ts via strip-types) and in the published package
 * (dist/src/version.js). Bump the version ONLY in package.json — everything
 * that reports a version (GET /, OpenAPI, agent card, MCP server) imports
 * VERSION from here. server.json is synced by scripts/sync-version.mjs via
 * the `npm version` lifecycle hook.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export const VERSION: string = (() => {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { name?: string; version?: string };
      if (pkg.name === "paysafe-x402" && typeof pkg.version === "string") return pkg.version;
    } catch {
      // keep walking up
    }
    dir = dirname(dir);
  }
  return "0.0.0"; // unreachable in any supported layout; never crash the server over metadata
})();

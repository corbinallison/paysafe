// Copyright (c) 2026 Tollwarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Generates the Ed25519 keypair for MCP registry DNS verification —
 * a no-openssl replacement for the commands in the registry docs.
 *
 * Run:   node scripts/gen-mcp-dns-key.mjs
 *
 * Prints:
 *  1. the TXT record value to add in Namecheap (public key)
 *  2. the private-key hex for `mcp-publisher login dns` — also saved to
 *     ~/tollwarden-mcp-key.hex (OUTSIDE the repo, so it can't be committed).
 *
 * The private key is your namespace credential. Treat it like a password.
 * Running this again generates a NEW key (the old TXT record stops matching).
 */
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const keyFile = join(homedir(), "tollwarden-mcp-key.hex");
if (existsSync(keyFile)) {
  console.error(`A key already exists at ${keyFile}.`);
  console.error("Delete it first if you really want to rotate (your DNS TXT record must be updated to match).");
  process.exit(1);
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
// Raw 32-byte keys live at the tail of the DER encodings.
const privRaw = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);

writeFileSync(keyFile, privRaw.toString("hex"), { mode: 0o600 });

console.log("1) Add this TXT record in Namecheap (Advanced DNS -> Add New Record):");
console.log("   Type: TXT   Host: @");
console.log(`   Value: v=MCPv1; k=ed25519; p=${pubRaw.toString("base64")}`);
console.log("");
console.log(`2) Private key hex saved to: ${keyFile}  (keep it, don't commit it)`);
console.log("");
console.log("3) After the TXT record propagates (~15 min), from the repo root in PowerShell:");
console.log('   .\\mcp-publisher.exe login dns --domain tollwarden.com --private-key (Get-Content ~\\tollwarden-mcp-key.hex)');
console.log("   .\\mcp-publisher.exe publish");

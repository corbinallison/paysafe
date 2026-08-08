// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Generate a THROWAWAY test wallet for the Base Sepolia paid dry-run.
 *
 * Prints a fresh random private key + its address. Fund the address with
 * Base Sepolia test USDC + a little test ETH, then use the key as
 * EVM_PRIVATE_KEY when running `npm run dryrun`.
 *
 * Run:  npm run gen:wallet
 *
 * ┌─ SECURITY ────────────────────────────────────────────────────────────┐
 * │ This key is for TESTNET ONLY. It is printed to your terminal — it is    │
 * │ never saved to a file, committed, or sent anywhere. Do NOT put real     │
 * │ funds in this wallet, and do NOT paste the key into any file or share   │
 * │ it. If it leaks, nothing is lost (it only ever holds test tokens).      │
 * └────────────────────────────────────────────────────────────────────────┘
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const privateKey = generatePrivateKey();
const account = privateKeyToAccount(privateKey);

console.log("\n=== Throwaway Base Sepolia TEST wallet (testnet only) ===\n");
console.log("Address (fund this):");
console.log(`  ${account.address}\n`);
console.log("Private key (keep local, testnet only — never commit or share):");
console.log(`  ${privateKey}\n`);
console.log("Next steps:");
console.log("  1. Fund the ADDRESS above on Base Sepolia:");
console.log("     - Test USDC + a little test ETH from https://portal.cdp.coinbase.com/products/faucet");
console.log("       (pick network: Base Sepolia; request both ETH and USDC)");
console.log("  2. Once funded, run the dry-run with the PRIVATE KEY above:");
console.log("       EVM_PRIVATE_KEY=<private key> TOLLWARDEN_URL=https://tollwarden.com npm run dryrun");
console.log("\n(Reminder: throwaway testnet wallet — do not reuse it for real funds.)\n");

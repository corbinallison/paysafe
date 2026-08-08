// Copyright (c) 2026 Tollwarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * EVM wallet signature verification (EIP-191 personal_sign), used to prove
 * key ownership for reputation disputes: only the holder of a reported
 * wallet's private key can attach a rebuttal to that wallet's record.
 *
 * Why a library at all: Node's crypto has no keccak-256 (its sha3-* are NIST
 * SHA-3 — different padding byte) and no secp256k1 public-key recovery, and
 * EVM signatures verify against an ADDRESS, which requires recovering the
 * pubkey from (r, s, v) and keccak-hashing it. @noble/curves + @noble/hashes
 * are audited, pure-JS, and already resolved in our lockfile via the x402
 * stack — the minimal primitives, not a whole chain SDK.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

/** keccak256("\x19Ethereum Signed Message:\n" + len + message) per EIP-191. */
export function personalSignHash(message: string): Uint8Array {
  const body = Buffer.from(message, "utf8");
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${body.length}`, "utf8");
  return keccak_256(Buffer.concat([prefix, body]));
}

function parseSignature(sigHex: string): { compact: Uint8Array; recovery: number } | null {
  const hex = sigHex.startsWith("0x") ? sigHex.slice(2) : sigHex;
  if (!/^[0-9a-fA-F]{130}$/.test(hex)) return null; // 65 bytes: r(32) s(32) v(1)
  const bytes = Buffer.from(hex, "hex");
  const v = bytes[64];
  const recovery = v >= 27 ? v - 27 : v; // wallets emit 27/28; raw libs emit 0/1
  if (recovery !== 0 && recovery !== 1) return null;
  return { compact: bytes.subarray(0, 64), recovery };
}

/**
 * Recover the checksummed-agnostic (lowercase) signer address of an EIP-191
 * personal_sign signature. Returns null on any malformed input — never throws.
 */
export function recoverPersonalSigner(message: string, signatureHex: string): string | null {
  const parsed = typeof signatureHex === "string" ? parseSignature(signatureHex) : null;
  if (!parsed) return null;
  try {
    const sig = secp256k1.Signature.fromCompact(parsed.compact).addRecoveryBit(parsed.recovery);
    const pub = sig.recoverPublicKey(personalSignHash(message)).toRawBytes(false);
    const addr = keccak_256(pub.subarray(1)).subarray(-20);
    return `0x${Buffer.from(addr).toString("hex")}`;
  } catch {
    return null; // invalid r/s, point not on curve, unrecoverable — all just "no"
  }
}

/** Does this personal_sign signature prove control of `address`? */
export function verifyPersonalSign(address: string, message: string, signatureHex: string): boolean {
  const signer = recoverPersonalSigner(message, signatureHex);
  return signer !== null && signer === address.trim().toLowerCase();
}

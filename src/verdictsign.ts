// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Ed25519 verdict signing. PaySafe signs each verdict so downstream wallet
 * policies can REQUIRE a fresh PaySafe allow-verdict before signing a payment —
 * turning the firewall from advisory into enforceable without PaySafe ever
 * touching funds. Sign/verify is sub-millisecond.
 *
 * Signed message format (pipe-delimited, no JSON canonicalization pitfalls):
 *   scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at
 * plus a second signed evidence record on scan attestations:
 *   evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration
 *
 * Verify (Node):
 *   const key = crypto.createPublicKey({ key: Buffer.from(pubHex, "hex"), format: "der", type: "spki" });
 *   crypto.verify(null, Buffer.from(message), key, Buffer.from(sigHex, "hex"));
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { PinEvidence, ScanResponse, VerdictAttestation } from "./types.ts";

export class VerdictSigner {
  private privateKey: KeyObject;
  readonly publicKeySpkiHex: string;
  readonly createdAt: string;

  /** Persists the signing key under dataDir; ephemeral key when dataDir is null. */
  constructor(dataDir: string | null) {
    const keyFile = dataDir ? join(dataDir, "verdict-key.json") : null;

    if (keyFile && existsSync(keyFile)) {
      const saved = JSON.parse(readFileSync(keyFile, "utf8")) as {
        pkcs8_hex: string;
        created_at: string;
      };
      this.privateKey = createPrivateKey({
        key: Buffer.from(saved.pkcs8_hex, "hex"),
        format: "der",
        type: "pkcs8",
      });
      this.createdAt = saved.created_at;
    } else {
      const { privateKey } = generateKeyPairSync("ed25519");
      this.privateKey = privateKey;
      this.createdAt = new Date().toISOString();
      if (keyFile) {
        mkdirSync(dataDir as string, { recursive: true });
        writeFileSync(
          keyFile,
          JSON.stringify({
            pkcs8_hex: (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("hex"),
            created_at: this.createdAt,
          }),
          { mode: 0o600 },
        );
      }
    }

    const pub = createPublicKey(this.privateKey);
    this.publicKeySpkiHex = (pub.export({ format: "der", type: "spki" }) as Buffer).toString("hex");
  }

  /**
   * Sign the verdict, BINDING it to the specific payment via `commitment`
   * (sha256 of network|pay_to|asset|amount|nonce) and to a short expiry
   * (audit H-1). A verifier must recompute the commitment from the payment it
   * is about to sign and confirm it matches — this prevents replaying an
   * allow-attestation issued for a benign payment against a different one.
   *
   * The verdict message is FROZEN at its 7 fields: deployed verifiers reject
   * any other field count, so new signed facts ride in a SECOND signed record
   * (`evidence`) instead. evidence-v1 carries the merchant-pin facts — pin age
   * and named corroboration sources — bound to the same scan_id + commitment
   * so it can't be lifted onto another attestation. The record is always
   * emitted: SIGNED empty pin fields assert "no pin applies", which a
   * stripped or absent record cannot — verifiers tolerate absence (older
   * servers, overrides), so absence itself proves nothing; a consumer that
   * requires pin evidence must decide its own policy for an attestation
   * without one. Only override attestations omit it deliberately, because
   * approval-time pin state is not scan-time evidence.
   */
  attest(
    scan: ScanResponse,
    commitment: string,
    ttlSeconds = 300,
    pin: PinEvidence | null = null,
  ): VerdictAttestation {
    const expiresAt = new Date(Date.parse(scan.scanned_at) + ttlSeconds * 1000).toISOString();
    const message = [
      scan.scan_id,
      scan.direction,
      scan.verdict,
      scan.risk_score,
      scan.scanned_at,
      commitment,
      expiresAt,
    ].join("|");
    const signature = edSign(null, Buffer.from(message, "utf8"), this.privateKey);
    const evidenceMessage = [
      "evidence-v1",
      scan.scan_id,
      commitment,
      pin ? pin.domain : "",
      pin ? String(pin.age_seconds) : "",
      pin ? (pin.corroboration.length ? pin.corroboration.join(",") : "none") : "",
    ].join("|");
    const evidenceSignature = edSign(null, Buffer.from(evidenceMessage, "utf8"), this.privateKey);
    return {
      alg: "ed25519",
      public_key_spki_hex: this.publicKeySpkiHex,
      message,
      signature_hex: signature.toString("hex"),
      payment_commitment: commitment,
      expires_at: expiresAt,
      evidence: {
        message: evidenceMessage,
        signature_hex: evidenceSignature.toString("hex"),
        pin: pin ? { ...pin, corroboration: [...pin.corroboration] } : null,
      },
    };
  }

  /**
   * Sign a human-approved OVERRIDE verdict (verdict tag "override:allow") for
   * a payment that scanned as flag. Same 7-field message format as attest(),
   * so every existing verifier parses it — but the distinct verdict tag means
   * an override can never masquerade as an organic allow in the signature.
   * TTL is STRUCTURALLY capped at 300s (roadmap constraint: override windows
   * stay short); expiry is computed from the approval time, not the original
   * scan time.
   */
  attestOverride(
    fields: { scan_id: string; direction: string; risk_score: number; approved_at: string },
    commitment: string,
    ttlSeconds = 300,
  ): VerdictAttestation {
    const ttl = Math.min(Math.max(Math.floor(ttlSeconds), 1), 300);
    const expiresAt = new Date(Date.parse(fields.approved_at) + ttl * 1000).toISOString();
    const message = [
      fields.scan_id,
      fields.direction,
      "override:allow",
      fields.risk_score,
      fields.approved_at,
      commitment,
      expiresAt,
    ].join("|");
    const signature = edSign(null, Buffer.from(message, "utf8"), this.privateKey);
    return {
      alg: "ed25519",
      public_key_spki_hex: this.publicKeySpkiHex,
      message,
      signature_hex: signature.toString("hex"),
      payment_commitment: commitment,
      expires_at: expiresAt,
    };
  }

  publicKeyInfo(): object {
    return {
      alg: "ed25519",
      public_key_spki_hex: this.publicKeySpkiHex,
      created_at: this.createdAt,
      message_format: "scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at",
      payment_commitment: "sha256(network|pay_to(lowercased)|asset(lowercased)|amount|nonce)",
      evidence_format:
        "evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration — a second signed record on scan attestations (same key). pin_age_seconds is how long the domain↔pay_to pin had held at scan time (0 = first sighting); pin_corroboration NAMES the out-of-band sources that corroborated the pin ('none', or a comma-joined list — today: cdp_bazaar), never a boolean or a score. Empty pin fields = no pin applies to this payee. Verify: signature over the evidence message with this key, then confirm its scan_id and payment_commitment equal the verdict message's; it shares the attestation's expiry. Whether a young or uncorroborated pin is acceptable is YOUR decision boundary — weigh it against the payment size.",
      usage:
        "Before signing a payment, a wallet policy should: (1) verify the Ed25519 signature over `message` with this key, (2) recompute payment_commitment from the payment and confirm it equals the attested value, (3) confirm verdict=allow and now < expires_at. Human-approved overrides carry the distinct verdict tag 'override:allow' (never plain 'allow') with a <=300s expiry — accept them only if your policy opts in.",
    };
  }
}

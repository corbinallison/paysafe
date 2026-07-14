/**
 * Ed25519 verdict signing. PaySafe signs each verdict so downstream wallet
 * policies can REQUIRE a fresh PaySafe allow-verdict before signing a payment —
 * turning the firewall from advisory into enforceable without PaySafe ever
 * touching funds. Sign/verify is sub-millisecond.
 *
 * Signed message format (pipe-delimited, no JSON canonicalization pitfalls):
 *   scan_id|direction|verdict|risk_score|scanned_at
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
import type { ScanResponse, VerdictAttestation } from "./types.ts";

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

  attest(scan: ScanResponse): VerdictAttestation {
    const message = [scan.scan_id, scan.direction, scan.verdict, scan.risk_score, scan.scanned_at].join("|");
    const signature = edSign(null, Buffer.from(message, "utf8"), this.privateKey);
    return {
      alg: "ed25519",
      public_key_spki_hex: this.publicKeySpkiHex,
      message,
      signature_hex: signature.toString("hex"),
    };
  }

  publicKeyInfo(): object {
    return {
      alg: "ed25519",
      public_key_spki_hex: this.publicKeySpkiHex,
      created_at: this.createdAt,
      message_format: "scan_id|direction|verdict|risk_score|scanned_at",
      usage:
        "Wallet policies can require a PaySafe attestation with verdict=allow and a recent scanned_at before signing a payment.",
    };
  }
}

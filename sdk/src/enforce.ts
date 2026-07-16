/**
 * Wallet-side enforcement kit.
 *
 * Turns PaySafe from advisory into ENFORCED: a wrapped signer physically
 * refuses to sign an x402 payment authorization unless a fresh, Ed25519-
 * verified PaySafe allow-verdict exists for exactly that payment. Because the
 * verdict's payment commitment — sha256(network|pay_to|asset|amount|nonce) —
 * is recomputed from the typed data the wallet is being asked to sign, a
 * compromised agent cannot scan one payment and settle another: any change to
 * the recipient, amount, asset, chain, or nonce changes the commitment and
 * the signature is refused.
 *
 *   const paysafe  = new PaySafeClient({ agentId: "my-agent" });
 *   const enforcer = new PaySafeEnforcer({ trustedKeyHex: PINNED_KEY });
 *   const account  = enforcer.guardSigner(privateKeyToAccount(PRIVATE_KEY));
 *
 *   const scan = await paysafe.guardOutgoing(payment);  // throws on block
 *   enforcer.approve(scan, payment);                    // registers the verdict
 *   // ... hand `account` to your x402 client as usual. It will only ever
 *   // sign authorizations whose commitment carries a live allow-verdict.
 *
 * Design notes:
 *  - Zero dependencies, signer-agnostic: anything with a `signTypedData`
 *    method works (viem accounts/wallet clients, ethers v6 signers, custom).
 *    The wrapper is a Proxy — every other property/method passes through.
 *  - Recognized payment types: EIP-3009 TransferWithAuthorization /
 *    ReceiveWithAuthorization (the x402 "exact" scheme on EVM) and ERC-2612
 *    Permit. Other typed data passes through by default; set
 *    `strictTypes: true` to refuse everything unrecognized (deny-by-default).
 *  - Approvals are SINGLE-USE by default and expire with the attestation
 *    (plus an optional tighter `maxAgeMs`), so a verdict can't be hoarded.
 *  - Enforcement never phones home: approval happens locally against the
 *    pinned key. If PaySafe is unreachable, nothing new can be approved —
 *    fail-closed, which is the point.
 */
import {
  computePaymentCommitment,
  verifyAttestation,
  type PaymentDetails,
  type ScanResponse,
  type VerdictAttestation,
} from "./index.ts";

// ---------------------------------------------------------------------------
// Typed-data shapes (structural — no viem/ethers dependency)
// ---------------------------------------------------------------------------
export interface Eip712DomainLike {
  name?: string;
  version?: string;
  chainId?: number | bigint | string;
  verifyingContract?: string;
}

export interface TypedDataLike {
  domain?: Eip712DomainLike;
  types?: Record<string, unknown>;
  primaryType?: string;
  message?: Record<string, unknown>;
}

/** Anything with a signTypedData method (viem account, ethers signer, ...). */
export interface TypedDataSigner {
  signTypedData(...args: unknown[]): Promise<unknown>;
}

export interface EnforcerOptions {
  /** PINNED PaySafe verdict key (hex SPKI DER, from /.well-known/paysafe-verdict-key).
   * Required — enforcement without a pinned key would trust whatever key a
   * forged response embeds. */
  trustedKeyHex: string;
  /** Also accept "flag" verdicts (default false: allow-only). */
  allowFlagged?: boolean;
  /** Tighter freshness bound than the attestation's own expires_at, measured
   * from approve() time. Optional. */
  maxAgeMs?: number;
  /** Let one approval sign multiple times (default false: single-use). */
  reusable?: boolean;
  /** Refuse to sign ANY typed data that isn't a recognized payment
   * authorization (default false: unrecognized types pass through). */
  strictTypes?: boolean;
}

export class PaySafeEnforcementError extends Error {
  readonly commitment?: string;
  readonly primaryType?: string;
  constructor(message: string, info: { commitment?: string; primaryType?: string } = {}) {
    super(message);
    this.name = "PaySafeEnforcementError";
    this.commitment = info.commitment;
    this.primaryType = info.primaryType;
  }
}

interface Approval {
  attestation: VerdictAttestation;
  scanId: string;
  verdict: string;
  approvedAt: number;
  used: boolean;
}

/**
 * Map an EIP-712 payload to the payment fields the commitment binds.
 * Returns null for typed data that is not a recognized payment authorization.
 */
export function paymentFromTypedData(td: TypedDataLike): PaymentDetails | null {
  const pt = td.primaryType;
  if (!pt) return null;
  const m = td.message ?? {};
  const d = td.domain ?? {};
  const s = (v: unknown): string =>
    typeof v === "string" ? v : typeof v === "number" || typeof v === "bigint" ? String(v) : "";
  const network = d.chainId !== undefined && d.chainId !== null && s(d.chainId) !== "" ? `eip155:${s(d.chainId)}` : "";
  const asset = typeof d.verifyingContract === "string" ? d.verifyingContract : "";

  // EIP-3009 — how the x402 "exact" scheme authorizes USDC transfers on EVM.
  if (pt === "TransferWithAuthorization" || pt === "ReceiveWithAuthorization") {
    return { network, asset, pay_to: s(m.to), payer: s(m.from), amount: s(m.value), nonce: s(m.nonce) };
  }
  // ERC-2612 Permit — a spend approval is a payment authorization too.
  if (pt === "Permit") {
    return { network, asset, pay_to: s(m.spender), payer: s(m.owner), amount: s(m.value), nonce: s(m.nonce) };
  }
  return null;
}

export class PaySafeEnforcer {
  private readonly trustedKeyHex: string;
  private readonly allowFlagged: boolean;
  private readonly maxAgeMs: number | null;
  private readonly reusable: boolean;
  private readonly strictTypes: boolean;
  private readonly approvals = new Map<string, Approval>();

  constructor(opts: EnforcerOptions) {
    if (!opts.trustedKeyHex) {
      throw new PaySafeEnforcementError(
        "trustedKeyHex is required: pin the PaySafe verdict key (GET /.well-known/paysafe-verdict-key) — enforcement must never trust a key embedded in a response.",
      );
    }
    this.trustedKeyHex = opts.trustedKeyHex;
    this.allowFlagged = opts.allowFlagged ?? false;
    this.maxAgeMs = opts.maxAgeMs ?? null;
    this.reusable = opts.reusable ?? false;
    this.strictTypes = opts.strictTypes ?? false;
  }

  /**
   * Register a scan verdict as signing authority for its payment. Verifies the
   * attestation against the PINNED key (signature, field match, commitment,
   * expiry — throws AttestationError on any failure), then requires an allow
   * verdict (or flag with allowFlagged). Returns the payment commitment.
   */
  approve(scan: ScanResponse, payment: PaymentDetails): string {
    verifyAttestation(scan, payment, this.trustedKeyHex);
    if (scan.verdict !== "allow" && !(scan.verdict === "flag" && this.allowFlagged)) {
      throw new PaySafeEnforcementError(
        `refusing to approve a "${scan.verdict}" verdict for signing${scan.verdict === "flag" ? " (set allowFlagged to accept flags)" : ""}`,
      );
    }
    const commitment = computePaymentCommitment(payment);
    this.approvals.set(commitment, {
      attestation: scan.attestation as VerdictAttestation,
      scanId: scan.scan_id,
      verdict: scan.verdict,
      approvedAt: Date.now(),
      used: false,
    });
    return commitment;
  }

  /** Withdraw signing authority for a commitment. */
  revoke(commitment: string): void {
    this.approvals.delete(commitment);
  }

  /** Drop all approvals. */
  clear(): void {
    this.approvals.clear();
  }

  /**
   * The sign-time gate. Throws PaySafeEnforcementError unless a live,
   * unexpired (and unused, unless reusable) approval exists for this
   * commitment; consumes it on success.
   */
  assertApproved(commitment: string, primaryType?: string): void {
    const a = this.approvals.get(commitment);
    if (!a) {
      throw new PaySafeEnforcementError(
        `no PaySafe allow-verdict for this payment authorization (commitment ${commitment.slice(0, 16)}…). ` +
          `Scan the payment and call enforcer.approve(scan, payment) first. If the payment was scanned, its ` +
          `recipient/amount/asset/chain/nonce differs from what is now being signed — which is exactly what this gate exists to catch.`,
        { commitment, primaryType },
      );
    }
    if (a.used && !this.reusable) {
      throw new PaySafeEnforcementError(
        `this allow-verdict was already used to sign once (scan ${a.scanId}); approvals are single-use. Re-scan to sign again.`,
        { commitment, primaryType },
      );
    }
    const expiresAt = Date.parse(a.attestation.expires_at);
    const staleAt = this.maxAgeMs !== null ? a.approvedAt + this.maxAgeMs : Infinity;
    const deadline = Math.min(expiresAt, staleAt);
    if (Date.now() >= deadline) {
      this.approvals.delete(commitment);
      throw new PaySafeEnforcementError(
        `the allow-verdict for this payment is stale (scan ${a.scanId}, deadline ${new Date(deadline).toISOString()}). Re-scan to obtain a fresh verdict.`,
        { commitment, primaryType },
      );
    }
    a.used = true;
  }

  /**
   * Wrap a signer so signTypedData refuses x402/EIP-3009/Permit payment
   * authorizations that lack a live approval. Every other property and method
   * of the signer passes through untouched (Proxy), so the wrapped signer is
   * a drop-in replacement for viem accounts, ethers signers, etc.
   *
   * Scope: this guards the typed-data path x402 uses. If your signer exposes
   * other fund-moving paths (signTransaction), gate those at your policy
   * layer too.
   */
  guardSigner<T extends TypedDataSigner>(signer: T): T {
    // viem calls account.signTypedData(typedData); ethers v6 uses
    // signer.signTypedData(domain, types, message). Support both shapes.
    const enforcer = this;
    const wrapped = async function (this: unknown, ...args: unknown[]): Promise<unknown> {
      const td: TypedDataLike =
        args.length >= 3
          ? { domain: args[0] as Eip712DomainLike, types: args[1] as Record<string, unknown>, message: args[2] as Record<string, unknown>, primaryType: inferPrimaryType(args[1]) }
          : ((args[0] ?? {}) as TypedDataLike);
      const payment = paymentFromTypedData(td);
      if (payment === null) {
        if (enforcer.strictTypes) {
          throw new PaySafeEnforcementError(
            `strictTypes: refusing to sign unrecognized typed data (primaryType ${td.primaryType ?? "unknown"})`,
            { primaryType: td.primaryType },
          );
        }
        return signer.signTypedData(...args);
      }
      enforcer.assertApproved(computePaymentCommitment(payment), td.primaryType);
      return signer.signTypedData(...args);
    };
    return new Proxy(signer, {
      get(target, prop, receiver) {
        if (prop === "signTypedData") return wrapped;
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  }
}

/** ethers v6 passes (domain, types, message) with no primaryType — infer it
 * as the type that no other type references (EIP-712 convention). */
function inferPrimaryType(types: unknown): string | undefined {
  if (typeof types !== "object" || types === null) return undefined;
  const names = Object.keys(types as Record<string, unknown>).filter((n) => n !== "EIP712Domain");
  const referenced = new Set<string>();
  for (const n of names) {
    const fields = (types as Record<string, unknown>)[n];
    if (!Array.isArray(fields)) continue;
    for (const f of fields) {
      const t = (f as { type?: string })?.type ?? "";
      referenced.add(t.replace(/\[\]$/, ""));
    }
  }
  return names.find((n) => !referenced.has(n)) ?? names[0];
}

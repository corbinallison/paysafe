/**
 * paysafe-x402-client — official client SDK for PaySafe, the payment security
 * firewall for x402 micropayments (https://paysafe-agent.com).
 *
 * Zero runtime dependencies. Node 18+ (global fetch; node:crypto for Ed25519).
 *
 * What it adds over raw HTTP:
 *  - Provenance auto-tagging: call `observe()` whenever your agent reads
 *    external content (tool results, fetched pages); scans are automatically
 *    tagged with `context.origin` + the content, which powers PaySafe's
 *    prompt-injection-triggered-payment detection.
 *  - API key management: mints a key on first use, tracks the free-call quota.
 *  - Plans: subscribe/renew autonomously when constructed with an x402
 *    payment-capable fetch (e.g. wrapFetchWithPayment from @x402/fetch).
 *  - Attestation verification: every scan response's Ed25519 attestation is
 *    checked against a pinned server key, the payment commitment is recomputed
 *    locally, and expiry is enforced — so a tampered or replayed verdict fails.
 *
 * Quick start:
 *   import { PaySafeClient } from "paysafe-x402-client";
 *   const paysafe = new PaySafeClient();
 *   paysafe.observe(toolResultText, { sourceUrl: "https://api.example.com" });
 *   const scan = await paysafe.guardOutgoing(payment, { expectedPriceUsd: 0.01 });
 *   // throws PaySafeBlockedError on a block verdict; otherwise safe to settle
 */
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

// Wallet-side enforcement kit: PaySafeEnforcer, guardSigner, paymentFromTypedData.
export * from "./enforce.ts";
// Default-payment-path wrapper: wrapFetchWithPaySafe (scan before every x402 payment).
export * from "./wrap.ts";

// ---------------------------------------------------------------------------
// Types (mirrors the server's public API)
// ---------------------------------------------------------------------------
export type Verdict = "allow" | "flag" | "block" | "override:allow";
export type PaymentOrigin = "planning" | "user_instruction" | "tool_result" | "fetched_content" | "unknown";

export interface PaymentDetails {
  scheme?: string;
  network?: string;
  asset?: string;
  amount?: string;
  amount_usd?: number;
  asset_decimals?: number;
  pay_to?: string;
  payer?: string;
  resource_url?: string;
  description?: string;
  reason?: string;
  nonce?: string;
  valid_until?: string;
  metadata?: Record<string, string>;
}

export interface CheckResult {
  id: string;
  name: string;
  verdict: Verdict;
  severity: "info" | "low" | "medium" | "high" | "critical";
  reason: string;
  details?: Record<string, unknown>;
}

export interface VerdictAttestation {
  alg: "ed25519";
  public_key_spki_hex: string;
  message: string;
  signature_hex: string;
  payment_commitment: string;
  expires_at: string;
}

export interface ScanResponse {
  scan_id: string;
  direction: "outgoing" | "incoming";
  verdict: Verdict;
  risk_score: number;
  checks: CheckResult[];
  scanned_at: string;
  advisory: string;
  attestation?: VerdictAttestation;
  /** Added by the SDK: result of local attestation verification (absent when verification is disabled). */
  attestation_verified?: boolean;
  /** Present on a flag verdict when the key has human-in-the-loop approvals
   * configured: a human is being asked to decide. Poll with waitForApproval(). */
  approval?: PendingApproval;
}

/** Attached to a flag scan when the operator has approvals configured. */
export interface PendingApproval {
  approval_id: string;
  status: "pending";
  expires_at: string;
  poll: string;
  note: string;
}

/** GET /v1/approvals/{id} response shape. */
export interface ApprovalState {
  approval_id: string;
  scan_id: string;
  status: "pending" | "approved" | "denied" | "expired";
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  /** Scan-shaped override (verdict "override:allow" + attestation), present when approved. */
  override?: ScanResponse;
}

export interface ScanOptions {
  agentId?: string;
  expectedPriceUsd?: number;
  /** Explicit provenance; overrides the automatic observation-based tagging. */
  context?: { origin?: PaymentOrigin; content?: string; content_source_url?: string };
  policy?: { force_deep?: boolean; skip_deep?: boolean };
  /** With guard*: also throw on "flag" verdicts (default: only "block"). */
  strict?: boolean;
}

export interface PlanInfo {
  id: string;
  name: string;
  price: string;
  duration_days: number | null;
  description: string;
  limits: Record<string, unknown>;
}

export interface ClientOptions {
  /** Service base URL. Default: https://paysafe-agent.com */
  baseUrl?: string;
  /** Existing API key. If omitted and autoKey is on, one is minted on first use. */
  apiKey?: string;
  /** Mint an API key automatically on first use (100 free calls). Default: true. */
  autoKey?: boolean;
  /** Stable agent identifier — scopes PaySafe's velocity limits to your agent. */
  agentId?: string;
  /**
   * fetch implementation. Pass an x402 payment-capable fetch (e.g.
   * wrapFetchWithPayment from @x402/fetch) to transparently pay for scans
   * beyond the free tier and for plan subscriptions. Default: global fetch.
   */
  fetch?: typeof fetch;
  /** Origin used when no observation/explicit context exists. Default: "unknown". */
  defaultOrigin?: PaymentOrigin;
  /** How long an observation stays "recent" for auto-tagging. Default: 5 minutes. */
  observationTtlMs?: number;
  /** Max bytes of observed content attached to a scan. Default: 8192. */
  maxContentBytes?: number;
  /** Verify each scan's Ed25519 attestation against the pinned server key. Default: true. */
  verifyAttestations?: boolean;
  /** Pin the server verdict key (hex SPKI DER). Default: fetched once from /.well-known/paysafe-verdict-key. */
  verdictKeyHex?: string;
  /** Re-subscribe automatically when the active plan is within renewWindowMs of expiry. Default: false (spends money). */
  autoRenew?: boolean;
  /** Renewal window. Default: 24h. */
  renewWindowMs?: number;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
export class PaySafeError extends Error {
  readonly status?: number;
  readonly body?: unknown;
  constructor(message: string, status?: number, body?: unknown) {
    super(message);
    this.name = "PaySafeError";
    this.status = status;
    this.body = body;
  }
}

/** Thrown by guardOutgoing/guardIncoming when the verdict is block (or flag in strict mode). */
export class PaySafeBlockedError extends PaySafeError {
  readonly scan: ScanResponse;
  constructor(scan: ScanResponse) {
    super(
      `PaySafe verdict: ${scan.verdict} (risk ${scan.risk_score}). ` +
        scan.checks
          .filter((c) => c.verdict !== "allow")
          .map((c) => `${c.id}: ${c.reason}`)
          .join("; "),
    );
    this.name = "PaySafeBlockedError";
    this.scan = scan;
  }
}

export class AttestationError extends PaySafeError {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

// ---------------------------------------------------------------------------
// Attestation verification (standalone — usable without a client instance)
// ---------------------------------------------------------------------------

/** Recomputes the server's payment commitment: sha256(network|pay_to↓|asset↓|amount|nonce). */
export function computePaymentCommitment(p: PaymentDetails): string {
  const amount =
    p.amount !== undefined ? String(p.amount)
    : p.amount_usd !== undefined ? `usd:${p.amount_usd}`
    : "";
  const canonical = [
    p.network ?? "",
    (p.pay_to ?? "").toLowerCase(),
    (p.asset ?? "").toLowerCase(),
    amount,
    p.nonce ?? "",
  ].join("|");
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * Full attestation check. Returns silently on success; throws AttestationError
 * with a specific reason on any failure. Checks, in order:
 *  1. signature over `message` verifies under `trustedKeyHex` (the PINNED key —
 *     never the key embedded in the response, which an attacker controls);
 *  2. message fields match the scan (id, direction, verdict, risk, time);
 *  3. the commitment in the message matches one recomputed from `payment`;
 *  4. the attestation has not expired.
 */
export function verifyAttestation(
  scan: ScanResponse,
  payment: PaymentDetails,
  trustedKeyHex: string,
  now: Date = new Date(),
): void {
  const att = scan.attestation;
  if (!att) throw new AttestationError("scan carries no attestation");

  let ok = false;
  try {
    const key = createPublicKey({ key: Buffer.from(trustedKeyHex, "hex"), format: "der", type: "spki" });
    ok = edVerify(null, Buffer.from(att.message, "utf8"), key, Buffer.from(att.signature_hex, "hex"));
  } catch (e) {
    throw new AttestationError(`signature check failed to run: ${(e as Error).message}`);
  }
  if (!ok) throw new AttestationError("Ed25519 signature invalid under the pinned server key");

  const [scanId, direction, verdict, risk, scannedAt, commitment, expiresAt] = att.message.split("|");
  if (scanId !== scan.scan_id || direction !== scan.direction || verdict !== scan.verdict ||
      Number(risk) !== scan.risk_score || scannedAt !== scan.scanned_at) {
    throw new AttestationError("attested message does not match the scan response fields");
  }
  const recomputed = computePaymentCommitment(payment);
  if (commitment !== recomputed) {
    throw new AttestationError(
      "payment commitment mismatch — this attestation was issued for a DIFFERENT payment (possible attestation replay)",
    );
  }
  if (Date.parse(expiresAt) <= now.getTime()) {
    throw new AttestationError(`attestation expired at ${expiresAt}`);
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
interface Observation {
  content: string;
  sourceUrl?: string;
  kind: "tool_result" | "fetched_content";
  at: number;
}

export class PaySafeClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly autoKey: boolean;
  private readonly agentId?: string;
  private readonly defaultOrigin: PaymentOrigin;
  private readonly observationTtlMs: number;
  private readonly maxContentBytes: number;
  private readonly shouldVerify: boolean;
  private readonly autoRenew: boolean;
  private readonly renewWindowMs: number;

  private apiKey?: string;
  private pinnedKeyHex?: string;
  private lastObservation: Observation | null = null;
  private explicitOrigin: PaymentOrigin | null = null;

  /** Free calls left on the current key, per the last response header (null = unknown). */
  freeCallsRemaining: number | null = null;
  /** Active plan state, tracked from subscribe() responses. */
  plan: { id: string; expires_at: string } | null = null;

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://paysafe-agent.com").replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? fetch;
    this.apiKey = opts.apiKey;
    this.autoKey = opts.autoKey ?? true;
    this.agentId = opts.agentId;
    this.defaultOrigin = opts.defaultOrigin ?? "unknown";
    this.observationTtlMs = opts.observationTtlMs ?? 5 * 60_000;
    this.maxContentBytes = opts.maxContentBytes ?? 8192;
    this.shouldVerify = opts.verifyAttestations ?? true;
    this.pinnedKeyHex = opts.verdictKeyHex;
    this.autoRenew = opts.autoRenew ?? false;
    this.renewWindowMs = opts.renewWindowMs ?? 24 * 3600_000;
  }

  // -- provenance -----------------------------------------------------------

  /**
   * Record that the agent just read external content. Call this after every
   * tool result / fetched page your agent processes; the next scan within the
   * observation TTL is tagged with it, enabling injection-triggered-payment
   * detection. Content is truncated to maxContentBytes.
   */
  observe(content: string, meta: { sourceUrl?: string; kind?: "tool_result" | "fetched_content" } = {}): void {
    this.lastObservation = {
      content: content.slice(0, this.maxContentBytes),
      sourceUrl: meta.sourceUrl,
      kind: meta.kind ?? (meta.sourceUrl ? "fetched_content" : "tool_result"),
      at: Date.now(),
    };
    this.explicitOrigin = null;
  }

  /** Mark that the NEXT payment decision came from the agent's own planning step. */
  notePlanning(): void {
    this.explicitOrigin = "planning";
    this.lastObservation = null;
  }

  /** Mark that the NEXT payment decision came from an explicit human instruction. */
  noteUserInstruction(): void {
    this.explicitOrigin = "user_instruction";
    this.lastObservation = null;
  }

  private buildContext(explicit?: ScanOptions["context"]): { origin: PaymentOrigin; content?: string; content_source_url?: string } {
    if (explicit) return { origin: explicit.origin ?? this.defaultOrigin, content: explicit.content, content_source_url: explicit.content_source_url };
    if (this.explicitOrigin) return { origin: this.explicitOrigin };
    const obs = this.lastObservation;
    if (obs && Date.now() - obs.at <= this.observationTtlMs) {
      return { origin: obs.kind, content: obs.content, content_source_url: obs.sourceUrl };
    }
    return { origin: this.defaultOrigin };
  }

  // -- plumbing --------------------------------------------------------------

  private async request(method: string, path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    return this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  private async requestJson<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.request(method, path, body);
    const remaining = res.headers.get("x-free-calls-remaining");
    if (remaining !== null) this.freeCallsRemaining = Number(remaining);
    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      /* non-JSON error body */
    }
    if (!res.ok) {
      const msg = (parsed as { error?: string } | null)?.error ?? `HTTP ${res.status}`;
      if (res.status === 402) {
        throw new PaySafeError(
          "Payment required and this client's fetch cannot pay. Construct PaySafeClient with an x402 payment-capable fetch (e.g. wrapFetchWithPayment from @x402/fetch), supply an API key with free calls remaining, or subscribe to a plan.",
          402,
          parsed,
        );
      }
      throw new PaySafeError(msg, res.status, parsed);
    }
    return parsed as T;
  }

  /** Mint an API key if none is set (autoKey). Returns the active key. */
  async ensureApiKey(): Promise<string> {
    if (this.apiKey) return this.apiKey;
    if (!this.autoKey) throw new PaySafeError("no API key set and autoKey is disabled");
    const r = await this.requestJson<{ api_key: string; free_calls_remaining?: number }>(
      "POST",
      "/v1/keys",
      this.agentId ? { agent_id: this.agentId } : {},
    );
    this.apiKey = r.api_key;
    if (typeof r.free_calls_remaining === "number") this.freeCallsRemaining = r.free_calls_remaining;
    return this.apiKey;
  }

  /** The pinned verdict key (fetched once from /.well-known/paysafe-verdict-key unless supplied). */
  async verdictKey(): Promise<string> {
    if (this.pinnedKeyHex) return this.pinnedKeyHex;
    const r = await this.requestJson<{ public_key_spki_hex: string }>("GET", "/.well-known/paysafe-verdict-key");
    this.pinnedKeyHex = r.public_key_spki_hex;
    return this.pinnedKeyHex;
  }

  // -- scans -----------------------------------------------------------------

  private async scan(direction: "outgoing" | "incoming", payment: PaymentDetails, opts: ScanOptions = {}): Promise<ScanResponse> {
    await this.ensureApiKey().catch(() => undefined); // scanning without a key still works via x402-paid fetch
    await this.maybeRenew();
    const body = {
      agent_id: opts.agentId ?? this.agentId,
      payment,
      expected_price_usd: opts.expectedPriceUsd,
      context: this.buildContext(opts.context),
      policy: opts.policy,
    };
    const scan = await this.requestJson<ScanResponse>("POST", `/v1/scan/${direction}`, body);
    if (this.shouldVerify && scan.attestation) {
      verifyAttestation(scan, payment, await this.verdictKey()); // throws on tamper/replay/expiry
      scan.attestation_verified = true;
    }
    // A consumed observation shouldn't leak provenance onto unrelated later scans.
    this.lastObservation = null;
    this.explicitOrigin = null;
    return scan;
  }

  /** Scan a payment the agent is about to make. Returns the verdict; never throws on flag/block. */
  scanOutgoing(payment: PaymentDetails, opts?: ScanOptions): Promise<ScanResponse> {
    return this.scan("outgoing", payment, opts);
  }

  /** Scan a 402 offer / payment request the agent received. */
  scanIncoming(payment: PaymentDetails, opts?: ScanOptions): Promise<ScanResponse> {
    return this.scan("incoming", payment, opts);
  }

  /** Scan and THROW PaySafeBlockedError on block (and on flag when opts.strict). */
  async guardOutgoing(payment: PaymentDetails, opts: ScanOptions = {}): Promise<ScanResponse> {
    const scan = await this.scan("outgoing", payment, opts);
    if (scan.verdict === "block" || (opts.strict && scan.verdict === "flag")) throw new PaySafeBlockedError(scan);
    return scan;
  }

  /** Scan an incoming offer and THROW on block (and on flag when opts.strict). */
  async guardIncoming(payment: PaymentDetails, opts: ScanOptions = {}): Promise<ScanResponse> {
    const scan = await this.scan("incoming", payment, opts);
    if (scan.verdict === "block" || (opts.strict && scan.verdict === "flag")) throw new PaySafeBlockedError(scan);
    return scan;
  }

  // -- human-in-the-loop approvals ---------------------------------------------

  /**
   * Wait for a human decision on a flagged scan (requires the operator to have
   * configured approvals via POST /v1/approvals/config). Polls until approved,
   * denied, expired, or timeout.
   *
   *   const scan = await paysafe.scanOutgoing(payment);
   *   if (scan.verdict === "flag" && scan.approval) {
   *     const override = await paysafe.waitForApproval(scan, { payment });
   *     enforcer.approve(override, payment); // needs acceptOverrides: true
   *   }
   *
   * Returns the override scan-shaped object (verdict "override:allow", signed
   * attestation bound to the payment commitment). Throws PaySafeError on deny/
   * expiry/timeout. When opts.payment is supplied (recommended) and this client
   * verifies attestations, the override is verified against the pinned key and
   * that exact payment before being returned.
   */
  async waitForApproval(
    scanOrId: ScanResponse | string,
    opts: { timeoutMs?: number; intervalMs?: number; payment?: PaymentDetails } = {},
  ): Promise<ScanResponse> {
    const approvalId = typeof scanOrId === "string" ? scanOrId : scanOrId.approval?.approval_id;
    if (!approvalId) {
      throw new PaySafeError(
        "no approval to wait for: the scan carries no `approval` (either the verdict was not flag, or the key has no approvals config — POST /v1/approvals/config first)",
      );
    }
    const timeoutMs = opts.timeoutMs ?? 600_000; // matches the default pending TTL
    const intervalMs = Math.max(opts.intervalMs ?? 3000, 250);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const state = await this.requestJson<ApprovalState>("GET", `/v1/approvals/${encodeURIComponent(approvalId)}`);
      if (state.status === "approved" && state.override) {
        if (this.shouldVerify && state.override.attestation && opts.payment) {
          verifyAttestation(state.override, opts.payment, await this.verdictKey());
          state.override.attestation_verified = true;
        }
        return state.override;
      }
      if (state.status === "denied") throw new PaySafeError(`approval ${approvalId} was DENIED by the operator`, 403, state);
      if (state.status === "expired") throw new PaySafeError(`approval ${approvalId} expired before a decision`, 410, state);
      if (Date.now() + intervalMs > deadline) throw new PaySafeError(`timed out waiting for approval ${approvalId}`, 408, state);
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  /**
   * Configure (or disable, with webhookUrl: null) human-in-the-loop approvals
   * for this key. Returns the webhook signing secret ONCE — store it; every
   * delivery carries X-PaySafe-Signature: sha256=HMAC-SHA256(secret, body).
   * SECURITY: the decide link each delivery carries is a bearer credential —
   * point the webhook somewhere the agent itself cannot read.
   */
  async configureApprovals(webhookUrl: string | null, opts: { format?: "json" | "slack" } = {}): Promise<{ enabled: boolean; webhook_secret?: string }> {
    await this.ensureApiKey();
    return this.requestJson("POST", "/v1/approvals/config", { webhook_url: webhookUrl, format: opts.format });
  }

  // -- delivery outcomes ---------------------------------------------------------

  /**
   * Record whether a scanned, settled payment actually DELIVERED. The report
   * is bound to the scan (scan_id + payment_commitment), so delivery history
   * can't be fabricated without real, scanned payments. One outcome per scan.
   * The payment-path wrapper (wrapFetchWithPaySafe) calls this automatically;
   * call it yourself when you settle payments some other way.
   */
  async reportOutcome(
    scan: ScanResponse,
    outcome: "delivered" | "not_delivered" | "partial" | "wrong_content",
    evidence?: { status?: number; contentType?: string; bytes?: number; latencyMs?: number },
  ): Promise<unknown> {
    const commitment = scan.attestation?.payment_commitment;
    if (!commitment) {
      throw new PaySafeError("cannot report an outcome: the scan carries no attestation/payment_commitment (verdict signing disabled?)");
    }
    return this.requestJson("POST", "/v1/outcomes", {
      scan_id: scan.scan_id,
      payment_commitment: commitment,
      outcome,
      evidence: evidence
        ? { status: evidence.status, content_type: evidence.contentType, bytes: evidence.bytes, latency_ms: evidence.latencyMs }
        : undefined,
    });
  }

  // -- reputation --------------------------------------------------------------

  /** File a counterparty report (always free). */
  async report(input: { address: string; category: string; reason: string; reporterAgentId?: string; evidenceUrl?: string }): Promise<unknown> {
    return this.requestJson("POST", "/v1/reputation/report", {
      address: input.address,
      category: input.category,
      reason: input.reason,
      reporter_agent_id: input.reporterAgentId ?? this.agentId ?? "paysafe-x402-client",
      evidence_url: input.evidenceUrl,
    });
  }

  /** Counterparty report summary (paid / free-tier). */
  async reputation(address: string): Promise<unknown> {
    await this.ensureApiKey().catch(() => undefined);
    return this.requestJson("GET", `/v1/reputation/${encodeURIComponent(address)}`);
  }

  // -- plans --------------------------------------------------------------------

  /** Machine-readable plan catalog (free). */
  async getPlans(): Promise<{ plans: PlanInfo[]; hard_ceilings: Record<string, number> }> {
    return this.requestJson("GET", "/v1/plans");
  }

  /**
   * Subscribe the current key to a plan (or renew it). Requires an x402
   * payment-capable fetch — the endpoint is paid at the plan's price. A key is
   * minted first if none exists.
   */
  async subscribe(planId: string): Promise<{ plan: string; expires_at: string }> {
    await this.ensureApiKey();
    const r = await this.requestJson<{ plan: string; expires_at: string; api_key?: string }>(
      "POST",
      "/v1/plans/subscribe",
      { plan: planId, agent_id: this.agentId },
    );
    if (r.api_key) this.apiKey = r.api_key;
    this.plan = { id: r.plan, expires_at: r.expires_at };
    return { plan: r.plan, expires_at: r.expires_at };
  }

  private renewWarned = false;
  private async maybeRenew(): Promise<void> {
    if (!this.autoRenew || !this.plan) return;
    const msLeft = Date.parse(this.plan.expires_at) - Date.now();
    if (msLeft > this.renewWindowMs) return;
    try {
      await this.subscribe(this.plan.id);
    } catch (e) {
      if (!this.renewWarned) {
        this.renewWarned = true;
        console.warn(`paysafe-x402-client: plan auto-renewal failed (${(e as Error).message}); continuing on default tier after expiry.`);
      }
    }
  }
}

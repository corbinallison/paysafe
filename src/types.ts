/** PaySafe core types. Zero runtime dependencies. */

export type Verdict = "allow" | "flag" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Direction = "outgoing" | "incoming";

export type PaymentOrigin =
  | "planning"          // agent's own planning/deliberation step
  | "user_instruction"  // explicit human instruction
  | "tool_result"       // decision was formed after reading a tool result
  | "fetched_content"   // decision was formed after reading a fetched page/doc
  | "unknown";

export interface PaymentDetails {
  /** x402 scheme, e.g. "exact" */
  scheme?: string;
  /** CAIP-2 network id, e.g. "eip155:8453" */
  network?: string;
  /** Token contract address (e.g. USDC) */
  asset?: string;
  /** Amount in atomic token units (string), e.g. "10000" = $0.01 USDC */
  amount?: string;
  /** Alternative: decimal USD value */
  amount_usd?: number;
  /** Token decimals if amount is atomic units (default 6 = USDC) */
  asset_decimals?: number;
  /** Recipient address */
  pay_to?: string;
  /** Paying agent's address (optional, scopes replay + velocity tracking) */
  payer?: string;
  /** The resource being purchased */
  resource_url?: string;
  description?: string;
  /** Free-text reason the agent recorded for making this payment */
  reason?: string;
  /** Payment nonce (from the signed payment payload) */
  nonce?: string;
  valid_until?: string;
  metadata?: Record<string, string>;
}

export interface ScanContext {
  /** Where the decision to pay originated */
  origin?: PaymentOrigin;
  /** The content the agent just read (tool result / fetched page), for injection analysis */
  content?: string;
  /** URL the content came from, if any */
  content_source_url?: string;
  /**
   * When in the payment flow this scan runs. "pre_sign" = before the client
   * has signed (EIP-3009 nonces don't exist yet, so a missing nonce is
   * expected, not suspicious). "post_sign" or absent = full replay coverage
   * expected.
   */
  phase?: "pre_sign" | "post_sign";
  /**
   * The raw 402 offer / discovery payload (e.g. the `accepts` entry or Bazaar
   * listing) the payment terms came from. The pay_to address is EXPECTED to
   * appear here — it is exempt from the address-provenance check, but still
   * scanned for injection tells. Prose the agent read goes in `content`.
   */
  offer?: string;
}

export interface ScanPolicy {
  /** Run the deep content-analysis tier even below the micropayment threshold */
  force_deep?: boolean;
  /** Skip the deep tier regardless of value (developer policy) */
  skip_deep?: boolean;
}

export interface ScanRequest {
  agent_id?: string;
  payment: PaymentDetails;
  /** What the agent expected this to cost, in USD (e.g. from the 402 quote or a catalog) */
  expected_price_usd?: number;
  context?: ScanContext;
  policy?: ScanPolicy;
}

export interface CheckResult {
  id: string;
  name: string;
  verdict: Verdict;
  severity: Severity;
  reason: string;
  details?: Record<string, unknown>;
}

/** Ed25519 attestation over the verdict, so wallet policies can require a PaySafe allow-verdict. */
export interface VerdictAttestation {
  alg: "ed25519";
  /** SPKI DER, hex-encoded. Also served at /.well-known/paysafe-verdict-key */
  public_key_spki_hex: string;
  /** Signed message: scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at */
  message: string;
  signature_hex: string;
  /** sha256(network|pay_to|asset|amount|nonce) — binds the verdict to this payment */
  payment_commitment: string;
  /** ISO time after which the attestation must be rejected */
  expires_at: string;
}

export interface ScanResponse {
  scan_id: string;
  direction: Direction;
  verdict: Verdict;
  /** 0 (clean) – 100 (maximum risk) */
  risk_score: number;
  checks: CheckResult[];
  scanned_at: string;
  advisory: string;
  attestation?: VerdictAttestation;
}

export type ReportCategory =
  | "scam"
  | "non_delivery"
  | "prompt_injection"
  | "overcharge"
  | "impersonation"
  | "replay_abuse"
  | "other";

export interface ReputationReport {
  address: string;
  category: ReportCategory;
  reason: string;
  reporter_agent_id: string;
  evidence_url?: string;
  reported_at: string;
}

/** A signed rebuttal from a reported wallet. Verified at submission time:
 * the EIP-191 personal_sign signature over the canonical dispute message
 * (see reputation.ts) must recover to `address`, proving key ownership.
 * The signature is stored and surfaced so third parties can re-verify. */
export interface ReputationDispute {
  address: string;
  statement: string;
  signature: string;
  disputed_at: string;
}

export interface ReputationSummary {
  address: string;
  status: "clean" | "reported";
  risk: "none" | "low" | "medium" | "high";
  report_count: number;
  distinct_reporters: number;
  /** v2 risk input: sum over distinct reporters of credibility × time decay
   * (90-day half-life). Fresh anonymous reporter = 0.5; observed payment
   * history raises credibility toward 1.0. Thresholds: ≥2.5 high, ≥1.0
   * medium, >0.1 low — so five fresh anonymous reporters still grade high,
   * but stale reports fade to "none" in ~7 months instead of forever. */
  weighted_score: number;
  /** Signed, verified rebuttals from the reported wallet (newest first). */
  disputes?: ReputationDispute[];
  categories: Record<string, number>;
  first_reported?: string;
  last_reported?: string;
  /** Measured, commitment-bound delivery outcomes (null = no outcome history). */
  delivery?: {
    outcomes_total: number;
    delivered: number;
    not_delivered: number;
    partial: number;
    wrong_content: number;
    delivery_rate: number;
    distinct_reporters: number;
    first_at: string;
    last_at: string;
  } | null;
}

/** PaySafe configuration, driven by environment variables. */

export interface PaySafeConfig {
  port: number;
  /** "live" = x402 payments enforced; "dev" = everything free (local testing) */
  mode: "live" | "dev";
  /** Receiving wallet for x402 payments */
  payTo: string;
  /** CAIP-2 network, e.g. eip155:8453 (Base mainnet), eip155:84532 (Base Sepolia) */
  network: string;
  /** "cdp" (mainnet, requires CDP_API_KEY_ID/SECRET) or "x402org" (testnet, no auth) */
  facilitator: "cdp" | "x402org";
  priceScan: string;         // e.g. "$0.01"
  priceReputation: string;   // e.g. "$0.01"
  freeCalls: number;         // free calls per API key
  overpayFlagMultiple: number;
  overpayBlockMultiple: number;
  maxPaymentUsd: number;
  nonceTtlHours: number;
  dataDir: string;
  publicBaseUrl: string;     // e.g. https://paysafe.onrender.com

  // --- zero-latency hardening tier ---
  /** Scans per agent per minute: flag at this rate, block at 2x */
  maxPaymentsPerMinute: number;
  /** Cumulative scanned spend per agent per hour (USD): block above */
  maxUsdPerHour: number;
  /** First payment to a never-seen counterparty above this (USD) is flagged */
  firstPaymentMaxUsd: number;
  /** Payments under this (USD) skip the deep content-analysis tier (micropayment bypass) */
  microBypassUsd: number;
  /** Non-canonical-USDC asset: "block" (default) or "flag" (if you intentionally accept other tokens) */
  allowNonUsdc: boolean;
  /** TOFU merchant pinning (domain -> pay_to) */
  pinning: boolean;
  /** Async (non-blocking) CDP Bazaar cross-check of pins. Off by default; enable in live deployments. */
  cdpPinVerify: boolean;
  /** Ed25519-sign verdicts so wallets can require a PaySafe allow-verdict */
  verdictSigning: boolean;
  /** Path to a JSON array of known-bad addresses (default: <dataDir>/badlist.json) */
  badlistPath: string | null;

  // --- abuse limits on FREE endpoints ---
  /** API keys mintable per IP per day (each key carries freeCalls free scans) */
  keysPerIpPerDay: number;
  /** Reputation reports per IP per hour */
  reportsPerIpPerHour: number;

  // --- audit + resource bounds ---
  /** Write a tamper-evident audit record for every scan decision */
  auditLog: boolean;
  /** Max entries per in-memory Map before oldest-first eviction (DoS bound) */
  maxStoreEntries: number;
}

function num(v: string | undefined, d: number): number {
  const n = v === undefined ? NaN : Number(v);
  return Number.isFinite(n) ? n : d;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): PaySafeConfig {
  const mode = env.PAYSAFE_MODE === "dev" ? "dev" : "live";
  const dataDir = env.DATA_DIR ?? "./data";
  return {
    port: num(env.PORT, 4021),
    mode,
    payTo: env.PAY_TO ?? "",
    network: env.X402_NETWORK ?? "eip155:8453",
    facilitator: env.X402_FACILITATOR === "x402org" ? "x402org" : "cdp",
    priceScan: env.PRICE_SCAN ?? "$0.01",
    priceReputation: env.PRICE_REPUTATION ?? "$0.01",
    freeCalls: num(env.FREE_CALLS, 100),
    overpayFlagMultiple: num(env.OVERPAY_FLAG_MULTIPLE, 3),
    overpayBlockMultiple: num(env.OVERPAY_BLOCK_MULTIPLE, 10),
    maxPaymentUsd: num(env.MAX_PAYMENT_USD, 10),
    nonceTtlHours: num(env.NONCE_TTL_HOURS, 24),
    dataDir,
    publicBaseUrl: env.PUBLIC_BASE_URL ?? `http://localhost:${num(env.PORT, 4021)}`,

    maxPaymentsPerMinute: num(env.MAX_PAYMENTS_PER_MINUTE, 10),
    maxUsdPerHour: num(env.MAX_USD_PER_HOUR, 5),
    firstPaymentMaxUsd: num(env.FIRST_PAYMENT_MAX_USD, 1),
    microBypassUsd: num(env.MICRO_BYPASS_USD, 0.005),
    allowNonUsdc: env.ALLOW_NON_USDC === "on",
    pinning: env.PINNING !== "off",
    cdpPinVerify: env.CDP_PIN_VERIFY === "on",
    verdictSigning: env.VERDICT_SIGNING !== "off",
    badlistPath: env.BADLIST_PATH ?? null,

    keysPerIpPerDay: num(env.KEYS_PER_IP_PER_DAY, 10),
    reportsPerIpPerHour: num(env.REPORTS_PER_IP_PER_HOUR, 30),

    auditLog: env.AUDIT_LOG !== "off",
    maxStoreEntries: num(env.MAX_STORE_ENTRIES, 100_000),
  };
}

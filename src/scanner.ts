/** Scan orchestration: runs detectors and aggregates a verdict. */
import { randomUUID } from "node:crypto";
import type { CheckResult, Direction, ScanRequest, ScanResponse, Verdict } from "./types.ts";
import type { PaySafeConfig } from "./config.ts";
import type { Store } from "./store.ts";
import { scanPii } from "./detectors/pii.ts";
import { checkReplay } from "./detectors/replay.ts";
import { checkOverpayment, resolveUsd } from "./detectors/overpayment.ts";
import { checkInjection, deepContentAnalysis } from "./detectors/injection.ts";
import { checkUrlRisk } from "./detectors/urlrisk.ts";
import { checkAsset } from "./detectors/asset.ts";
import { checkBadlist } from "./detectors/badlist.ts";
import { checkPinning, checkCdpPinStatus, scheduleCdpPinVerify } from "./detectors/pinning.ts";
import { checkAddressPoisoning } from "./detectors/poisoning.ts";
import { checkScoutScore, scheduleScoutScoreRefresh } from "./detectors/scoutscore.ts";
import { checkVelocity } from "./detectors/velocity.ts";
import { checkReputation } from "./reputation.ts";

const SEVERITY_SCORE: Record<string, number> = {
  info: 0,
  low: 15,
  medium: 40,
  high: 70,
  critical: 95,
};

function aggregate(checks: CheckResult[]): { verdict: Verdict; risk: number } {
  let verdict: Verdict = "allow";
  let risk = 0;
  for (const c of checks) {
    if (c.verdict === "block") verdict = "block";
    else if (c.verdict === "flag" && verdict === "allow") verdict = "flag";
    risk = Math.max(risk, SEVERITY_SCORE[c.severity] ?? 0);
  }
  // Multiple independent flags compound.
  const flags = checks.filter((c) => c.verdict !== "allow").length;
  if (flags > 1) risk = Math.min(100, risk + (flags - 1) * 5);
  return { verdict, risk };
}

function advisory(direction: Direction, verdict: Verdict): string {
  if (verdict === "allow") {
    return "No issues detected. PaySafe is advisory — final settlement remains with your wallet/facilitator.";
  }
  if (verdict === "flag") {
    return direction === "outgoing"
      ? "Review the flagged checks before authorizing settlement. Consider pausing this payment and confirming intent against the agent's plan."
      : "Review the flagged checks before acting on this payment request. Consider verifying the counterparty out-of-band.";
  }
  return direction === "outgoing"
    ? "Recommended action: DO NOT settle this payment. At least one check found a condition consistent with fund exfiltration or data leakage."
    : "Recommended action: DO NOT comply with this payment request. At least one check found a condition consistent with fraud.";
}

export function runScan(
  direction: Direction,
  req: ScanRequest,
  cfg: PaySafeConfig,
  store: Store,
): ScanResponse {
  const scanId = randomUUID();
  const payment = req.payment ?? {};
  const usd = resolveUsd(payment);
  const checks: CheckResult[] = [];

  // --- core detectors ---
  checks.push(...scanPii(payment));
  checks.push(checkReplay(payment, store, scanId, cfg.nonceTtlHours));
  checks.push(
    checkOverpayment(payment, req.expected_price_usd, {
      flagMultiple: cfg.overpayFlagMultiple,
      blockMultiple: cfg.overpayBlockMultiple,
      maxUsd: cfg.maxPaymentUsd,
    }),
  );
  checks.push(...checkInjection(payment, req.context));

  // Deep content tier: bypassed for micropayments unless forced (developer policy).
  // NOTE (audit M-2): a missing/unparseable amount does NOT unlock the deep
  // tier — otherwise an attacker omits `amount` to force the expensive path for
  // free. Unknown value is treated as below-threshold; use policy.force_deep to
  // opt in explicitly.
  const deepEligible =
    req.policy?.skip_deep !== true &&
    (req.policy?.force_deep === true || (usd !== null && usd >= cfg.microBypassUsd));
  if (deepEligible) {
    checks.push(...deepContentAnalysis(payment, req.context));
  } else if (req.context?.content) {
    checks.push({
      id: "tier.deep_bypassed",
      name: "Scan tiering",
      verdict: "allow",
      severity: "info",
      reason: `Deep content analysis bypassed (value ${usd === null ? "unknown" : `$${usd.toFixed(4)}`} < $${cfg.microBypassUsd} MICRO_BYPASS_USD). Set policy.force_deep to override.`,
    });
  }

  if (direction === "incoming") {
    checks.push(...checkUrlRisk(payment));
  }

  // --- zero-latency hardening tier ---
  checks.push(checkAsset(payment, cfg.allowNonUsdc));

  const badlistHit = checkBadlist(payment, store);
  if (badlistHit) checks.push(badlistHit);

  // Address poisoning: MUST run before pinning and velocity — both record
  // this scan's pay_to into trust state (pin / counterparty history), and the
  // lookalike has to be judged against state that does not yet contain it.
  const poisoning = checkAddressPoisoning(req, store);
  if (poisoning) checks.push(poisoning);

  // Snapshot pre-scan trust state so a BLOCKED payment can be rolled out of
  // it below (a blocked lookalike must not become "known" and silence the
  // poisoning detector on the next attempt).
  const velocityKey = req.agent_id ?? payment.payer?.toLowerCase();
  const payToLc = payment.pay_to?.toLowerCase();
  const counterpartyWasKnown =
    !!(velocityKey && payToLc && (store.counterparties.get(velocityKey) ?? []).includes(payToLc));
  let pinDomain: string | null = null;
  try {
    pinDomain = payment.resource_url ? new URL(payment.resource_url).hostname.toLowerCase() : null;
  } catch {
    pinDomain = null;
  }
  const pinExistedBefore = pinDomain !== null && store.pins.has(pinDomain);

  if (cfg.pinning) {
    checks.push(checkPinning(payment, store));
    const cdpStatus = checkCdpPinStatus(payment, store);
    if (cdpStatus) checks.push(cdpStatus);
    if (cfg.cdpPinVerify && payment.resource_url) {
      try {
        scheduleCdpPinVerify(store, new URL(payment.resource_url).hostname.toLowerCase());
      } catch {
        // unparseable URL already reported by other checks
      }
    }
  }

  // ScoutScore external trust signal: reads only the cache (zero latency);
  // the refresh runs out-of-band, same pattern as the CDP pin cross-check.
  if (cfg.scoutScore) {
    const scout = checkScoutScore(payment, store);
    if (scout) checks.push(scout);
    if (pinDomain !== null) scheduleScoutScoreRefresh(store, pinDomain, cfg.scoutScoreUrl);
  }

  if (direction === "outgoing") {
    checks.push(...checkVelocity(req, usd, store, cfg));
  }

  checks.push(checkReputation(store, payment.pay_to));

  const { verdict, risk } = aggregate(checks);

  // A BLOCKED payment must not grow trust state: roll back the counterparty
  // history entry and the pin this scan just created, so the lookalike isn't
  // "known" (exact match) on the next attempt, silencing the detectors.
  if (verdict === "block") {
    if (!counterpartyWasKnown && velocityKey && payToLc) {
      const seen = store.counterparties.get(velocityKey);
      const i = seen ? seen.indexOf(payToLc) : -1;
      if (seen && i >= 0) {
        seen.splice(i, 1);
        store.markDirty();
      }
    }
    if (pinDomain !== null && !pinExistedBefore && store.pins.delete(pinDomain)) {
      store.markDirty();
    }
  }
  return {
    scan_id: scanId,
    direction,
    verdict,
    risk_score: risk,
    checks,
    scanned_at: new Date().toISOString(),
    advisory: advisory(direction, verdict),
  };
}

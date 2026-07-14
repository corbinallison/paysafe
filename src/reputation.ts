/**
 * Counterparty reputation: shared post-hoc reporting + lookup.
 * Purely observational — a report registry, not a trust score.
 *
 * SECURITY NOTE (audit H-2): reporter_agent_id is self-asserted and
 * unauthenticated, so the registry is inherently spoofable. Therefore an
 * unverified report set NEVER produces a hard "block" inside a scan — the
 * worst it yields is "flag". Hard blocks come only from the operator-curated
 * badlist. Reports are a signal for humans/agents to weigh, not a kill switch.
 */
import type { CheckResult, ReportCategory, ReputationReport, ReputationSummary } from "./types.ts";
import type { Store } from "./store.ts";

const CATEGORIES: ReportCategory[] = [
  "scam", "non_delivery", "prompt_injection", "overcharge", "impersonation", "replay_abuse", "other",
];

export function isValidCategory(c: string): c is ReportCategory {
  return (CATEGORIES as string[]).includes(c);
}

export function addReport(
  store: Store,
  input: { address: string; category: string; reason: string; reporter_agent_id: string; evidence_url?: string },
): { ok: true; report: ReputationReport } | { ok: false; error: string } {
  const address = input.address?.trim().toLowerCase();
  if (!address || address.length < 6) return { ok: false, error: "address is required" };
  if (!isValidCategory(input.category)) {
    return { ok: false, error: `category must be one of: ${CATEGORIES.join(", ")}` };
  }
  if (!input.reporter_agent_id) return { ok: false, error: "reporter_agent_id is required" };
  if (!input.reason || input.reason.length < 10) {
    return { ok: false, error: "reason must be at least 10 characters" };
  }

  const existing = store.reportsByAddress.get(address) ?? [];

  // One report per (reporter, address, category) — dedup against the
  // per-address bucket (O(bucket), not O(all reports)).
  const dup = existing.find(
    (r) => r.category === input.category && r.reporter_agent_id === input.reporter_agent_id,
  );
  if (dup) return { ok: true, report: dup };

  const report: ReputationReport = {
    address,
    category: input.category,
    reason: input.reason.slice(0, 1000),
    reporter_agent_id: input.reporter_agent_id.slice(0, 200),
    evidence_url: input.evidence_url,
    reported_at: new Date().toISOString(),
  };
  store.reports.push(report);
  existing.push(report);
  store.reportsByAddress.set(address, existing);
  store.markDirty();
  return { ok: true, report };
}

export function summarize(store: Store, addressRaw: string): ReputationSummary {
  const address = addressRaw.trim().toLowerCase();
  const reports = store.reportsByAddress.get(address) ?? [];
  const reporters = new Set(reports.map((r) => r.reporter_agent_id));
  const categories: Record<string, number> = Object.create(null);
  for (const r of reports) categories[r.category] = (categories[r.category] ?? 0) + 1;

  let risk: ReputationSummary["risk"] = "none";
  if (reporters.size >= 5) risk = "high";
  else if (reporters.size >= 2) risk = "medium";
  else if (reporters.size === 1) risk = "low";

  const times = reports.map((r) => r.reported_at).sort();
  return {
    address,
    status: reports.length ? "reported" : "clean",
    risk,
    report_count: reports.length,
    distinct_reporters: reporters.size,
    categories,
    first_reported: times[0],
    last_reported: times[times.length - 1],
  };
}

/** Cross-check used inside scans: is the counterparty already reported? */
export function checkReputation(store: Store, payTo: string | undefined): CheckResult {
  if (!payTo) {
    return {
      id: "reputation.no_address",
      name: "Counterparty reputation",
      verdict: "allow",
      severity: "info",
      reason: "No pay_to address supplied; reputation cross-check skipped.",
    };
  }
  const s = summarize(store, payTo);
  if (s.status === "clean") {
    return {
      id: "reputation.clean",
      name: "Counterparty reputation",
      verdict: "allow",
      severity: "info",
      reason: `No reports on record for ${payTo}.`,
    };
  }
  // Unverified reports cap out at "flag" (never "block"): a spoofable registry
  // must not be able to hard-block an honest counterparty. Higher report
  // density raises severity but not the verdict.
  const severity = s.risk === "high" ? "high" : s.risk === "medium" ? "medium" : "low";
  return {
    id: "reputation.reported",
    name: "Counterparty reputation",
    verdict: "flag",
    severity,
    reason: `Counterparty ${payTo} has ${s.report_count} unverified report(s) from ${s.distinct_reporters} distinct reporter(s): ${Object.entries(s.categories).map(([k, v]) => `${k}×${v}`).join(", ")}. Reports are self-asserted — verify out-of-band before deciding.`,
    details: { ...s },
  };
}

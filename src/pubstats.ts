// Copyright (c) 2026 Tollwarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Public, unauthenticated service statistics — the data behind the homepage
 * "track record" section and GET /v1/stats. Same privacy rules as the
 * owner-only /v1/admin/stats, minus everything that isn't a plain aggregate:
 *  - Aggregates only. No API keys, agent ids, wallet addresses, or
 *    per-payment data ever leave here. The per-day breakdown and the scanned
 *    USD total stay admin-only: with few scans in a bucket, either could
 *    reveal an individual payment (its day, its amount).
 *  - O(1) per request. The audit log is the all-time source of truth but
 *    stats() re-reads the whole file, so the snapshot is cached for
 *    STATS_TTL_MS. An unauthenticated caller can never force a log scan, and
 *    the coarse refresh keeps the public counters too blurry to correlate an
 *    individual scan with a counter increment.
 *  - Honest numbers. Real zeros on a young deployment, never synthetic; the
 *    uptime figure is self-measured process liveness (store heartbeats,
 *    which cannot see network-level unreachability) and is labeled as such
 *    wherever it renders.
 */
import type { Store, UptimeRange } from "./store.ts";

export interface UptimeSummary {
  window_days: number;
  /** Percent of the measured window covered by heartbeats, 2 decimals. */
  pct: number;
  /** Start of measurement inside the window (clock starts at the first
   * heartbeat, not the window edge — a young deployment isn't "down" for
   * the days before it existed). */
  measured_since: string;
  /** Downtime events (heartbeat gaps) inside the window. */
  interruptions: number;
}

/** One side of the first-party / third-party split. */
export interface PartyStats {
  scans: number;
  blocked: number;
  flagged: number;
  distinct_agents: number;
}

export interface PublicStats {
  /** Every scan, both parties. Unchanged meaning, kept for compatibility. */
  scans_total: number;
  blocked: number;
  flagged: number;
  distinct_agents: number;
  /**
   * Scans from agents that are not the operator's. This is the honest answer to
   * "how much is Tollwarden used", and it is what the homepage panel shows.
   */
  third_party: PartyStats;
  /**
   * The operator's own agents, chiefly the ecosystem scout. Computed from the
   * per-key usage counters of keys the owner has tagged first-party, so the
   * attribution is authenticated (the key was presented at scan time) and the
   * split covers scans recorded BEFORE the key was tagged. The audit-record
   * first_party flag cannot do that job. Audit records are immutable and only
   * scans made after tagging carry the flag, so a flag-derived figure would
   * leave every earlier operator scan permanently counted as third-party.
   * Published rather than netted out silently. The scout is open source and
   * its run count is public, so this figure is checkable against it. A
   * disclosure sentence is a claim someone has to trust. A number that
   * reconciles is evidence.
   */
  first_party: PartyStats;
  /** First recorded scan (audit log), null before the first scan. */
  measuring_since: string | null;
  uptime: UptimeSummary | null;
  as_of: string;
  cache_ttl_seconds: number;
}

const WINDOW_DAYS = 90;
const STATS_TTL_MS = 5 * 60_000;
/** Mirrors the store's heartbeat-gap threshold: a range whose last beat is
 * this fresh belongs to a process that is up right now (it is, after all,
 * serving this request), so it counts as covered through `now` instead of
 * reading the sub-tick lag since the last beat as downtime. */
const LIVE_GRACE_MS = 120_000;

/** Uptime over the trailing window from the store's liveness ranges. */
export function computeUptime(ranges: UptimeRange[], now = Date.now()): UptimeSummary | null {
  const windowStart = now - WINDOW_DAYS * 86400_000;
  let covered = 0;
  let earliest = Infinity;
  let spans = 0;
  for (const r of ranges) {
    const from = Date.parse(r.from);
    const to = Date.parse(r.to);
    if (!Number.isFinite(from) || !Number.isFinite(to)) continue;
    const a = Math.max(from, windowStart);
    const b = Math.min(now - to <= LIVE_GRACE_MS ? now : to, now);
    if (b < a) continue;
    covered += b - a;
    earliest = Math.min(earliest, a);
    spans += 1;
  }
  if (earliest === Infinity) return null;
  const measured = now - earliest;
  const pct = measured <= 0 ? 100 : Math.min(100, (covered / measured) * 100);
  return {
    window_days: WINDOW_DAYS,
    pct: Number(pct.toFixed(2)),
    measured_since: new Date(earliest).toISOString(),
    interruptions: Math.max(0, spans - 1),
  };
}

/** Uncached aggregation (exported for tests; servers use publicStats). */
export function computePublicStats(store: Store, now = Date.now()): PublicStats {
  let scans_total = 0;
  let blocked = 0;
  let flagged = 0;
  let distinct_agents = 0;
  let since: string | null = null;
  const empty = (): PartyStats => ({ scans: 0, blocked: 0, flagged: 0, distinct_agents: 0 });
  let third_party = empty();
  let first_party = empty();
  if (store.auditLog) {
    // All-time truth, including anonymous (keyless) scans. The daily series
    // and USD total are computed but deliberately dropped — see module doc.
    const s = store.auditLog.stats(1);
    scans_total = s.count;
    blocked = s.by_verdict.block;
    flagged = s.by_verdict.flag;
    distinct_agents = s.distinct_agents;
    since = s.first_ts;
    // First-party share from per-key counters on owner-tagged keys, so scans
    // recorded before the key was tagged are attributed correctly (see the
    // interface docs). The audit-flag split in AuditStats stays as an owner
    // cross-check; it converges with this one for scans made after tagging.
    for (const rec of store.keys.values()) {
      if (!rec.first_party || !rec.scans) continue;
      first_party.scans += rec.scans.total;
      first_party.blocked += rec.scans.block;
      first_party.flagged += rec.scans.flag;
      if (rec.scans.total > 0) first_party.distinct_agents += 1;
    }
    // agent_id is caller-supplied, so this subtraction can only remove ids.
    // An outsider spoofing an operator agent_id deflates the third-party agent
    // count rather than inflating it. Understating our third-party reach is
    // the acceptable direction for a self-published usage figure.
    const taggedIds = new Set(
      [...store.keys.values()]
        .filter((r) => r.first_party && r.agent_id)
        .map((r) => r.agent_id as string),
    );
    const overlap = s.agent_ids.filter((id) => taggedIds.has(id)).length;
    // Clamped subtraction, so a counter that outlives its audit records can
    // never push a third-party figure below zero.
    third_party = {
      scans: Math.max(0, scans_total - first_party.scans),
      blocked: Math.max(0, blocked - first_party.blocked),
      flagged: Math.max(0, flagged - first_party.flagged),
      distinct_agents: Math.max(0, distinct_agents - overlap),
    };
  } else {
    // No audit log: fall back to per-key counters (keys that have scanned
    // stand in for distinct agents — the closest honest approximation).
    for (const rec of store.keys.values()) {
      if (!rec.scans) continue;
      scans_total += rec.scans.total;
      blocked += rec.scans.block;
      flagged += rec.scans.flag;
      distinct_agents += 1;
      const side = rec.first_party ? first_party : third_party;
      side.scans += rec.scans.total;
      side.blocked += rec.scans.block;
      side.flagged += rec.scans.flag;
      side.distinct_agents += 1;
    }
  }
  return {
    scans_total,
    blocked,
    flagged,
    distinct_agents,
    third_party,
    first_party,
    measuring_since: since,
    uptime: computeUptime(store.uptimeRanges, now),
    as_of: new Date(now).toISOString(),
    cache_ttl_seconds: STATS_TTL_MS / 1000,
  };
}

let cache: { at: number; body: PublicStats } | null = null;

/** TTL-cached snapshot — the only entry point request handlers may use. */
export function publicStats(store: Store, now = Date.now()): PublicStats {
  if (!cache || now - cache.at >= STATS_TTL_MS) {
    cache = { at: now, body: computePublicStats(store, now) };
  }
  return cache.body;
}

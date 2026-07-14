/**
 * Minimal in-memory sliding-window rate limiter for the FREE endpoints
 * (key minting, reputation reports). Paid endpoints are already gated by
 * x402 payment + the free-tier quota; without this, POST /v1/keys would let
 * anyone mint unlimited free-call allowances.
 */
export class RateLimiter {
  private limit: number;
  private windowMs: number;
  private hits: Map<string, number[]> = new Map();

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** Returns true if the request is allowed (and records it). */
  allow(key: string): boolean {
    const now = Date.now();
    const recent = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (recent.length >= this.limit) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(key, recent);
    if (this.hits.size > 50_000) this.prune(now);
    return true;
  }

  private prune(now: number): void {
    for (const [k, v] of this.hits) {
      if (v.every((t) => now - t >= this.windowMs)) this.hits.delete(k);
    }
  }
}

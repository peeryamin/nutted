/**
 * Rate limiter for active testing (product plan §8: throttling guardrail).
 *
 * Fixed-gap token bucket: at most one active request per `gapMs`, which
 * keeps request volume predictable and DoS-safe. Every acquire() is recorded
 * so the popup can show live throttle status and the report can account for
 * the exact number of requests sent.
 */
export class RateLimiter {
  private nextAllowedAt = 0;
  private requestsMade = 0;
  private throttledMsTotal = 0;
  private maxRequests: number;

  constructor(
    public readonly gapMs: number,
    maxRequests = 120,
  ) {
    this.maxRequests = maxRequests;
  }

  /**
   * Wait until the next request slot is available, then claim it.
   * Throws when the per-scan request cap is reached.
   */
  async acquire(): Promise<{ waitedMs: number }> {
    if (this.requestsMade >= this.maxRequests) {
      throw new Error(
        `Active request cap reached (${this.maxRequests}). Scan stopped early to protect the target.`,
      );
    }
    const now = Date.now();
    const waitMs = Math.max(0, this.nextAllowedAt - now);
    if (waitMs > 0) {
      this.throttledMsTotal += waitMs;
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
    // Re-read the clock after sleeping so bursts stay spaced.
    this.nextAllowedAt = Date.now() + this.gapMs;
    this.requestsMade++;
    return { waitedMs: waitMs };
  }

  /** Milliseconds until the next slot opens (for the throttle UI). */
  nextRequestInMs(): number {
    return Math.max(0, this.nextAllowedAt - Date.now());
  }

  getStats(): {
    requestsMade: number;
    gapMs: number;
    throttledMsTotal: number;
    nextRequestInMs: number;
    maxRequests: number;
  } {
    return {
      requestsMade: this.requestsMade,
      gapMs: this.gapMs,
      throttledMsTotal: this.throttledMsTotal,
      nextRequestInMs: this.nextRequestInMs(),
      maxRequests: this.maxRequests,
    };
  }
}

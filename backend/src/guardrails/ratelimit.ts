/**
 * LEGAL GUARDRAIL — rate limiting on ALL active requests (product plan §8).
 *
 * The tool should never send enough requests to impact the target's
 * availability. Every active-testing tool acquires a token before sending a
 * request. Default is AGENT_REQUESTS_PER_SECOND (2/s); configurable per scan
 * via the scope policy.
 */
export class TokenBucketRateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly requestsPerSecond: number,
    private readonly burst: number = 1
  ) {
    if (requestsPerSecond <= 0) throw new Error('requestsPerSecond must be > 0');
    this.tokens = burst;
    this.lastRefill = Date.now();
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.burst, this.tokens + elapsed * this.requestsPerSecond);
    this.lastRefill = now;
  }

  /** Resolves when a token is available. Never rejects. */
  async take(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.ceil((1 - this.tokens) / this.requestsPerSecond * 1000);
      await new Promise((r) => setTimeout(r, Math.max(waitMs, 10)));
    }
  }
}

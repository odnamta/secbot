export interface RateLimiterOptions {
  requestsPerSecond?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  backoffMultiplier?: number;
}

export interface RateLimiterStats {
  totalRequests: number;
  backoffs: number;
  currentDelayMs: number;
}

/**
 * Adaptive rate limiter with token bucket algorithm and exponential backoff.
 *
 * - Enforces a requests-per-second ceiling via token bucket.
 * - On 429/503 responses, applies exponential backoff.
 * - After 5 consecutive 2xx responses, gradually reduces delay back toward initial.
 */
export class RateLimiter {
  private readonly requestsPerSecond: number;
  private readonly initialDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly backoffMultiplier: number;

  private currentDelayMs: number;
  private totalRequests: number;
  private backoffs: number;
  private consecutive2xx: number;

  // Token bucket state
  private tokens: number;
  private maxTokens: number;
  private lastRefill: number;

  constructor(options: RateLimiterOptions = {}) {
    this.requestsPerSecond = options.requestsPerSecond ?? 10;
    this.initialDelayMs = options.initialDelayMs ?? 100;
    this.maxDelayMs = options.maxDelayMs ?? 30000;
    this.backoffMultiplier = options.backoffMultiplier ?? 2;

    this.currentDelayMs = this.initialDelayMs;
    this.totalRequests = 0;
    this.backoffs = 0;
    this.consecutive2xx = 0;

    // Token bucket: start full
    this.maxTokens = this.requestsPerSecond;
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
  }

  /**
   * Call before making a request. Enforces rate limit by delaying if needed.
   * Uses a token bucket algorithm combined with the adaptive delay.
   */
  async acquire(): Promise<void> {
    // Refill tokens based on elapsed time
    this.refillTokens();

    // If no tokens available, wait until one is available
    if (this.tokens < 1) {
      const waitForToken = ((1 - this.tokens) / this.requestsPerSecond) * 1000;
      await this.sleep(waitForToken);
      this.refillTokens();
    }

    // Consume a token
    this.tokens -= 1;

    // Apply the adaptive delay (backoff-aware)
    if (this.currentDelayMs > 0) {
      await this.sleep(this.currentDelayMs);
    }

    this.totalRequests += 1;
  }

  /**
   * Call after each response. Adjusts delay based on status code.
   * - 429 or 503: exponential backoff
   * - 2xx for 5 consecutive: gradually reduce delay
   */
  recordResponse(status: number): void {
    if (status === 429 || status === 503) {
      this.consecutive2xx = 0;
      this.currentDelayMs = Math.min(
        this.currentDelayMs * this.backoffMultiplier,
        this.maxDelayMs,
      );
      this.backoffs += 1;
    } else if (status >= 200 && status < 300) {
      this.consecutive2xx += 1;
      if (this.consecutive2xx >= 5) {
        // Reduce delay by half, but never below initial
        this.currentDelayMs = Math.max(
          Math.floor(this.currentDelayMs / 2),
          this.initialDelayMs,
        );
        this.consecutive2xx = 0;
      }
    } else {
      // Other statuses (4xx, 5xx besides 503): reset consecutive counter but don't backoff
      this.consecutive2xx = 0;
    }
  }

  /** Returns current stats for logging. */
  getStats(): RateLimiterStats {
    return {
      totalRequests: this.totalRequests,
      backoffs: this.backoffs,
      currentDelayMs: this.currentDelayMs,
    };
  }

  /** Reset to initial state. */
  reset(): void {
    this.currentDelayMs = this.initialDelayMs;
    this.totalRequests = 0;
    this.backoffs = 0;
    this.consecutive2xx = 0;
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
  }

  private refillTokens(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const newTokens = (elapsed / 1000) * this.requestsPerSecond;
    this.tokens = Math.min(this.tokens + newTokens, this.maxTokens);
    this.lastRefill = now;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

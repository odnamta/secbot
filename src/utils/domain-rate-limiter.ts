import { RateLimiter, type RateLimiterOptions } from './rate-limiter.js';

/**
 * Per-domain rate limiter that applies different rate limits based on URL domain patterns.
 *
 * Config format in .secbotrc.json:
 * ```json
 * {
 *   "rateLimits": {
 *     "*.hackerone.com": 5,
 *     "api.example.com": 2,
 *     "default": 10
 *   }
 * }
 * ```
 *
 * Pattern matching:
 * - Exact domain match: "api.example.com" matches only api.example.com
 * - Wildcard prefix: "*.example.com" matches foo.example.com, bar.baz.example.com
 * - "default" key: fallback for unmatched domains
 */
export class DomainRateLimiter {
  private readonly domainPatterns: Map<string, number>;
  private readonly defaultRps: number;
  private readonly limiters: Map<string, RateLimiter>;
  private readonly baseOptions: Omit<RateLimiterOptions, 'requestsPerSecond'>;

  constructor(
    rateLimits: Record<string, number> = {},
    baseOptions: Omit<RateLimiterOptions, 'requestsPerSecond'> = {},
  ) {
    this.domainPatterns = new Map();
    this.limiters = new Map();
    this.baseOptions = baseOptions;

    // Separate the "default" key from domain patterns
    this.defaultRps = rateLimits['default'] ?? 10;

    for (const [pattern, rps] of Object.entries(rateLimits)) {
      if (pattern !== 'default') {
        this.domainPatterns.set(pattern.toLowerCase(), rps);
      }
    }
  }

  /**
   * Get the configured rate limit (requests per second) for a given URL.
   * Matches the URL's hostname against configured domain patterns.
   * Falls back to the "default" rate limit if no pattern matches.
   */
  getRateLimit(url: string): number {
    const hostname = this.extractHostname(url);
    if (!hostname) return this.defaultRps;

    const lower = hostname.toLowerCase();

    // 1. Try exact domain match
    const exactMatch = this.domainPatterns.get(lower);
    if (exactMatch !== undefined) return exactMatch;

    // 2. Try wildcard patterns (*.example.com)
    for (const [pattern, rps] of this.domainPatterns) {
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(1); // ".example.com"
        if (lower.endsWith(suffix) && lower !== suffix.slice(1)) {
          // hostname ends with .example.com but is not just "example.com"
          return rps;
        }
      }
    }

    // 3. Fallback to default
    return this.defaultRps;
  }

  /**
   * Get (or create) a RateLimiter instance for the given URL's domain.
   * Each unique rate limit value gets its own RateLimiter.
   */
  getLimiter(url: string): RateLimiter {
    const rps = this.getRateLimit(url);
    const key = `rps:${rps}`;

    let limiter = this.limiters.get(key);
    if (!limiter) {
      limiter = new RateLimiter({
        ...this.baseOptions,
        requestsPerSecond: rps,
      });
      this.limiters.set(key, limiter);
    }

    return limiter;
  }

  /**
   * Acquire a rate limiter slot for the given URL.
   * Convenience method that combines getLimiter + acquire.
   */
  async acquire(url: string): Promise<void> {
    const limiter = this.getLimiter(url);
    await limiter.acquire();
  }

  /**
   * Record a response for the given URL's rate limiter.
   */
  recordResponse(url: string, status: number): void {
    const limiter = this.getLimiter(url);
    limiter.recordResponse(status);
  }

  /** Get the default RPS value. */
  getDefaultRps(): number {
    return this.defaultRps;
  }

  /** Get all configured patterns (for debugging/logging). */
  getPatterns(): Map<string, number> {
    return new Map(this.domainPatterns);
  }

  private extractHostname(url: string): string | null {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }
}

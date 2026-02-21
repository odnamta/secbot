import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RateLimiter } from '../../src/utils/rate-limiter.js';

describe('RateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('acquire() enforces delay between requests', async () => {
    const limiter = new RateLimiter({
      requestsPerSecond: 100, // high RPS so token bucket is not the bottleneck
      initialDelayMs: 50,
    });

    const start = Date.now();

    // First acquire — should still wait the initial delay
    const p = limiter.acquire();
    await vi.advanceTimersByTimeAsync(50);
    await p;

    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(50);
  });

  it('429 response triggers exponential backoff', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    expect(limiter.getStats().currentDelayMs).toBe(100);

    limiter.recordResponse(429);
    expect(limiter.getStats().currentDelayMs).toBe(200);

    limiter.recordResponse(429);
    expect(limiter.getStats().currentDelayMs).toBe(400);
  });

  it('503 response triggers exponential backoff', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    limiter.recordResponse(503);
    expect(limiter.getStats().currentDelayMs).toBe(200);

    limiter.recordResponse(503);
    expect(limiter.getStats().currentDelayMs).toBe(400);
  });

  it('consecutive 2xx responses gradually reduce delay', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    // First backoff to increase delay
    limiter.recordResponse(429);
    limiter.recordResponse(429);
    expect(limiter.getStats().currentDelayMs).toBe(400);

    // 5 consecutive 2xx should halve the delay
    for (let i = 0; i < 5; i++) {
      limiter.recordResponse(200);
    }
    expect(limiter.getStats().currentDelayMs).toBe(200);

    // Another 5 consecutive 2xx should halve again
    for (let i = 0; i < 5; i++) {
      limiter.recordResponse(200);
    }
    expect(limiter.getStats().currentDelayMs).toBe(100);
  });

  it('delay never exceeds maxDelayMs', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      maxDelayMs: 500,
      backoffMultiplier: 2,
    });

    // Trigger many backoffs
    limiter.recordResponse(429); // 200
    limiter.recordResponse(429); // 400
    limiter.recordResponse(429); // 500 (capped)
    limiter.recordResponse(429); // still 500

    expect(limiter.getStats().currentDelayMs).toBe(500);
  });

  it('delay never drops below initialDelayMs on recovery', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    // Backoff once to 200
    limiter.recordResponse(429);
    expect(limiter.getStats().currentDelayMs).toBe(200);

    // 5 consecutive 2xx -> 100 (halved)
    for (let i = 0; i < 5; i++) {
      limiter.recordResponse(200);
    }
    expect(limiter.getStats().currentDelayMs).toBe(100);

    // Another 5 -> should stay at 100 (floor)
    for (let i = 0; i < 5; i++) {
      limiter.recordResponse(200);
    }
    expect(limiter.getStats().currentDelayMs).toBe(100);
  });

  it('reset() restores initial state', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    // Mutate state
    limiter.recordResponse(429);
    limiter.recordResponse(429);

    // Simulate an acquire to bump totalRequests
    // (We can't easily await with fake timers, so just check stats after recordResponse)
    const stats = limiter.getStats();
    expect(stats.currentDelayMs).toBe(400);
    expect(stats.backoffs).toBe(2);

    limiter.reset();

    const resetStats = limiter.getStats();
    expect(resetStats.currentDelayMs).toBe(100);
    expect(resetStats.backoffs).toBe(0);
    expect(resetStats.totalRequests).toBe(0);
  });

  it('getStats() returns correct values', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    const initial = limiter.getStats();
    expect(initial).toEqual({
      totalRequests: 0,
      backoffs: 0,
      currentDelayMs: 100,
    });

    limiter.recordResponse(429);
    limiter.recordResponse(200);
    limiter.recordResponse(503);

    const updated = limiter.getStats();
    expect(updated.backoffs).toBe(2);
    expect(updated.currentDelayMs).toBe(400); // 100 -> 200 (429) -> 200 (200 doesn't reduce, only 1 consecutive) -> 400 (503)
  });

  it('non-429/503 errors reset consecutive 2xx counter without backoff', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 2,
    });

    // Backoff to 200
    limiter.recordResponse(429);
    expect(limiter.getStats().currentDelayMs).toBe(200);

    // 4 consecutive 2xx
    for (let i = 0; i < 4; i++) {
      limiter.recordResponse(200);
    }
    // A 404 resets the counter
    limiter.recordResponse(404);

    // 4 more 2xx — not enough for reduction (need 5 consecutive)
    for (let i = 0; i < 4; i++) {
      limiter.recordResponse(200);
    }
    expect(limiter.getStats().currentDelayMs).toBe(200); // unchanged
  });

  it('acquire() respects token bucket rate limit', async () => {
    const limiter = new RateLimiter({
      requestsPerSecond: 2, // very low: 2 req/s
      initialDelayMs: 0, // no backoff delay, purely token bucket
    });

    // First two acquires should be fast (tokens available)
    const p1 = limiter.acquire();
    await vi.advanceTimersByTimeAsync(0);
    await p1;

    const p2 = limiter.acquire();
    await vi.advanceTimersByTimeAsync(0);
    await p2;

    // Third acquire should need to wait for token refill (~500ms for 1 token at 2 rps)
    const start = Date.now();
    const p3 = limiter.acquire();
    // Advance time enough for a token refill
    await vi.advanceTimersByTimeAsync(600);
    await p3;
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(400); // waited for token
  });

  it('uses custom backoff multiplier', () => {
    const limiter = new RateLimiter({
      initialDelayMs: 100,
      backoffMultiplier: 3,
    });

    limiter.recordResponse(429);
    expect(limiter.getStats().currentDelayMs).toBe(300);

    limiter.recordResponse(503);
    expect(limiter.getStats().currentDelayMs).toBe(900);
  });
});

import { describe, it, expect } from 'vitest';
import {
  getRandomUserAgent,
  jitteredDelay,
  randomizeRequestOrder,
  USER_AGENT_COUNT,
} from '../../src/utils/stealth.js';
import { buildConfig } from '../../src/config/defaults.js';

// ─── getRandomUserAgent ─────────────────────────────────────────

describe('getRandomUserAgent', () => {
  it('returns a non-empty string', () => {
    const ua = getRandomUserAgent();
    expect(typeof ua).toBe('string');
    expect(ua.length).toBeGreaterThan(0);
  });

  it('returns a string that looks like a browser User-Agent', () => {
    const ua = getRandomUserAgent();
    expect(ua).toMatch(/Mozilla\/5\.0/);
  });

  it('varies across multiple calls (pool has 12+ entries)', () => {
    expect(USER_AGENT_COUNT).toBeGreaterThanOrEqual(10);

    // Call many times, collect unique values
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      seen.add(getRandomUserAgent());
    }
    // With 12 entries and 200 draws, extremely unlikely to see fewer than 5
    expect(seen.size).toBeGreaterThanOrEqual(5);
  });
});

// ─── jitteredDelay ──────────────────────────────────────────────

describe('jitteredDelay', () => {
  it('waits approximately the right amount of time', async () => {
    const baseMs = 100;
    const start = Date.now();
    await jitteredDelay(baseMs);
    const elapsed = Date.now() - start;

    // Should be within 50% jitter range: 50ms to 150ms
    // Allow generous margin for timer imprecision (30ms - 200ms)
    expect(elapsed).toBeGreaterThanOrEqual(30);
    expect(elapsed).toBeLessThan(200);
  });

  it('resolves for zero base delay', async () => {
    const start = Date.now();
    await jitteredDelay(0);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(50);
  });

  it('produces varying wait times', async () => {
    const times: number[] = [];
    for (let i = 0; i < 10; i++) {
      const start = Date.now();
      await jitteredDelay(100);
      times.push(Date.now() - start);
    }
    // Not all durations should be identical
    const unique = new Set(times);
    expect(unique.size).toBeGreaterThan(1);
  });
});

// ─── randomizeRequestOrder ──────────────────────────────────────

describe('randomizeRequestOrder', () => {
  it('returns an array with the same elements', () => {
    const input = [1, 2, 3, 4, 5];
    const result = randomizeRequestOrder(input);
    expect(result).toHaveLength(input.length);
    expect(result.sort()).toEqual(input.sort());
  });

  it('does not mutate the original array', () => {
    const input = [1, 2, 3, 4, 5];
    const copy = [...input];
    randomizeRequestOrder(input);
    expect(input).toEqual(copy);
  });

  it('handles empty array', () => {
    expect(randomizeRequestOrder([])).toEqual([]);
  });

  it('handles single-element array', () => {
    expect(randomizeRequestOrder([42])).toEqual([42]);
  });

  it('produces different orders (statistical test with large array)', () => {
    const input = Array.from({ length: 50 }, (_, i) => i);
    let differentOrderCount = 0;
    const runs = 20;

    for (let r = 0; r < runs; r++) {
      const shuffled = randomizeRequestOrder(input);
      const isSameOrder = shuffled.every((val, idx) => val === input[idx]);
      if (!isSameOrder) differentOrderCount++;
    }

    // The probability of a 50-element shuffle matching the original is ~1/50!
    // So all 20 runs should produce a different order.
    expect(differentOrderCount).toBe(runs);
  });
});

// ─── Stealth profile defaults ───────────────────────────────────

describe('stealth profile defaults', () => {
  it('has correct maxPages', () => {
    const config = buildConfig('https://example.com', { profile: 'stealth' });
    expect(config.maxPages).toBe(3);
  });

  it('has correct timeout', () => {
    const config = buildConfig('https://example.com', { profile: 'stealth' });
    expect(config.timeout).toBe(30000);
  });

  it('has concurrency of 1', () => {
    const config = buildConfig('https://example.com', { profile: 'stealth' });
    expect(config.concurrency).toBe(1);
  });

  it('has requestDelay set (base value for jittered delay)', () => {
    const config = buildConfig('https://example.com', { profile: 'stealth' });
    expect(config.requestDelay).toBe(500);
  });

  it('sets profile to stealth', () => {
    const config = buildConfig('https://example.com', { profile: 'stealth' });
    expect(config.profile).toBe('stealth');
  });
});

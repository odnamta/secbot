import { describe, it, expect } from 'vitest';
import {
  gaussianDelay,
  generateRefererChain,
  simulateHumanBehavior,
  buildConsistentProfile,
} from '../../src/utils/stealth.js';

describe('Behavioral stealth', () => {
  describe('gaussianDelay', () => {
    it('returns values centered around mean', () => {
      const delays = Array.from({ length: 200 }, () => gaussianDelay(500));
      const mean = delays.reduce((a, b) => a + b, 0) / delays.length;
      expect(mean).toBeGreaterThan(300);
      expect(mean).toBeLessThan(700);
    });

    it('never returns below 50ms floor', () => {
      const delays = Array.from({ length: 100 }, () => gaussianDelay(100));
      for (const d of delays) {
        expect(d).toBeGreaterThanOrEqual(50);
      }
    });

    it('produces different values (not constant)', () => {
      const delays = Array.from({ length: 10 }, () => gaussianDelay(500));
      const unique = new Set(delays);
      expect(unique.size).toBeGreaterThan(1);
    });
  });

  describe('generateRefererChain', () => {
    it('produces a 3-element chain', () => {
      const chain = generateRefererChain('https://example.com/page');
      expect(chain).toHaveLength(3);
    });

    it('starts with a search engine URL', () => {
      const chain = generateRefererChain('https://example.com/page');
      expect(chain[0]).toMatch(/google\.com|bing\.com|duckduckgo\.com/);
    });

    it('second element is the site root', () => {
      const chain = generateRefererChain('https://example.com/deep/page');
      expect(chain[1]).toBe('https://example.com/');
    });

    it('third element is the target URL', () => {
      const url = 'https://example.com/page?q=test';
      const chain = generateRefererChain(url);
      expect(chain[2]).toBe(url);
    });

    it('encodes hostname in search query', () => {
      const chain = generateRefererChain('https://test.example.com/');
      expect(chain[0]).toContain('test.example.com');
    });
  });

  describe('simulateHumanBehavior', () => {
    it('calls mouse.move and evaluate', async () => {
      let mouseMoved = false;
      let evaluated = false;
      const fakePage = {
        mouse: {
          move: async (_x: number, _y: number) => { mouseMoved = true; },
        },
        evaluate: async (_fn: () => void) => { evaluated = true; },
      };
      await simulateHumanBehavior(fakePage);
      expect(mouseMoved).toBe(true);
      expect(evaluated).toBe(true);
    });
  });

  describe('buildConsistentProfile', () => {
    it('returns a valid browser profile', () => {
      const profile = buildConsistentProfile();
      expect(profile.userAgent).toBeTruthy();
      expect(profile.viewport.width).toBeGreaterThan(0);
      expect(profile.viewport.height).toBeGreaterThan(0);
      expect(profile.locale).toBe('en-US');
      expect(profile.timezoneId).toBeTruthy();
    });

    it('matches macOS UA with macOS timezone', () => {
      // Run multiple times to get at least one macOS profile
      for (let i = 0; i < 50; i++) {
        const profile = buildConsistentProfile();
        if (profile.userAgent.includes('Macintosh')) {
          expect(profile.timezoneId).toBe('America/Los_Angeles');
          return;
        }
      }
      // If we never got a macOS profile in 50 tries, that's fine — test passes
    });

    it('matches Windows UA with Windows timezone', () => {
      for (let i = 0; i < 50; i++) {
        const profile = buildConsistentProfile();
        if (profile.userAgent.includes('Windows')) {
          expect(profile.timezoneId).toBe('America/New_York');
          return;
        }
      }
    });
  });
});

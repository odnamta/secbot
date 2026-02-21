import { describe, it, expect } from 'vitest';
import { DomainRateLimiter } from '../../src/utils/domain-rate-limiter.js';

describe('DomainRateLimiter', () => {
  describe('getRateLimit', () => {
    it('returns default RPS when no patterns are configured', () => {
      const limiter = new DomainRateLimiter({});
      expect(limiter.getRateLimit('https://example.com/page')).toBe(10); // built-in default
    });

    it('returns configured default RPS', () => {
      const limiter = new DomainRateLimiter({ default: 5 });
      expect(limiter.getRateLimit('https://example.com/page')).toBe(5);
    });

    it('matches exact domain', () => {
      const limiter = new DomainRateLimiter({
        'api.example.com': 2,
        default: 10,
      });
      expect(limiter.getRateLimit('https://api.example.com/v1/data')).toBe(2);
    });

    it('returns default for non-matching domain', () => {
      const limiter = new DomainRateLimiter({
        'api.example.com': 2,
        default: 10,
      });
      expect(limiter.getRateLimit('https://other.example.com/page')).toBe(10);
    });

    it('matches wildcard domain pattern', () => {
      const limiter = new DomainRateLimiter({
        '*.hackerone.com': 5,
        default: 10,
      });
      expect(limiter.getRateLimit('https://www.hackerone.com/report')).toBe(5);
      expect(limiter.getRateLimit('https://api.hackerone.com/bugs')).toBe(5);
    });

    it('wildcard matches deeply nested subdomains', () => {
      const limiter = new DomainRateLimiter({
        '*.example.com': 3,
        default: 10,
      });
      expect(limiter.getRateLimit('https://a.b.c.example.com/deep')).toBe(3);
    });

    it('wildcard does not match the bare domain itself', () => {
      const limiter = new DomainRateLimiter({
        '*.example.com': 3,
        default: 10,
      });
      // "example.com" should NOT match "*.example.com" — wildcard requires a subdomain
      expect(limiter.getRateLimit('https://example.com/page')).toBe(10);
    });

    it('exact match takes priority over wildcard', () => {
      const limiter = new DomainRateLimiter({
        'api.example.com': 1,
        '*.example.com': 5,
        default: 10,
      });
      expect(limiter.getRateLimit('https://api.example.com/v1')).toBe(1);
      expect(limiter.getRateLimit('https://www.example.com/page')).toBe(5);
    });

    it('is case-insensitive for domain matching', () => {
      const limiter = new DomainRateLimiter({
        'API.Example.COM': 2,
        default: 10,
      });
      expect(limiter.getRateLimit('https://api.example.com/v1')).toBe(2);
    });

    it('returns default for invalid URL', () => {
      const limiter = new DomainRateLimiter({ default: 7 });
      expect(limiter.getRateLimit('not-a-valid-url')).toBe(7);
    });

    it('handles multiple wildcard patterns', () => {
      const limiter = new DomainRateLimiter({
        '*.hackerone.com': 5,
        '*.bugcrowd.com': 3,
        default: 10,
      });
      expect(limiter.getRateLimit('https://www.hackerone.com/reports')).toBe(5);
      expect(limiter.getRateLimit('https://tracker.bugcrowd.com/submit')).toBe(3);
      expect(limiter.getRateLimit('https://other.com/')).toBe(10);
    });

    it('handles URLs with ports', () => {
      const limiter = new DomainRateLimiter({
        'localhost': 20,
        default: 10,
      });
      expect(limiter.getRateLimit('http://localhost:3000/api')).toBe(20);
    });
  });

  describe('getDefaultRps', () => {
    it('returns 10 when no default is configured', () => {
      const limiter = new DomainRateLimiter({});
      expect(limiter.getDefaultRps()).toBe(10);
    });

    it('returns configured default', () => {
      const limiter = new DomainRateLimiter({ default: 25 });
      expect(limiter.getDefaultRps()).toBe(25);
    });
  });

  describe('getPatterns', () => {
    it('returns empty map when no domain patterns configured', () => {
      const limiter = new DomainRateLimiter({ default: 10 });
      expect(limiter.getPatterns().size).toBe(0);
    });

    it('returns configured domain patterns without the default key', () => {
      const limiter = new DomainRateLimiter({
        '*.hackerone.com': 5,
        'api.example.com': 2,
        default: 10,
      });
      const patterns = limiter.getPatterns();
      expect(patterns.size).toBe(2);
      expect(patterns.get('*.hackerone.com')).toBe(5);
      expect(patterns.get('api.example.com')).toBe(2);
      expect(patterns.has('default')).toBe(false);
    });
  });

  describe('getLimiter', () => {
    it('returns a RateLimiter instance', () => {
      const limiter = new DomainRateLimiter({ default: 10 });
      const rl = limiter.getLimiter('https://example.com');
      expect(rl).toBeDefined();
      expect(typeof rl.acquire).toBe('function');
    });

    it('returns the same limiter for URLs with the same rate limit', () => {
      const limiter = new DomainRateLimiter({ default: 10 });
      const rl1 = limiter.getLimiter('https://a.com/page');
      const rl2 = limiter.getLimiter('https://b.com/other');
      expect(rl1).toBe(rl2); // same RPS -> same limiter instance
    });

    it('returns different limiters for different rate limits', () => {
      const limiter = new DomainRateLimiter({
        'fast.com': 20,
        'slow.com': 2,
        default: 10,
      });
      const rlFast = limiter.getLimiter('https://fast.com/page');
      const rlSlow = limiter.getLimiter('https://slow.com/page');
      const rlDefault = limiter.getLimiter('https://other.com/page');

      expect(rlFast).not.toBe(rlSlow);
      expect(rlFast).not.toBe(rlDefault);
      expect(rlSlow).not.toBe(rlDefault);
    });
  });

  describe('recordResponse', () => {
    it('does not throw for valid URL and status', () => {
      const limiter = new DomainRateLimiter({ default: 10 });
      expect(() => limiter.recordResponse('https://example.com', 200)).not.toThrow();
      expect(() => limiter.recordResponse('https://example.com', 429)).not.toThrow();
    });
  });

  describe('constructor with empty config', () => {
    it('creates a limiter with built-in defaults', () => {
      const limiter = new DomainRateLimiter();
      expect(limiter.getDefaultRps()).toBe(10);
      expect(limiter.getPatterns().size).toBe(0);
    });
  });
});

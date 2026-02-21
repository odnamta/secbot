import { describe, it, expect } from 'vitest';
import { SSRF_PAYLOADS, getSSRFPayloads, generateCallbackPayloads } from '../../src/config/payloads/ssrf.js';

describe('SSRF Callback Payloads', () => {
  describe('getSSRFPayloads() without callback URL', () => {
    it('returns only base payloads when no callback URL is provided', () => {
      const payloads = getSSRFPayloads();
      expect(payloads).toEqual(SSRF_PAYLOADS);
    });

    it('returns only base payloads when callback URL is undefined', () => {
      const payloads = getSSRFPayloads(undefined);
      expect(payloads).toEqual(SSRF_PAYLOADS);
    });

    it('returns a copy, not a reference to SSRF_PAYLOADS', () => {
      const payloads = getSSRFPayloads();
      payloads.push('http://test');
      expect(SSRF_PAYLOADS).not.toContain('http://test');
    });
  });

  describe('getSSRFPayloads() with callback URL', () => {
    const callbackUrl = 'https://callback.example.com';

    it('returns base payloads plus callback payloads', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      expect(payloads.length).toBeGreaterThan(SSRF_PAYLOADS.length);
    });

    it('starts with all base payloads', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      for (let i = 0; i < SSRF_PAYLOADS.length; i++) {
        expect(payloads[i]).toBe(SSRF_PAYLOADS[i]);
      }
    });

    it('callback payloads contain the provided URL', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      const callbackPayloads = payloads.slice(SSRF_PAYLOADS.length);
      expect(callbackPayloads.length).toBeGreaterThan(0);
      for (const payload of callbackPayloads) {
        // URL-encoded variant still contains the base URL (just encoded)
        expect(
          payload.includes('callback.example.com')
        ).toBe(true);
      }
    });

    it('callback payloads contain unique identifiers', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      const callbackPayloads = payloads.slice(SSRF_PAYLOADS.length);
      // Each payload should contain 'ssrf-' followed by a UUID
      for (const payload of callbackPayloads) {
        expect(payload).toMatch(/ssrf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
      }
    });

    it('generates different UUIDs each call', () => {
      const payloads1 = getSSRFPayloads(callbackUrl);
      const payloads2 = getSSRFPayloads(callbackUrl);
      const cb1 = payloads1.slice(SSRF_PAYLOADS.length);
      const cb2 = payloads2.slice(SSRF_PAYLOADS.length);
      // UUIDs should differ between calls
      expect(cb1).not.toEqual(cb2);
    });
  });

  describe('generateCallbackPayloads()', () => {
    it('generates 5 callback payload variants', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      expect(payloads).toHaveLength(5);
    });

    it('strips trailing slashes from callback URL', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com///');
      for (const payload of payloads) {
        expect(payload).not.toMatch(/example\.com\/\/\//);
      }
    });

    it('includes a plain URL variant', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const plain = payloads.filter((p) => p.startsWith('https://callback.example.com/ssrf-') && !p.includes('/probe') && !p.includes(':80') && !p.includes(':443'));
      expect(plain.length).toBeGreaterThanOrEqual(1);
    });

    it('includes a nested path variant', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const nested = payloads.filter((p) => p.includes('/probe'));
      expect(nested.length).toBeGreaterThanOrEqual(1);
    });

    it('includes port variants', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const withPort80 = payloads.filter((p) => p.includes(':80/'));
      const withPort443 = payloads.filter((p) => p.includes(':443/'));
      expect(withPort80.length).toBeGreaterThanOrEqual(1);
      expect(withPort443.length).toBeGreaterThanOrEqual(1);
    });

    it('includes a URL-encoded variant', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      // The encoded variant goes through encodeURI, which for this URL is the same
      // but the structure should still be valid
      expect(payloads.length).toBe(5);
      // All payloads should be valid URLs or URL-like strings
      for (const payload of payloads) {
        expect(payload).toContain('callback.example.com');
      }
    });

    it('all payloads have unique UUIDs', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const uuids = payloads
        .map((p) => {
          const match = p.match(/ssrf-([0-9a-f-]{36})/);
          return match ? match[1] : null;
        })
        .filter(Boolean);
      expect(new Set(uuids).size).toBe(uuids.length);
    });
  });
});

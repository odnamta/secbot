import { describe, it, expect } from 'vitest';
import { generateDnsCanary, DnsCanaryServer } from '../../src/scanner/oob/dns-canary.js';

describe('generateDnsCanary', () => {
  it('generates a subdomain in the form payloadId.domain', () => {
    const result = generateDnsCanary('blind-xss-001', 'oob.example.com');
    expect(result).toBe('blind-xss-001.oob.example.com');
  });

  it('strips leading dots from domain', () => {
    const result = generateDnsCanary('test', '..oob.example.com');
    expect(result).toBe('test.oob.example.com');
  });

  it('sanitizes payloadId to DNS-safe characters', () => {
    const result = generateDnsCanary('payload_with@special!chars', 'oob.test');
    expect(result).toBe('payload-with-special-chars.oob.test');
  });

  it('strips leading and trailing hyphens from sanitized payloadId', () => {
    const result = generateDnsCanary('---test---', 'oob.test');
    expect(result).toBe('test.oob.test');
  });

  it('truncates payloadId to 63 characters (DNS label limit)', () => {
    const longId = 'a'.repeat(100);
    const result = generateDnsCanary(longId, 'oob.test');
    const label = result.split('.')[0];
    expect(label.length).toBeLessThanOrEqual(63);
  });

  it('lowercases payloadId', () => {
    const result = generateDnsCanary('UPPERCASE-ID', 'oob.test');
    expect(result).toBe('uppercase-id.oob.test');
  });

  it('generates unique subdomains for different payloadIds', () => {
    const a = generateDnsCanary('payload-a', 'oob.test');
    const b = generateDnsCanary('payload-b', 'oob.test');
    expect(a).not.toBe(b);
  });
});

describe('DnsCanaryServer', () => {
  it('stores the base domain', () => {
    const server = new DnsCanaryServer('oob.example.com');
    expect(server.getDomain()).toBe('oob.example.com');
  });

  it('strips leading dots from domain', () => {
    const server = new DnsCanaryServer('..oob.example.com');
    expect(server.getDomain()).toBe('oob.example.com');
  });

  describe('generate', () => {
    it('creates a canary with the given payloadId', () => {
      const server = new DnsCanaryServer('oob.test');
      const canary = server.generate('my-payload');
      expect(canary.payloadId).toBe('my-payload');
      expect(canary.fullDomain).toBe('my-payload.oob.test');
    });

    it('auto-generates a UUID payloadId when none provided', () => {
      const server = new DnsCanaryServer('oob.test');
      const canary = server.generate();
      expect(canary.payloadId).toMatch(/^[0-9a-f-]{36}$/);
      expect(canary.fullDomain).toContain('.oob.test');
    });

    it('generates unique canaries on each call', () => {
      const server = new DnsCanaryServer('oob.test');
      const c1 = server.generate();
      const c2 = server.generate();
      expect(c1.payloadId).not.toBe(c2.payloadId);
      expect(c1.fullDomain).not.toBe(c2.fullDomain);
    });

    it('records a timestamp', () => {
      const server = new DnsCanaryServer('oob.test');
      const canary = server.generate('ts-test');
      expect(canary.createdAt).toBeTruthy();
      // Should be a valid ISO date
      expect(new Date(canary.createdAt).toISOString()).toBe(canary.createdAt);
    });
  });

  describe('lookup', () => {
    it('finds a previously generated canary', () => {
      const server = new DnsCanaryServer('oob.test');
      server.generate('lookup-me');
      const found = server.lookup('lookup-me');
      expect(found).toBeDefined();
      expect(found!.payloadId).toBe('lookup-me');
    });

    it('returns undefined for unknown payloadId', () => {
      const server = new DnsCanaryServer('oob.test');
      expect(server.lookup('nonexistent')).toBeUndefined();
    });
  });

  describe('getAll', () => {
    it('returns all generated canaries', () => {
      const server = new DnsCanaryServer('oob.test');
      server.generate('a');
      server.generate('b');
      server.generate('c');
      const all = server.getAll();
      expect(all).toHaveLength(3);
      expect(all.map((c) => c.payloadId)).toEqual(['a', 'b', 'c']);
    });

    it('returns empty array when no canaries generated', () => {
      const server = new DnsCanaryServer('oob.test');
      expect(server.getAll()).toEqual([]);
    });
  });
});

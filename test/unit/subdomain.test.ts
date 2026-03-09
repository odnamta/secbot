import { describe, it, expect, vi, beforeEach } from 'vitest';
import dns from 'node:dns/promises';
import { enumerateSubdomains, COMMON_SUBDOMAINS, type SubdomainResult } from '../../src/scanner/recon/subdomain.js';

// Mock the logger to suppress output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('COMMON_SUBDOMAINS', () => {
  it('has at least 50 entries', () => {
    expect(COMMON_SUBDOMAINS.length).toBeGreaterThanOrEqual(50);
  });

  it('includes essential subdomains', () => {
    const essentials = ['www', 'mail', 'api', 'admin', 'dev', 'staging', 'cdn', 'vpn'];
    for (const sub of essentials) {
      expect(COMMON_SUBDOMAINS).toContain(sub);
    }
  });

  it('has no duplicates', () => {
    const unique = new Set(COMMON_SUBDOMAINS);
    expect(unique.size).toBe(COMMON_SUBDOMAINS.length);
  });

  it('has no empty strings', () => {
    for (const sub of COMMON_SUBDOMAINS) {
      expect(sub.length).toBeGreaterThan(0);
    }
  });
});

describe('enumerateSubdomains', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('exists and returns an array', async () => {
    // Mock all DNS to return ENOTFOUND so the test runs quickly
    vi.spyOn(dns, 'resolve4').mockRejectedValue(
      Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' }),
    );
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomains('nonexistent-domain-test.invalid');
    expect(Array.isArray(results)).toBe(true);
    expect(results).toHaveLength(0);
  });

  it('returns found subdomains with IPs', async () => {
    // Mock DNS: only www.example.com resolves
    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') {
        return ['93.184.216.34'];
      }
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomains('example.com');
    expect(results).toHaveLength(1);
    expect(results[0].subdomain).toBe('www.example.com');
    expect(results[0].ips).toEqual(['93.184.216.34']);
    expect(results[0].cname).toBeUndefined();
  });

  it('captures CNAME records when available', async () => {
    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'cdn.example.com') {
        return ['1.2.3.4'];
      }
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockImplementation(async (hostname: string) => {
      if (hostname === 'cdn.example.com') {
        return ['cdn.cloudfront.net'];
      }
      throw Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' });
    });

    const results = await enumerateSubdomains('example.com');
    const cdn = results.find((r) => r.subdomain === 'cdn.example.com');
    expect(cdn).toBeDefined();
    expect(cdn!.cname).toBe('cdn.cloudfront.net');
  });

  it('handles multiple resolved subdomains', async () => {
    const resolved = new Map<string, string[]>([
      ['www.example.com', ['1.1.1.1']],
      ['mail.example.com', ['2.2.2.2']],
      ['api.example.com', ['3.3.3.3']],
    ]);

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      const ips = resolved.get(hostname);
      if (ips) return ips;
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomains('example.com');
    expect(results).toHaveLength(3);
    const subdomainNames = results.map((r) => r.subdomain);
    expect(subdomainNames).toContain('www.example.com');
    expect(subdomainNames).toContain('mail.example.com');
    expect(subdomainNames).toContain('api.example.com');
  });

  it('handles DNS timeout errors gracefully', async () => {
    vi.spyOn(dns, 'resolve4').mockRejectedValue(
      Object.assign(new Error('queryA ETIMEOUT'), { code: 'ETIMEOUT' }),
    );
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ETIMEOUT'), { code: 'ETIMEOUT' }),
    );

    const results = await enumerateSubdomains('example.com');
    expect(results).toHaveLength(0);
  });

  it('handles SERVFAIL errors gracefully', async () => {
    vi.spyOn(dns, 'resolve4').mockRejectedValue(
      Object.assign(new Error('queryA SERVFAIL'), { code: 'SERVFAIL' }),
    );

    const results = await enumerateSubdomains('example.com');
    expect(results).toHaveLength(0);
  });

  it('respects concurrency parameter', async () => {
    let maxConcurrent = 0;
    let currentConcurrent = 0;

    vi.spyOn(dns, 'resolve4').mockImplementation(async () => {
      currentConcurrent++;
      if (currentConcurrent > maxConcurrent) {
        maxConcurrent = currentConcurrent;
      }
      // Simulate a small delay so concurrency is observable
      await new Promise((resolve) => setTimeout(resolve, 5));
      currentConcurrent--;
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });

    await enumerateSubdomains('example.com', 5);
    // maxConcurrent should not exceed the concurrency limit
    expect(maxConcurrent).toBeLessThanOrEqual(5);
  });

  it('result matches SubdomainResult interface', async () => {
    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'api.example.com') return ['10.0.0.1', '10.0.0.2'];
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomains('example.com');
    const api = results.find((r) => r.subdomain === 'api.example.com');
    expect(api).toBeDefined();

    // Verify shape
    expect(api).toHaveProperty('subdomain');
    expect(api).toHaveProperty('ips');
    expect(typeof api!.subdomain).toBe('string');
    expect(Array.isArray(api!.ips)).toBe(true);
    expect(api!.ips).toHaveLength(2);
  });
});

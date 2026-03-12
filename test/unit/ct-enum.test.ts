import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import dns from 'node:dns/promises';
import { enumerateSubdomainsCT, mergeSubdomainResults } from '../../src/scanner/recon/ct-enum.js';
import type { SubdomainResult } from '../../src/scanner/recon/subdomain.js';

// Mock the logger to suppress output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// Sample crt.sh response entries
function makeCrtShResponse(entries: Array<{ name_value: string }>) {
  return entries.map((e, i) => ({
    id: i + 1,
    issuer_ca_id: 1,
    issuer_name: 'Test CA',
    common_name: 'example.com',
    name_value: e.name_value,
    not_before: '2025-01-01T00:00:00',
    not_after: '2026-01-01T00:00:00',
    serial_number: `SN${i}`,
    result_count: 1,
  }));
}

describe('enumerateSubdomainsCT', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('parses crt.sh response and resolves subdomains', async () => {
    const crtResponse = makeCrtShResponse([
      { name_value: 'www.example.com' },
      { name_value: 'api.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') return ['93.184.216.34'];
      if (hostname === 'api.example.com') return ['93.184.216.35'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(2);
    expect(results.map(r => r.subdomain).sort()).toEqual(['api.example.com', 'www.example.com']);
  });

  it('deduplicates subdomains from crt.sh response', async () => {
    // crt.sh often returns the same subdomain in multiple certificate entries
    const crtResponse = makeCrtShResponse([
      { name_value: 'www.example.com' },
      { name_value: 'www.example.com' },
      { name_value: 'www.example.com' },
      { name_value: 'api.example.com' },
      { name_value: 'api.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') return ['1.1.1.1'];
      if (hostname === 'api.example.com') return ['2.2.2.2'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    // Should only have 2 unique subdomains, not 5
    expect(results).toHaveLength(2);
  });

  it('handles multiline name_value fields', async () => {
    // crt.sh name_value can contain multiple names separated by newlines
    const crtResponse = makeCrtShResponse([
      { name_value: 'www.example.com\nmail.example.com\nftp.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      const ips: Record<string, string[]> = {
        'www.example.com': ['1.1.1.1'],
        'mail.example.com': ['2.2.2.2'],
        'ftp.example.com': ['3.3.3.3'],
      };
      if (ips[hostname]) return ips[hostname];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(3);
    const names = results.map(r => r.subdomain).sort();
    expect(names).toEqual(['ftp.example.com', 'mail.example.com', 'www.example.com']);
  });

  it('skips wildcard entries', async () => {
    const crtResponse = makeCrtShResponse([
      { name_value: '*.example.com' },
      { name_value: 'www.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') return ['1.1.1.1'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(1);
    expect(results[0].subdomain).toBe('www.example.com');
  });

  it('filters out subdomains not belonging to target domain', async () => {
    const crtResponse = makeCrtShResponse([
      { name_value: 'www.example.com' },
      { name_value: 'evil.other-domain.com' },
      { name_value: 'notexample.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') return ['1.1.1.1'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(1);
    expect(results[0].subdomain).toBe('www.example.com');
  });

  it('handles crt.sh timeout gracefully', async () => {
    // Simulate AbortError (fetch aborted due to timeout)
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(
      Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }),
    ));

    const results = await enumerateSubdomainsCT('example.com', 10, 1);
    expect(results).toHaveLength(0);
  });

  it('handles crt.sh HTTP error gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
    }));

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(0);
  });

  it('handles invalid JSON response gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.reject(new Error('Unexpected token')),
    }));

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(0);
  });

  it('handles network failure gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(
      new Error('fetch failed: ECONNREFUSED'),
    ));

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(0);
  });

  it('handles empty crt.sh response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([]),
    }));

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(0);
  });

  it('captures CNAME records for CT subdomains', async () => {
    const crtResponse = makeCrtShResponse([
      { name_value: 'cdn.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'cdn.example.com') return ['1.2.3.4'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockImplementation(async (hostname: string) => {
      if (hostname === 'cdn.example.com') return ['cdn.cloudfront.net'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(1);
    expect(results[0].cname).toBe('cdn.cloudfront.net');
  });

  it('returns SubdomainResult[] matching the interface', async () => {
    const crtResponse = makeCrtShResponse([
      { name_value: 'test.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockResolvedValue(['10.0.0.1']);
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    expect(results).toHaveLength(1);
    const result = results[0];
    expect(result).toHaveProperty('subdomain');
    expect(result).toHaveProperty('ips');
    expect(typeof result.subdomain).toBe('string');
    expect(Array.isArray(result.ips)).toBe(true);
  });

  it('normalizes subdomains to lowercase', async () => {
    const crtResponse = makeCrtShResponse([
      { name_value: 'WWW.Example.COM' },
      { name_value: 'www.example.com' },
    ]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(crtResponse),
    }));

    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') return ['1.1.1.1'];
      throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const results = await enumerateSubdomainsCT('example.com');
    // Should deduplicate case-insensitively
    expect(results).toHaveLength(1);
    expect(results[0].subdomain).toBe('www.example.com');
  });
});

describe('mergeSubdomainResults', () => {
  it('merges disjoint results from DNS and CT', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1'] },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'staging.example.com', ips: ['2.2.2.2'] },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged).toHaveLength(2);
    const names = merged.map(r => r.subdomain).sort();
    expect(names).toEqual(['staging.example.com', 'www.example.com']);
  });

  it('deduplicates overlapping results by hostname', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1'] },
      { subdomain: 'api.example.com', ips: ['3.3.3.3'] },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1'] },
      { subdomain: 'mail.example.com', ips: ['4.4.4.4'] },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged).toHaveLength(3);
  });

  it('merges IPs from both sources for the same subdomain', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1'] },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['2.2.2.2'] },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged).toHaveLength(1);
    expect(merged[0].ips).toContain('1.1.1.1');
    expect(merged[0].ips).toContain('2.2.2.2');
  });

  it('deduplicates IPs when merging', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1', '2.2.2.2'] },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1', '3.3.3.3'] },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged).toHaveLength(1);
    expect(merged[0].ips).toHaveLength(3);
    expect(new Set(merged[0].ips).size).toBe(3);
  });

  it('preserves CNAME from DNS when CT has none', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'cdn.example.com', ips: ['1.1.1.1'], cname: 'cdn.cloudfront.net' },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'cdn.example.com', ips: ['1.1.1.1'] },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged[0].cname).toBe('cdn.cloudfront.net');
  });

  it('takes CNAME from CT when DNS has none', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'cdn.example.com', ips: ['1.1.1.1'] },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'cdn.example.com', ips: ['1.1.1.1'], cname: 'cdn.cloudfront.net' },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged[0].cname).toBe('cdn.cloudfront.net');
  });

  it('handles empty inputs', () => {
    expect(mergeSubdomainResults([], [])).toHaveLength(0);
    expect(mergeSubdomainResults([], [{ subdomain: 'a.example.com', ips: ['1.1.1.1'] }])).toHaveLength(1);
    expect(mergeSubdomainResults([{ subdomain: 'a.example.com', ips: ['1.1.1.1'] }], [])).toHaveLength(1);
  });

  it('deduplicates case-insensitively', () => {
    const dnsResults: SubdomainResult[] = [
      { subdomain: 'WWW.example.com', ips: ['1.1.1.1'] },
    ];
    const ctResults: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['2.2.2.2'] },
    ];

    const merged = mergeSubdomainResults(dnsResults, ctResults);
    expect(merged).toHaveLength(1);
    expect(merged[0].ips).toContain('1.1.1.1');
    expect(merged[0].ips).toContain('2.2.2.2');
  });
});

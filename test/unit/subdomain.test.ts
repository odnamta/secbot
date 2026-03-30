import { describe, it, expect, vi, beforeEach } from 'vitest';
import dns from 'node:dns/promises';
import {
  enumerateSubdomains,
  probeSubdomains,
  enumerateAndProbeSubdomains,
  COMMON_SUBDOMAINS,
  type SubdomainResult,
  type HttpProbeResult,
} from '../../src/scanner/recon/subdomain.js';

// Mock the logger to suppress output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock FastEngine
const mockBatch = vi.fn();
const mockGetStats = vi.fn().mockReturnValue({ total: 0, errors: 0, active: 0, rps: 0 });

vi.mock('../../src/scanner/fast-engine.js', () => {
  // Must use a real function (not arrow) so it works with `new`
  const FastEngine = function FastEngine() {
    return {
      batch: mockBatch,
      probe: vi.fn(),
      getStats: mockGetStats,
    };
  };
  return { FastEngine };
});

describe('COMMON_SUBDOMAINS', () => {
  it('has at least 500 entries', () => {
    expect(COMMON_SUBDOMAINS.length).toBeGreaterThanOrEqual(500);
  });

  it('includes essential subdomains', () => {
    const essentials = [
      'www', 'mail', 'api', 'admin', 'dev', 'staging', 'cdn', 'vpn',
      'ftp', 'smtp', 'pop', 'imap', 'webmail',
      'test', 'qa', 'uat', 'sandbox', 'demo', 'beta',
      'app', 'portal', 'gateway', 'dashboard',
      'internal', 'intranet', 'corp',
      'jenkins', 'ci', 'gitlab', 'jira', 'confluence',
      'sentry', 'monitoring', 'grafana', 'kibana',
      'db', 'mysql', 'postgres', 'redis', 'mongo',
      'auth', 'sso', 'login', 'oauth',
      'shop', 'store', 'payment', 'billing',
      'mobile', 'm',
      'k8s', 'docker', 'aws', 'cloud',
      'backup', 'archive', 'old', 'legacy',
      'ns1', 'ns2', 'dns',
      'static', 'assets', 'media', 'images',
    ];
    for (const sub of essentials) {
      expect(COMMON_SUBDOMAINS, `Missing essential subdomain: ${sub}`).toContain(sub);
    }
  });

  it('includes development lifecycle subdomains', () => {
    const devLifecycle = ['dev', 'staging', 'test', 'qa', 'uat', 'sandbox', 'demo', 'beta', 'alpha', 'canary', 'preprod'];
    for (const sub of devLifecycle) {
      expect(COMMON_SUBDOMAINS, `Missing dev lifecycle subdomain: ${sub}`).toContain(sub);
    }
  });

  it('includes cloud/infrastructure subdomains', () => {
    const cloud = ['k8s', 'kubernetes', 'docker', 'aws', 'gcp', 'azure', 'cloud', 's3', 'lambda'];
    for (const sub of cloud) {
      expect(COMMON_SUBDOMAINS, `Missing cloud subdomain: ${sub}`).toContain(sub);
    }
  });

  it('includes security-relevant subdomains', () => {
    const security = ['admin', 'vpn', 'ssh', 'bastion', 'internal', 'intranet', 'secure', 'vault'];
    for (const sub of security) {
      expect(COMMON_SUBDOMAINS, `Missing security subdomain: ${sub}`).toContain(sub);
    }
  });

  it('includes numbered variants', () => {
    const numbered = ['web1', 'web2', 'srv1', 'srv2', 'server1', 'node1', 'host1', 'dc1'];
    for (const sub of numbered) {
      expect(COMMON_SUBDOMAINS, `Missing numbered subdomain: ${sub}`).toContain(sub);
    }
  });

  it('includes regional subdomains', () => {
    const regional = ['us', 'eu', 'asia', 'au', 'uk', 'de', 'jp', 'sg', 'id'];
    for (const sub of regional) {
      expect(COMMON_SUBDOMAINS, `Missing regional subdomain: ${sub}`).toContain(sub);
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

  it('all entries are lowercase and trimmed', () => {
    for (const sub of COMMON_SUBDOMAINS) {
      expect(sub).toBe(sub.toLowerCase().trim());
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

describe('probeSubdomains', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetStats.mockReturnValue({ total: 0, errors: 0, active: 0, rps: 0 });
  });

  it('returns empty array for empty input', async () => {
    const results = await probeSubdomains([]);
    expect(results).toEqual([]);
    expect(mockBatch).not.toHaveBeenCalled();
  });

  it('probes HTTPS first, then HTTP fallback for failures', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'api.example.com', ips: ['1.1.1.1'] },
      { subdomain: 'dev.example.com', ips: ['2.2.2.2'] },
    ];

    // First batch call (HTTPS): api succeeds, dev fails
    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://api.example.com',
        status: 200,
        headers: { server: 'nginx' },
        body: '<html><title>API Docs</title></html>',
        redirected: false,
        timeMs: 150,
      },
      null, // dev fails HTTPS
    ]);

    // Second batch call (HTTP fallback for dev)
    mockBatch.mockResolvedValueOnce([
      {
        url: 'http://dev.example.com',
        status: 200,
        headers: { server: 'Apache' },
        body: '<html><title>Dev Portal</title></html>',
        redirected: false,
        timeMs: 200,
      },
    ]);

    const results = await probeSubdomains(subdomains);

    expect(results).toHaveLength(2);

    const api = results.find(r => r.subdomain === 'api.example.com');
    expect(api).toBeDefined();
    expect(api!.url).toBe('https://api.example.com');
    expect(api!.status).toBe(200);
    expect(api!.server).toBe('nginx');
    expect(api!.title).toBe('API Docs');

    const dev = results.find(r => r.subdomain === 'dev.example.com');
    expect(dev).toBeDefined();
    expect(dev!.url).toBe('http://dev.example.com');
    expect(dev!.server).toBe('Apache');
    expect(dev!.title).toBe('Dev Portal');
  });

  it('captures redirected URLs', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'www.example.com', ips: ['1.1.1.1'] },
    ];

    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://example.com/', // Final URL after redirect
        status: 200,
        headers: {},
        body: '<html><title>Example</title></html>',
        redirected: true,
        timeMs: 300,
      },
    ]);

    const results = await probeSubdomains(subdomains);

    expect(results).toHaveLength(1);
    expect(results[0].redirected).toBe(true);
    expect(results[0].finalUrl).toBe('https://example.com/');
  });

  it('filters out unacceptable status codes', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'gone.example.com', ips: ['1.1.1.1'] },
    ];

    // HTTPS returns 404 (not in accept list by default)
    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://gone.example.com',
        status: 404,
        headers: {},
        body: 'Not Found',
        redirected: false,
        timeMs: 100,
      },
    ]);

    // HTTP also returns 404
    mockBatch.mockResolvedValueOnce([
      {
        url: 'http://gone.example.com',
        status: 404,
        headers: {},
        body: 'Not Found',
        redirected: false,
        timeMs: 100,
      },
    ]);

    const results = await probeSubdomains(subdomains);
    expect(results).toHaveLength(0);
  });

  it('accepts custom status codes', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'custom.example.com', ips: ['1.1.1.1'] },
    ];

    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://custom.example.com',
        status: 418,
        headers: {},
        body: "I'm a teapot",
        redirected: false,
        timeMs: 50,
      },
    ]);

    const results = await probeSubdomains(subdomains, { acceptStatuses: [418] });
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(418);
  });

  it('does not HTTP-fallback for HTTPS successes', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'secure.example.com', ips: ['1.1.1.1'] },
    ];

    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://secure.example.com',
        status: 200,
        headers: {},
        body: '<html></html>',
        redirected: false,
        timeMs: 100,
      },
    ]);

    const results = await probeSubdomains(subdomains);
    expect(results).toHaveLength(1);
    // Only one batch call (HTTPS) — no HTTP fallback
    expect(mockBatch).toHaveBeenCalledTimes(1);
  });

  it('handles 403 as alive (could be access-controlled)', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'admin.example.com', ips: ['1.1.1.1'] },
    ];

    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://admin.example.com',
        status: 403,
        headers: { server: 'cloudflare' },
        body: '<html><title>Access Denied</title></html>',
        redirected: false,
        timeMs: 80,
      },
    ]);

    const results = await probeSubdomains(subdomains);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(403);
    expect(results[0].title).toBe('Access Denied');
  });

  it('extracts title from HTML body', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'blog.example.com', ips: ['1.1.1.1'] },
    ];

    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://blog.example.com',
        status: 200,
        headers: {},
        body: '<!DOCTYPE html><html><head><title>Company Blog - Latest News</title></head><body></body></html>',
        redirected: false,
        timeMs: 120,
      },
    ]);

    const results = await probeSubdomains(subdomains);
    expect(results[0].title).toBe('Company Blog - Latest News');
  });

  it('truncates very long titles', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'long.example.com', ips: ['1.1.1.1'] },
    ];

    const longTitle = 'A'.repeat(300);
    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://long.example.com',
        status: 200,
        headers: {},
        body: `<html><title>${longTitle}</title></html>`,
        redirected: false,
        timeMs: 100,
      },
    ]);

    const results = await probeSubdomains(subdomains);
    expect(results[0].title!.length).toBeLessThanOrEqual(204); // 200 + '...'
  });

  it('result matches HttpProbeResult interface', async () => {
    const subdomains: SubdomainResult[] = [
      { subdomain: 'typed.example.com', ips: ['5.5.5.5'] },
    ];

    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://typed.example.com',
        status: 200,
        headers: { server: 'nginx/1.24' },
        body: '<html><title>Typed</title></html>',
        redirected: false,
        timeMs: 99,
      },
    ]);

    const results = await probeSubdomains(subdomains);
    const r = results[0];

    // Verify shape matches HttpProbeResult
    expect(r).toHaveProperty('subdomain');
    expect(r).toHaveProperty('url');
    expect(r).toHaveProperty('status');
    expect(r).toHaveProperty('timeMs');
    expect(r).toHaveProperty('redirected');
    expect(typeof r.subdomain).toBe('string');
    expect(typeof r.url).toBe('string');
    expect(typeof r.status).toBe('number');
    expect(typeof r.timeMs).toBe('number');
    expect(typeof r.redirected).toBe('boolean');
  });
});

describe('enumerateAndProbeSubdomains', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
    mockGetStats.mockReturnValue({ total: 0, errors: 0, active: 0, rps: 0 });
  });

  it('returns combined DNS + HTTP results', async () => {
    // Mock DNS: www and api resolve
    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'www.example.com') return ['1.1.1.1'];
      if (hostname === 'api.example.com') return ['2.2.2.2'];
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    // Mock HTTP probing: both alive
    mockBatch.mockResolvedValueOnce([
      {
        url: 'https://www.example.com',
        status: 200,
        headers: {},
        body: '<html><title>Home</title></html>',
        redirected: false,
        timeMs: 100,
      },
      {
        url: 'https://api.example.com',
        status: 200,
        headers: { server: 'gunicorn' },
        body: '{"status":"ok"}',
        redirected: false,
        timeMs: 50,
      },
    ]);

    const result = await enumerateAndProbeSubdomains('example.com');

    expect(result.resolved).toHaveLength(2);
    expect(result.httpAlive).toHaveLength(2);

    const resolvedNames = result.resolved.map(r => r.subdomain);
    expect(resolvedNames).toContain('www.example.com');
    expect(resolvedNames).toContain('api.example.com');

    const aliveNames = result.httpAlive.map(r => r.subdomain);
    expect(aliveNames).toContain('www.example.com');
    expect(aliveNames).toContain('api.example.com');
  });

  it('returns empty httpAlive when no DNS results', async () => {
    vi.spyOn(dns, 'resolve4').mockRejectedValue(
      Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    const result = await enumerateAndProbeSubdomains('nope.invalid');

    expect(result.resolved).toHaveLength(0);
    expect(result.httpAlive).toHaveLength(0);
  });

  it('handles DNS success but HTTP failure', async () => {
    vi.spyOn(dns, 'resolve4').mockImplementation(async (hostname: string) => {
      if (hostname === 'internal.example.com') return ['10.0.0.1'];
      throw Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' });
    });
    vi.spyOn(dns, 'resolveCname').mockRejectedValue(
      Object.assign(new Error('queryCname ENOTFOUND'), { code: 'ENOTFOUND' }),
    );

    // HTTPS fails
    mockBatch.mockResolvedValueOnce([null]);
    // HTTP also fails
    mockBatch.mockResolvedValueOnce([null]);

    const result = await enumerateAndProbeSubdomains('example.com');

    expect(result.resolved).toHaveLength(1);
    expect(result.resolved[0].subdomain).toBe('internal.example.com');
    expect(result.httpAlive).toHaveLength(0);
  });
});

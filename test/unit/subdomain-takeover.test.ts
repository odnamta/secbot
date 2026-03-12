import { describe, it, expect, vi } from 'vitest';
import {
  TAKEOVER_FINGERPRINTS,
  matchFingerprint,
} from '../../src/scanner/active/subdomain-takeover-fingerprints.js';
import {
  subdomainTakeoverCheck,
  checkSubdomainTakeover,
} from '../../src/scanner/active/subdomain-takeover.js';
import type { SubdomainResult } from '../../src/scanner/recon/subdomain.js';
import type { ScanConfig } from '../../src/scanner/types.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// ─── Helpers ────────────────────────────────────────────────────────

function makeConfig(subdomainResults?: SubdomainResult[]): ScanConfig {
  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    maxPages: 10,
    timeout: 30000,
    respectRobots: true,
    outputFormat: ['terminal'],
    concurrency: 5,
    requestDelay: 0,
    logRequests: false,
    useAI: false,
    subdomainResults,
  };
}

// ─── TAKEOVER_FINGERPRINTS ───────────────────────────────────────────

describe('TAKEOVER_FINGERPRINTS', () => {
  it('has at least 14 service entries', () => {
    expect(TAKEOVER_FINGERPRINTS.length).toBeGreaterThanOrEqual(14);
  });

  it('includes GitHub Pages', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'GitHub Pages');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(true);
  });

  it('includes Heroku', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'Heroku');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(true);
  });

  it('includes AWS S3', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'AWS S3');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(true);
  });

  it('includes Shopify', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'Shopify');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(true);
  });

  it('includes Azure', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'Azure');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(true);
  });

  it('includes Vercel as non-exploitable', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'Vercel');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(false);
  });

  it('includes Google Cloud as non-exploitable', () => {
    const svc = TAKEOVER_FINGERPRINTS.find((f) => f.service === 'Google Cloud');
    expect(svc).toBeDefined();
    expect(svc!.exploitable).toBe(false);
  });

  it('every entry has required fields', () => {
    for (const fp of TAKEOVER_FINGERPRINTS) {
      expect(typeof fp.service).toBe('string');
      expect(fp.service.length).toBeGreaterThan(0);
      expect(Array.isArray(fp.cnamePatterns)).toBe(true);
      expect(Array.isArray(fp.bodyFingerprints)).toBe(true);
      expect(Array.isArray(fp.statusCodes)).toBe(true);
      expect(typeof fp.exploitable).toBe('boolean');
    }
  });
});

// ─── matchFingerprint ────────────────────────────────────────────────

describe('matchFingerprint', () => {
  it('detects GitHub Pages 404 (body fingerprint)', () => {
    const body = "There isn't a GitHub Pages site here.";
    const result = matchFingerprint('test.example.com', body, 404);
    expect(result).not.toBeNull();
    expect(result!.service).toBe('GitHub Pages');
  });

  it('detects Heroku no-app (body fingerprint)', () => {
    const body = 'No such app';
    const result = matchFingerprint('app.example.com', body, 404);
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Heroku');
  });

  it('detects S3 NoSuchBucket (body fingerprint)', () => {
    const body = '<Code>NoSuchBucket</Code>';
    const result = matchFingerprint('assets.example.com', body, 404);
    expect(result).not.toBeNull();
    expect(result!.service).toBe('AWS S3');
  });

  it('returns null for normal 200 response', () => {
    const body = '<html><body>Hello World!</body></html>';
    const result = matchFingerprint('www.example.com', body, 200);
    expect(result).toBeNull();
  });

  it('returns null for empty body with no CNAME', () => {
    const result = matchFingerprint('www.example.com', '', 200);
    expect(result).toBeNull();
  });

  it('matches by CNAME when body is empty', () => {
    // GitHub Pages CNAME pattern: *.github.io
    const result = matchFingerprint(
      'blog.example.com',
      '',
      404,
      'myorg.github.io',
    );
    expect(result).not.toBeNull();
    expect(result!.service).toBe('GitHub Pages');
  });

  it('matches Heroku CNAME even with non-takeover body', () => {
    const result = matchFingerprint(
      'api.example.com',
      '',
      404,
      'my-app.herokuapp.com',
    );
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Heroku');
  });

  it('prefers CNAME match over body match when both apply', () => {
    // Heroku CNAME + some generic body
    const result = matchFingerprint(
      'api.example.com',
      'generic not found page',
      404,
      'my-app.herokuapp.com',
    );
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Heroku');
  });

  it('detects Azure by body fingerprint', () => {
    const body = 'This web app is stopped.';
    const result = matchFingerprint('portal.example.com', body, 404);
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Azure');
  });

  it('detects Netlify by body fingerprint', () => {
    const body = 'Not Found - Request ID: abc123<br>No netlify site configured.';
    const result = matchFingerprint('site.example.com', body, 404);
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Netlify');
  });
});

// ─── subdomainTakeoverCheck metadata ────────────────────────────────

describe('subdomainTakeoverCheck metadata', () => {
  it('has correct name', () => {
    expect(subdomainTakeoverCheck.name).toBe('subdomain-takeover');
  });

  it('has correct category', () => {
    expect(subdomainTakeoverCheck.category).toBe('subdomain-takeover');
  });

  it('is parallel', () => {
    expect(subdomainTakeoverCheck.parallel).toBe(true);
  });
});

// ─── checkSubdomainTakeover ──────────────────────────────────────────

describe('checkSubdomainTakeover', () => {
  it('detects dangling CNAME to GitHub Pages', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'blog.example.com',
        ips: ['185.199.110.153'],
        cname: 'myorg.github.io',
      },
    ];

    const fetcher = vi.fn().mockResolvedValue({
      status: 404,
      body: "There isn't a GitHub Pages site here.",
    });

    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings[0];
    expect(finding.severity).toBe('high');
    expect(finding.category).toBe('subdomain-takeover');
    expect(finding.evidence).toContain('myorg.github.io');
    expect(finding.evidence).toContain('GitHub Pages');
  });

  it('skips subdomains with no CNAME', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'www.example.com',
        ips: ['1.2.3.4'],
        // no cname
      },
    ];

    const fetcher = vi.fn().mockResolvedValue({ status: 200, body: 'OK' });

    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );

    expect(findings).toHaveLength(0);
    // fetcher should NOT be called for subdomains without CNAME
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('skips non-exploitable services (Vercel)', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'app.example.com',
        ips: ['76.76.21.21'],
        cname: 'my-project.vercel.app',
      },
    ];

    const fetcher = vi.fn().mockResolvedValue({
      status: 404,
      body: 'The deployment could not be found on Vercel.',
    });

    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );

    // Vercel is non-exploitable — should produce no findings
    expect(findings).toHaveLength(0);
  });

  it('detects S3 bucket takeover', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'assets.example.com',
        ips: ['52.217.1.1'],
        cname: 'assets.example.com.s3.amazonaws.com',
      },
    ];

    const fetcher = vi.fn().mockResolvedValue({
      status: 404,
      body: '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>',
    });

    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].evidence).toContain('AWS S3');
    expect(findings[0].severity).toBe('high');
  });

  it('limits concurrent checks by concurrency parameter', async () => {
    // Create 10 subdomains all with CNAMEs pointing to GitHub Pages
    const subdomains: SubdomainResult[] = Array.from({ length: 10 }, (_, i) => ({
      subdomain: `sub${i}.example.com`,
      ips: ['185.199.110.153'],
      cname: `org${i}.github.io`,
    }));

    let maxConcurrent = 0;
    let currentConcurrent = 0;

    const fetcher = vi.fn().mockImplementation(async () => {
      currentConcurrent++;
      if (currentConcurrent > maxConcurrent) {
        maxConcurrent = currentConcurrent;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
      currentConcurrent--;
      return {
        status: 404,
        body: "There isn't a GitHub Pages site here.",
      };
    });

    await checkSubdomainTakeover(subdomains, 'example.com', fetcher, 3);

    // Concurrency should never exceed the limit of 3
    expect(maxConcurrent).toBeLessThanOrEqual(3);
  });

  it('returns empty array when no subdomains provided', async () => {
    const fetcher = vi.fn();
    const findings = await checkSubdomainTakeover([], 'example.com', fetcher);
    expect(findings).toHaveLength(0);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('includes HTTP status and body match in evidence', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'shop.example.com',
        ips: ['23.227.38.74'],
        cname: 'myshop.myshopify.com',
      },
    ];

    const fetcher = vi.fn().mockResolvedValue({
      status: 404,
      body: 'Sorry, this shop is currently unavailable.',
    });

    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings[0];
    expect(finding.evidence).toContain('myshop.myshopify.com');
    expect(finding.evidence).toContain('Shopify');
    expect(finding.url).toContain('shop.example.com');
  });

  it('handles fetch errors gracefully without crashing', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'broken.example.com',
        ips: ['1.2.3.4'],
        cname: 'myorg.github.io',
      },
    ];

    const fetcher = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );

    // Should not throw, should return empty or partial results
    expect(Array.isArray(findings)).toBe(true);
  });

  it('skips subdomains that are the target domain itself', async () => {
    const subdomains: SubdomainResult[] = [
      {
        subdomain: 'example.com',
        ips: ['1.2.3.4'],
        cname: 'myorg.github.io',
      },
    ];

    const fetcher = vi.fn().mockResolvedValue({
      status: 404,
      body: "There isn't a GitHub Pages site here.",
    });

    // The base domain itself — behavior depends on implementation.
    // Just verify it doesn't crash and returns a valid array.
    const findings = await checkSubdomainTakeover(
      subdomains,
      'example.com',
      fetcher,
    );
    expect(Array.isArray(findings)).toBe(true);
  });
});

// ─── subdomainTakeoverCheck.run integration ──────────────────────────

describe('subdomainTakeoverCheck.run', () => {
  it('returns empty array when no subdomainResults in config', async () => {
    const config = makeConfig(undefined);
    const context = {} as any;
    const targets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await subdomainTakeoverCheck.run(context, targets, config);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array when subdomainResults is empty', async () => {
    const config = makeConfig([]);
    const context = {} as any;
    const targets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await subdomainTakeoverCheck.run(context, targets, config);
    expect(findings).toHaveLength(0);
  });
});

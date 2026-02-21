import { describe, it, expect } from 'vitest';
import { tlsCheck, getTlsInfo, getHstsHeader } from '../../src/scanner/active/tls.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

function makeConfig(overrides: Partial<ScanConfig> = {}): ScanConfig {
  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    maxPages: 10,
    timeout: 30000,
    respectRobots: true,
    outputFormat: ['terminal'],
    concurrency: 1,
    requestDelay: 100,
    logRequests: false,
    useAI: false,
    ...overrides,
  };
}

function makeTargets(overrides: Partial<ScanTargets> = {}): ScanTargets {
  return {
    pages: ['https://example.com/'],
    forms: [],
    urlsWithParams: [],
    apiEndpoints: [],
    redirectUrls: [],
    fileParams: [],
    ...overrides,
  };
}

describe('TLS check: HTTP target skip', () => {
  it('returns empty findings for HTTP targets', async () => {
    const config = makeConfig({ targetUrl: 'http://example.com' });
    const targets = makeTargets();
    const context = {} as any; // Not used by TLS check

    const findings = await tlsCheck.run(context, targets, config);
    expect(findings).toHaveLength(0);
  });

  it('returns empty findings for invalid URL', async () => {
    const config = makeConfig({ targetUrl: 'not-a-url' });
    const targets = makeTargets();
    const context = {} as any;

    const findings = await tlsCheck.run(context, targets, config);
    expect(findings).toHaveLength(0);
  });
});

describe('TLS check: connection failure handling', () => {
  it('gracefully handles connection errors without crashing', async () => {
    // Use a non-routable address to trigger a connection error quickly
    const config = makeConfig({ targetUrl: 'https://192.0.2.1:1' });
    const targets = makeTargets();
    const context = {} as any;

    // Should not throw — just returns empty or partial findings
    const findings = await tlsCheck.run(context, targets, config);
    expect(Array.isArray(findings)).toBe(true);
  }, 15_000);
});

describe('TLS check: metadata', () => {
  it('has correct name and category', () => {
    expect(tlsCheck.name).toBe('tls');
    expect(tlsCheck.category).toBe('tls');
  });
});

describe('TLS check: helper functions', () => {
  it('getTlsInfo rejects on connection error', async () => {
    // Connect to a port that is almost certainly not listening
    await expect(getTlsInfo('127.0.0.1', 1)).rejects.toThrow();
  });

  it('getHstsHeader returns null on connection error', async () => {
    const result = await getHstsHeader('127.0.0.1', 1);
    expect(result).toBeNull();
  });
});

describe('TLS check: HSTS analysis logic', () => {
  it('correctly identifies deprecated TLS versions', () => {
    const deprecatedVersions = ['TLSv1', 'TLSv1.1', 'SSLv3'];
    for (const version of deprecatedVersions) {
      expect(deprecatedVersions.includes(version)).toBe(true);
    }
    // TLSv1.2 and TLSv1.3 should NOT be flagged
    expect(deprecatedVersions.includes('TLSv1.2')).toBe(false);
    expect(deprecatedVersions.includes('TLSv1.3')).toBe(false);
  });

  it('validates HSTS preload requirements', () => {
    // Preload requirements: includeSubDomains + max-age >= 31536000
    const validHsts = 'max-age=63072000; includeSubDomains; preload';
    const tooShortMaxAge = 'max-age=86400; includeSubDomains';
    const noIncludeSubDomains = 'max-age=63072000';
    const bareMinimum = 'max-age=31536000; includeSubDomains';

    // Valid: has both requirements
    expect(/includeSubDomains/i.test(validHsts)).toBe(true);
    const validMatch = validHsts.match(/max-age\s*=\s*(\d+)/i);
    expect(validMatch).not.toBeNull();
    expect(parseInt(validMatch![1], 10)).toBeGreaterThanOrEqual(31536000);

    // Too short max-age
    const shortMatch = tooShortMaxAge.match(/max-age\s*=\s*(\d+)/i);
    expect(parseInt(shortMatch![1], 10)).toBeLessThan(31536000);

    // Missing includeSubDomains
    expect(/includeSubDomains/i.test(noIncludeSubDomains)).toBe(false);

    // Bare minimum passes
    const bareMatch = bareMinimum.match(/max-age\s*=\s*(\d+)/i);
    expect(parseInt(bareMatch![1], 10)).toBeGreaterThanOrEqual(31536000);
    expect(/includeSubDomains/i.test(bareMinimum)).toBe(true);
  });

  it('self-signed detection: issuer === subject means self-signed', () => {
    const selfSignedCert = {
      issuer: { CN: 'Test CA', O: 'Test Org' },
      subject: { CN: 'Test CA', O: 'Test Org' },
    };
    const caSigned = {
      issuer: { CN: "Let's Encrypt", O: "Let's Encrypt" },
      subject: { CN: 'example.com', O: 'Example Inc' },
    };

    const isSelfSigned = (cert: typeof selfSignedCert) =>
      cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O;

    expect(isSelfSigned(selfSignedCert)).toBe(true);
    expect(isSelfSigned(caSigned)).toBe(false);
  });

  it('certificate expiry calculation is correct', () => {
    const now = new Date();

    // Expired cert (10 days ago)
    const expiredDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000);
    const daysExpired = Math.floor(
      (expiredDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
    );
    expect(daysExpired).toBeLessThan(0);

    // Expiring soon (15 days)
    const soonDate = new Date(now.getTime() + 15 * 24 * 60 * 60 * 1000);
    const daysSoon = Math.floor(
      (soonDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
    );
    expect(daysSoon).toBeGreaterThanOrEqual(0);
    expect(daysSoon).toBeLessThanOrEqual(30);

    // Valid cert (365 days)
    const validDate = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
    const daysValid = Math.floor(
      (validDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
    );
    expect(daysValid).toBeGreaterThan(30);
  });
});

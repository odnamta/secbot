import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { redirectCheck } from '../../src/scanner/active/redirect.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('Redirect Integration Tests', () => {
  let browser: Browser;
  let context: BrowserContext;
  let baseUrl: string;

  const defaultConfig: ScanConfig = {
    targetUrl: '',
    profile: 'standard',
    maxPages: 10,
    timeout: 15000,
    respectRobots: false,
    outputFormat: ['terminal'],
    concurrency: 1,
    requestDelay: 50,
    logRequests: false,
    useAI: false,
  };

  beforeAll(async () => {
    baseUrl = await startTestServer();
    defaultConfig.targetUrl = baseUrl;
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext();
  }, 30000);

  afterAll(async () => {
    await context?.close();
    await browser?.close();
    await stopTestServer();
  });

  it('detects open redirect via "url" parameter on /redirect', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/redirect?url=https://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/redirect?url=https://example.com`],
      apiEndpoints: [],
      redirectUrls: [`${baseUrl}/redirect?url=https://example.com`],
      fileParams: [],
    };

    const findings = await redirectCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const redirectFinding = findings.find(
      (f) => f.category === 'open-redirect' && f.title.includes('"url"'),
    );
    expect(redirectFinding).toBeDefined();
    expect(redirectFinding!.severity).toBe('medium');
    expect(redirectFinding!.evidence).toContain('evil.example.com');
  }, 60000);

  it('detects open redirect via "to" parameter on /redirect-to (Juice Shop pattern)', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/redirect-to?to=https://github.com/juice-shop/juice-shop`],
      forms: [],
      urlsWithParams: [`${baseUrl}/redirect-to?to=https://github.com/juice-shop/juice-shop`],
      apiEndpoints: [],
      redirectUrls: [`${baseUrl}/redirect-to?to=https://github.com/juice-shop/juice-shop`],
      fileParams: [],
    };

    const findings = await redirectCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const redirectFinding = findings.find(
      (f) => f.category === 'open-redirect' && f.title.includes('"to"'),
    );
    expect(redirectFinding).toBeDefined();
    expect(redirectFinding!.severity).toBe('medium');
    expect(redirectFinding!.evidence).toContain('evil.example.com');
  }, 60000);

  it('detects existing external URL in parameter value as open redirect candidate', async () => {
    // This simulates a crawled URL that already has an external domain in a redirect param
    // The check should notice the value is external and test with our canary
    const targets: ScanTargets = {
      pages: [`${baseUrl}/redirect?url=https://some-external-site.com/page`],
      forms: [],
      urlsWithParams: [`${baseUrl}/redirect?url=https://some-external-site.com/page`],
      apiEndpoints: [],
      redirectUrls: [`${baseUrl}/redirect?url=https://some-external-site.com/page`],
      fileParams: [],
    };

    const findings = await redirectCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings[0];
    expect(finding.category).toBe('open-redirect');
    expect(finding.evidence).toContain('evil.example.com');
  }, 60000);

  it('does NOT produce redirect findings for safe-redirect with domain whitelist', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe-redirect?to=https://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/safe-redirect?to=https://example.com`],
      apiEndpoints: [],
      redirectUrls: [`${baseUrl}/safe-redirect?to=https://example.com`],
      fileParams: [],
    };

    const findings = await redirectCheck.run(context, targets, defaultConfig);

    const redirectFindings = findings.filter((f) => f.category === 'open-redirect');
    expect(redirectFindings).toEqual([]);
  }, 60000);

  it('does NOT produce redirect findings when no redirect params exist', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await redirectCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/redirect?url=https://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/redirect?url=https://example.com`],
      apiEndpoints: [],
      redirectUrls: [`${baseUrl}/redirect?url=https://example.com`],
      fileParams: [],
    };

    const findings = await redirectCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('open-redirect');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
    expect(finding.request).toBeDefined();
    expect(finding.request!.method).toBe('GET');
  }, 60000);
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { ssrfCheck } from '../../src/scanner/active/ssrf.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('SSRF Integration Tests', () => {
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

  it('detects SSRF on /fetch?url= endpoint', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/fetch?url=http://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/fetch?url=http://example.com`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await ssrfCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const ssrfFinding = findings.find((f) => f.category === 'ssrf');
    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding!.category).toBe('ssrf');
    expect(['critical', 'high']).toContain(ssrfFinding!.severity);
    expect(ssrfFinding!.title).toContain('SSRF');
    expect(ssrfFinding!.url).toContain('/fetch');
  }, 60000);

  it('does NOT flag URLs without SSRF-relevant parameters', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/search?q=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/search?q=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await ssrfCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/fetch?url=http://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/fetch?url=http://example.com`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await ssrfCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('ssrf');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
    expect(finding.request).toBeDefined();
    expect(finding.response).toBeDefined();
  }, 60000);
});

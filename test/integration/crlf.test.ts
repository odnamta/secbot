import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { crlfCheck } from '../../src/scanner/active/crlf.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('CRLF Injection Integration Tests', () => {
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

  it('detects CRLF injection on /api/crlf-redirect?url= endpoint', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/crlf-redirect?url=https://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/crlf-redirect?url=https://example.com`],
      apiEndpoints: [`${baseUrl}/api/crlf-redirect`],
      redirectUrls: [`${baseUrl}/api/crlf-redirect?url=https://example.com`],
      fileParams: [],
    };

    const findings = await crlfCheck.run(context, targets, defaultConfig);

    // Should detect at least one CRLF injection finding
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const crlfFinding = findings.find((f) => f.category === 'crlf-injection');
    expect(crlfFinding).toBeDefined();
    expect(crlfFinding!.severity).toBe('high');
    // Title contains either "CRLF" or "Header Injection" or "Response Splitting"
    expect(
      crlfFinding!.title.includes('Injection') || crlfFinding!.title.includes('Splitting'),
    ).toBe(true);
    expect(crlfFinding!.url).toContain('/api/crlf-redirect');
  }, 60000);

  it('detects CRLF injection on /api/crlf-header?name= endpoint', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/crlf-header?name=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/crlf-header?name=test`],
      apiEndpoints: [`${baseUrl}/api/crlf-header`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await crlfCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const crlfFinding = findings.find((f) => f.category === 'crlf-injection');
    expect(crlfFinding).toBeDefined();
    expect(crlfFinding!.severity).toBe('high');
    expect(
      crlfFinding!.title.includes('Injection') || crlfFinding!.title.includes('Splitting'),
    ).toBe(true);
  }, 60000);

  it('does NOT flag the safe CRLF endpoint', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/crlf-safe?url=https://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/crlf-safe?url=https://example.com`],
      apiEndpoints: [`${baseUrl}/api/crlf-safe`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await crlfCheck.run(context, targets, defaultConfig);

    const crlfFindings = findings.filter((f) => f.category === 'crlf-injection');
    expect(crlfFindings.length).toBe(0);
  }, 30000);

  it('does NOT flag /safe page with CRLF issues', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await crlfCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/crlf-redirect?url=https://example.com`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/crlf-redirect?url=https://example.com`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await crlfCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('crlf-injection');
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

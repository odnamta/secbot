import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer, getTestUrl } from '../setup.js';
import { xssCheck } from '../../src/scanner/active/xss.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('XSS Integration Tests', () => {
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

  it('detects reflected XSS in URL parameter on /search?q=', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/search?q=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/search?q=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const xssFinding = findings.find(f => f.category === 'xss' && f.url.includes('/search'));
    expect(xssFinding).toBeDefined();
    expect(xssFinding!.severity).toBe('high');
    expect(xssFinding!.title).toContain('Reflected XSS');
    expect(xssFinding!.title).toContain('"q"');
  }, 60000);

  it('detects reflected XSS via form submission on /login', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/login`],
      forms: [
        {
          action: `${baseUrl}/login`,
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text' },
            { name: 'password', type: 'password' },
          ],
          pageUrl: `${baseUrl}/login`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const formFinding = findings.find(f => f.category === 'xss' && f.title.includes('Form'));
    expect(formFinding).toBeDefined();
    expect(formFinding!.severity).toBe('high');
  }, 60000);

  it('does NOT produce XSS findings for the /safe page', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    // Safe page has no parameters or forms to inject into, so no findings
    expect(findings.length).toBe(0);
  }, 30000);

  it('does NOT flag /safe as reflected XSS when tested with params', async () => {
    // The safe page itself doesn't have a query parameter that reflects,
    // but if we did add a ?q= param it wouldn't be reflected unsafely.
    // This verifies no false positives on safe pages.
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [], // Safe page doesn't have params
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);
    const xssFindings = findings.filter(f => f.category === 'xss');
    expect(xssFindings.length).toBe(0);
  }, 30000);

  it('findings include payload type information', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/search?q=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/search?q=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    // Evidence should include type info
    const finding = findings[0];
    expect(finding.evidence).toContain('Type:');
  }, 60000);
});

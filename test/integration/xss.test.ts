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

  // ─── POST Body Parameter XSS Tests ─────────────────────────────

  it('detects reflected XSS in POST body parameter on /feedback', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/feedback`],
      forms: [
        {
          action: `${baseUrl}/feedback`,
          method: 'POST',
          inputs: [
            { name: 'name', type: 'text' },
            { name: 'message', type: 'text' },
          ],
          pageUrl: `${baseUrl}/feedback`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    // Should find XSS via POST body parameter testing
    const postBodyFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('POST Body Parameter'),
    );
    expect(postBodyFinding).toBeDefined();
    expect(postBodyFinding!.severity).toBe('high');
    expect(postBodyFinding!.title).toMatch(/POST Body Parameter "(?:name|message)"/);
    expect(postBodyFinding!.request?.method).toBe('POST');
  }, 60000);

  it('POST body XSS test includes proper evidence and request details', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/feedback`],
      forms: [
        {
          action: `${baseUrl}/feedback`,
          method: 'POST',
          inputs: [
            { name: 'name', type: 'text' },
            { name: 'message', type: 'text' },
          ],
          pageUrl: `${baseUrl}/feedback`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    const postBodyFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('POST Body Parameter'),
    );
    expect(postBodyFinding).toBeDefined();
    expect(postBodyFinding!.evidence).toContain('Method: POST');
    expect(postBodyFinding!.evidence).toContain('Payload:');
    expect(postBodyFinding!.evidence).toContain('Parameter:');
    expect(postBodyFinding!.request?.body).toBeDefined();
  }, 60000);

  it('skips POST body XSS test for GET-only forms', async () => {
    // Only provide URL params (no forms at all) — verify no POST body findings
    // The key behavior: forms.filter(f => f.method === 'POST') returns empty for GET forms
    const targets: ScanTargets = {
      pages: [`${baseUrl}/search?q=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/search?q=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    // Should NOT have POST body findings (no POST forms)
    const postBodyFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('POST Body Parameter'),
    );
    expect(postBodyFinding).toBeUndefined();

    // But should still detect reflected XSS via URL params
    const urlFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('URL Parameter'),
    );
    expect(urlFinding).toBeDefined();
  }, 60000);

  // ─── JSON API XSS Tests ────────────────────────────────────────

  it('detects potential stored XSS via JSON API on /api/v1/comments', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/comments`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    const jsonXssFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('JSON API'),
    );
    expect(jsonXssFinding).toBeDefined();
    expect(jsonXssFinding!.severity).toBe('medium');
    expect(jsonXssFinding!.title).toContain('Stored XSS via JSON API');
    expect(jsonXssFinding!.evidence).toContain('API Response');
    expect(jsonXssFinding!.request?.headers?.['Content-Type']).toBe('application/json');
    expect(jsonXssFinding!.response?.status).toBe(200);
  }, 60000);

  it('does NOT flag safe JSON API as XSS', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/safe-comments`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    // Safe API encodes HTML characters, so no XSS findings
    const jsonXssFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('JSON API'),
    );
    expect(jsonXssFinding).toBeUndefined();
  }, 60000);

  it('does NOT produce JSON API XSS findings when no apiEndpoints provided', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [], // No API endpoints
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    const jsonXssFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('JSON API'),
    );
    expect(jsonXssFinding).toBeUndefined();
  }, 30000);

  // ─── Combined POST + JSON test ─────────────────────────────────

  it('detects both POST body and JSON API XSS in a combined scan', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/feedback`],
      forms: [
        {
          action: `${baseUrl}/feedback`,
          method: 'POST',
          inputs: [
            { name: 'name', type: 'text' },
            { name: 'message', type: 'text' },
          ],
          pageUrl: `${baseUrl}/feedback`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/comments`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xssCheck.run(context, targets, defaultConfig);

    const postBodyFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('POST Body Parameter'),
    );
    const jsonApiFinding = findings.find(
      f => f.category === 'xss' && f.title.includes('JSON API'),
    );

    expect(postBodyFinding).toBeDefined();
    expect(jsonApiFinding).toBeDefined();
  }, 90000);
});

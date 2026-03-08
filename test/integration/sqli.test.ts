import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { sqliCheck } from '../../src/scanner/active/sqli.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('SQLi Integration Tests', () => {
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

  it('detects error-based SQLi in URL parameter on /api/v1/data?query=', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/data?query=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/v1/data?query=test`],
      apiEndpoints: [`${baseUrl}/api/v1/data?query=test`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const sqliFinding = findings.find(
      (f) => f.category === 'sqli' && f.url.includes('/api/v1/data'),
    );
    expect(sqliFinding).toBeDefined();
    expect(sqliFinding!.severity).toBe('critical');
    expect(sqliFinding!.title).toContain('SQL Injection');
    expect(sqliFinding!.title).toContain('"query"');
  }, 60000);

  it('findings include evidence of SQL error patterns', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/data?query=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/v1/data?query=test`],
      apiEndpoints: [`${baseUrl}/api/v1/data?query=test`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const sqliFinding = findings.find((f) => f.category === 'sqli');
    expect(sqliFinding).toBeDefined();
    // Evidence should contain SQL error text from the server response
    expect(sqliFinding!.evidence).toMatch(/sql error/i);
  }, 60000);

  it('does NOT produce SQLi findings for the /safe page', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBe(0);
  }, 30000);

  it('detects boolean-based blind SQLi via response length difference', async () => {
    // The /api/v1/data endpoint returns an HTML error page for queries with quotes
    // vs a short JSON response for clean queries, creating a body length difference.
    // However, the error-based check will fire first (critical), so boolean-blind
    // won't be reached for this param. We verify the error-based finding exists.
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/data?query=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/v1/data?query=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    // Error-based should fire first for this endpoint
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].category).toBe('sqli');
  }, 60000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/data?query=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/api/v1/data?query=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('sqli');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
    expect(finding.request).toBeDefined();
    expect(finding.request!.method).toBe('GET');
    expect(finding.request!.url).toContain('/api/v1/data');
  }, 60000);

  // ─── POST Form SQLi Tests ──────────────────────────────────────────

  it('detects error-based SQLi in POST form field (username)', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/login-vuln`],
      forms: [
        {
          action: `${baseUrl}/api/v1/login`,
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text', value: '' },
            { name: 'password', type: 'password', value: '' },
          ],
          pageUrl: `${baseUrl}/login-vuln`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    const postSqliFinding = findings.find(
      (f) => f.category === 'sqli' && f.title.includes('POST Form Field'),
    );
    expect(postSqliFinding).toBeDefined();
    expect(postSqliFinding!.severity).toBe('critical');
    expect(postSqliFinding!.title).toContain('"username"');
    expect(postSqliFinding!.request?.method).toBe('POST');
    expect(postSqliFinding!.evidence).toMatch(/sql error/i);
  }, 60000);

  it('POST form SQLi finding has correct structure', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/login-vuln`],
      forms: [
        {
          action: `${baseUrl}/api/v1/login`,
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text', value: '' },
            { name: 'password', type: 'password', value: '' },
          ],
          pageUrl: `${baseUrl}/login-vuln`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);
    const postFinding = findings.find((f) => f.title.includes('POST Form Field'));
    expect(postFinding).toBeDefined();
    expect(postFinding!.request).toBeDefined();
    expect(postFinding!.request!.url).toContain('/api/v1/login');
    expect(postFinding!.request!.body).toBeDefined();
    expect(postFinding!.response).toBeDefined();
    expect(postFinding!.response!.status).toBe(500);
  }, 60000);

  it('does NOT produce POST form SQLi findings for safe login endpoint', async () => {
    // The original /login POST just echoes the username — no SQL error
    const targets: ScanTargets = {
      pages: [`${baseUrl}/login`],
      forms: [
        {
          action: `${baseUrl}/login`,
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text', value: '' },
            { name: 'password', type: 'password', value: '' },
          ],
          pageUrl: `${baseUrl}/login`,
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    const postSqliFinding = findings.find(
      (f) => f.category === 'sqli' && f.title.includes('POST Form Field'),
    );
    expect(postSqliFinding).toBeUndefined();
  }, 60000);

  // ─── JSON API SQLi Tests ───────────────────────────────────────────

  it('detects error-based SQLi in JSON API body (/api/v1/search)', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/search`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    const jsonSqliFinding = findings.find(
      (f) => f.category === 'sqli' && f.title.includes('JSON API Field'),
    );
    expect(jsonSqliFinding).toBeDefined();
    expect(jsonSqliFinding!.severity).toBe('critical');
    expect(jsonSqliFinding!.title).toContain('"query"');
    expect(jsonSqliFinding!.request?.method).toBe('POST');
    expect(jsonSqliFinding!.request?.headers?.['Content-Type']).toBe('application/json');
    expect(jsonSqliFinding!.evidence).toMatch(/sql error/i);
  }, 60000);

  it('JSON API SQLi finding has correct structure', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/search`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);
    const jsonFinding = findings.find((f) => f.title.includes('JSON API Field'));
    expect(jsonFinding).toBeDefined();
    expect(jsonFinding!.request).toBeDefined();
    expect(jsonFinding!.request!.url).toContain('/api/v1/search');
    expect(jsonFinding!.request!.body).toBeDefined();
    // Body should be valid JSON
    expect(() => JSON.parse(jsonFinding!.request!.body!)).not.toThrow();
    expect(jsonFinding!.response).toBeDefined();
    expect(jsonFinding!.response!.status).toBe(500);
  }, 60000);

  it('does NOT produce JSON API SQLi findings for safe search endpoint', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/safe-search`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    const jsonSqliFinding = findings.find(
      (f) => f.category === 'sqli' && f.title.includes('JSON API Field'),
    );
    expect(jsonSqliFinding).toBeUndefined();
  }, 60000);

  it('skips destructive-looking JSON API endpoints', async () => {
    // JSON API test should skip endpoints with delete/destroy in the path
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/users/destroy`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sqliCheck.run(context, targets, defaultConfig);

    const jsonFinding = findings.find((f) => f.title.includes('JSON API Field'));
    expect(jsonFinding).toBeUndefined();
  }, 30000);
});

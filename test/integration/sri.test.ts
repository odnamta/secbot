import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { sriCheck } from '../../src/scanner/active/sri.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('SRI Integration Tests', () => {
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

  it('detects missing SRI on external script and stylesheet tags', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sriCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const sriFinding = findings.find((f) => f.category === 'sri');
    expect(sriFinding).toBeDefined();
    expect(sriFinding!.severity).toBe('medium');
    expect(sriFinding!.title).toContain('Subresource Integrity');
    expect(sriFinding!.evidence).toContain('cdn.example.com');
  }, 60000);

  it('does NOT flag same-origin resources', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sriCheck.run(context, targets, defaultConfig);

    // /safe page has no external scripts/stylesheets, so no SRI findings
    const sriFindings = findings.filter((f) => f.category === 'sri');
    expect(sriFindings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sriCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('sri');
    expect(finding.severity).toBe('medium');
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBe(`${baseUrl}/`);
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
  }, 60000);

  it('groups findings by page (one finding per page)', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sriCheck.run(context, targets, defaultConfig);

    // Homepage has both external script and stylesheet without SRI
    // but they should be grouped into a single finding per page
    const homepageFindings = findings.filter((f) => f.url === `${baseUrl}/`);
    expect(homepageFindings.length).toBe(1);

    // The single finding should mention both resources
    expect(homepageFindings[0].evidence).toContain('lib.js');
    expect(homepageFindings[0].evidence).toContain('style.css');
  }, 60000);
});

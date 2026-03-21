import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { bflaCheck } from '../../src/scanner/active/bfla.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('BFLA Integration Tests', () => {
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

  it('detects broken function-level authorization on /api/v1/admin/users', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/admin/users`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await bflaCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const bflaFinding = findings.find((f) => f.category === 'broken-access-control');
    expect(bflaFinding).toBeDefined();
    expect(bflaFinding!.url).toContain('/api/v1/admin');
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/admin/users`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await bflaCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('broken-access-control');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
  }, 30000);
});

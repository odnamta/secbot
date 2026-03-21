import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { clickjackingCheck } from '../../src/scanner/active/clickjacking.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('Clickjacking Integration Tests', () => {
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

  it('detects clickjacking on /clickjack-me endpoint (no X-Frame-Options)', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/clickjack-me`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await clickjackingCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const clickjackFinding = findings.find((f) => f.category === 'clickjacking');
    expect(clickjackFinding).toBeDefined();
    expect(clickjackFinding!.title).toContain('Clickjacking');
    expect(clickjackFinding!.url).toContain('/clickjack-me');
  }, 30000);

  it('does NOT flag /safe page for clickjacking (has X-Frame-Options: DENY)', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await clickjackingCheck.run(context, targets, defaultConfig);

    const clickjackFindings = findings.filter((f) => f.category === 'clickjacking');
    expect(clickjackFindings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/clickjack-me`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await clickjackingCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('clickjacking');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
  }, 30000);
});

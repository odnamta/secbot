import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { rateLimitCheck } from '../../src/scanner/active/rate-limit.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('Rate Limit Integration Tests', () => {
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

  it('detects missing rate limiting on /login endpoint', async () => {
    // Use the /login page (which has a GET handler returning 200) as the auth endpoint.
    // The rate-limit check sends 15 rapid GET requests and checks for rate-limit headers.
    // The fixture server has no rate limiting, so all 15 return 200 without throttling.
    const targets: ScanTargets = {
      pages: [`${baseUrl}/login`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await rateLimitCheck.run(context, targets, defaultConfig);

    // The fixture has no rate limiting, so at least one finding is expected
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const rateFinding = findings.find((f) => f.category === 'rate-limit');
    expect(rateFinding).toBeDefined();
    expect(rateFinding!.title).toContain('Rate Limiting');
    expect(rateFinding!.url).toContain('/login');
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/login`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await rateLimitCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('rate-limit');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
  }, 30000);
});

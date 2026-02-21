import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { corsCheck } from '../../src/scanner/active/cors.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('CORS Integration Tests', () => {
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

  it('detects CORS wildcard with credentials on /cors-api', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/cors-api`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/cors-api`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await corsCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const corsFinding = findings.find(
      (f) => f.category === 'cors-misconfiguration' && f.title.includes('Wildcard with Credentials'),
    );
    expect(corsFinding).toBeDefined();
    expect(corsFinding!.severity).toBe('high');
    expect(corsFinding!.evidence).toContain('Access-Control-Allow-Origin: *');
    expect(corsFinding!.evidence).toContain('Access-Control-Allow-Credentials: true');
  }, 60000);

  it('does NOT flag /safe page with CORS issues', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await corsCheck.run(context, targets, defaultConfig);

    const corsFindings = findings.filter((f) => f.category === 'cors-misconfiguration');
    expect(corsFindings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/cors-api`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/cors-api`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await corsCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('cors-misconfiguration');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
    expect(finding.response).toBeDefined();
  }, 60000);
});

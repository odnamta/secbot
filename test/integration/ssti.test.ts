import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { sstiCheck } from '../../src/scanner/active/ssti.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('SSTI Integration Tests', () => {
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

  it('detects SSTI on /template?name= endpoint', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/template?name=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/template?name=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sstiCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const sstiFinding = findings.find((f) => f.category === 'ssti');
    expect(sstiFinding).toBeDefined();
    expect(sstiFinding!.category).toBe('ssti');
    expect(sstiFinding!.severity).toBe('critical');
    expect(sstiFinding!.title).toContain('Template Injection');
    expect(sstiFinding!.url).toContain('/template');
  }, 60000);

  it('does NOT flag URLs where template expressions are not evaluated', async () => {
    // /search reflects input literally without evaluating template syntax
    const targets: ScanTargets = {
      pages: [`${baseUrl}/search?q=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/search?q=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sstiCheck.run(context, targets, defaultConfig);

    // Should have zero SSTI findings because /search doesn't evaluate templates
    const sstiFindings = findings.filter((f) => f.category === 'ssti');
    expect(sstiFindings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/template?name=test`],
      forms: [],
      urlsWithParams: [`${baseUrl}/template?name=test`],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await sstiCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('ssti');
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

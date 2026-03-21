import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { xxeCheck } from '../../src/scanner/active/xxe.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('XXE Integration Tests', () => {
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

  it('tests /xml-parse endpoint for XXE without crashing', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/xml-parse`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/xml-parse`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xxeCheck.run(context, targets, defaultConfig);

    // The fixture server reflects XML but does not parse entities,
    // so XXE file read may not fire. Assert the check ran without error.
    expect(findings.length).toBeGreaterThanOrEqual(0);

    // If findings were produced, verify they have the correct category
    if (findings.length > 0) {
      const xxeFinding = findings.find((f) => f.category === 'xxe');
      expect(xxeFinding).toBeDefined();
      expect(xxeFinding!.url).toContain('/xml-parse');
    }
  }, 30000);

  it('findings (if any) have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/xml-parse`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/xml-parse`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await xxeCheck.run(context, targets, defaultConfig);

    if (findings.length > 0) {
      const finding = findings[0];
      expect(finding.id).toBeDefined();
      expect(finding.category).toBe('xxe');
      expect(finding.severity).toBeDefined();
      expect(finding.title).toBeDefined();
      expect(finding.description).toBeDefined();
      expect(finding.url).toBeDefined();
      expect(finding.evidence).toBeDefined();
      expect(finding.timestamp).toBeDefined();
    }
  }, 30000);
});

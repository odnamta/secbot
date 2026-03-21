import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { verboseErrorsCheck } from '../../src/scanner/active/verbose-errors.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('Verbose Errors Integration Tests', () => {
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

  it('detects verbose errors / stack trace on /error-debug endpoint', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/error-debug?id=invalid`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/error-debug`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await verboseErrorsCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const errorFinding = findings.find((f) => f.category === 'info-disclosure');
    expect(errorFinding).toBeDefined();
    expect(
      errorFinding!.title.includes('Stack Trace') ||
      errorFinding!.title.includes('Verbose') ||
      errorFinding!.title.includes('Error') ||
      errorFinding!.title.includes('Node.js'),
    ).toBe(true);
  }, 30000);

  it('does NOT flag /safe page with verbose errors', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await verboseErrorsCheck.run(context, targets, defaultConfig);

    // The verbose-errors check triggers errors on base URL paths, so it may find
    // the Express "Cannot GET" debug page. Filter to only stack trace findings.
    const stackTraceFindings = findings.filter(
      (f) => f.category === 'info-disclosure' && f.title.includes('Stack Trace'),
    );
    // /safe itself should not produce stack traces
    expect(stackTraceFindings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/error-debug?id=invalid`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/error-debug`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await verboseErrorsCheck.run(context, targets, defaultConfig);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('info-disclosure');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
  }, 30000);
});

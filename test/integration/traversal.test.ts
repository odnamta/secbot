import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { traversalCheck } from '../../src/scanner/active/traversal.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('Traversal Integration Tests', () => {
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

  it('detects directory traversal via "path" parameter on /files', async () => {
    const fileUrl = `${baseUrl}/files?path=etc/passwd`;
    const targets: ScanTargets = {
      pages: [fileUrl],
      forms: [],
      urlsWithParams: [fileUrl],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [fileUrl],
    };

    const findings = await traversalCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const traversalFinding = findings.find(
      (f) => f.category === 'directory-traversal',
    );
    expect(traversalFinding).toBeDefined();
    expect(traversalFinding!.severity).toBe('critical');
    expect(traversalFinding!.evidence).toContain('Payload:');
    expect(traversalFinding!.response?.bodySnippet).toContain('root:');
  }, 60000);

  it('does NOT produce traversal findings when no targets exist', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await traversalCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBe(0);
  }, 30000);

  it('works with fileParams targets (not just apiEndpoints)', async () => {
    // /files is NOT an API endpoint (/api/ path), but has a file-like parameter
    const fileUrl = `${baseUrl}/files?path=readme.txt`;
    const targets: ScanTargets = {
      pages: [fileUrl],
      forms: [],
      urlsWithParams: [fileUrl],
      apiEndpoints: [], // intentionally empty — testing fileParams path
      redirectUrls: [],
      fileParams: [fileUrl],
    };

    const findings = await traversalCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].category).toBe('directory-traversal');
  }, 60000);

  it('findings have required RawFinding fields', async () => {
    const fileUrl = `${baseUrl}/files?path=etc/passwd`;
    const targets: ScanTargets = {
      pages: [fileUrl],
      forms: [],
      urlsWithParams: [fileUrl],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [fileUrl],
    };

    const findings = await traversalCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('directory-traversal');
    expect(finding.severity).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
    expect(finding.request).toBeDefined();
    expect(finding.request!.method).toBe('GET');
    expect(finding.response).toBeDefined();
    expect(finding.response!.bodySnippet).toBeDefined();
  }, 60000);
});

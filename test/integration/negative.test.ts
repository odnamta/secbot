import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { sqliCheck } from '../../src/scanner/active/sqli.js';
import { corsCheck } from '../../src/scanner/active/cors.js';
import { redirectCheck } from '../../src/scanner/active/redirect.js';
import { ssrfCheck } from '../../src/scanner/active/ssrf.js';
import { sstiCheck } from '../../src/scanner/active/ssti.js';
import { traversalCheck } from '../../src/scanner/active/traversal.js';
import { cmdiCheck } from '../../src/scanner/active/cmdi.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

/**
 * Negative tests: verify the scanner does NOT produce findings on safe endpoints.
 * This catches false positives — the scanner should stay quiet on properly secured pages.
 */
describe('Negative Tests — Safe Endpoints Produce 0 Findings', () => {
  let browser: Browser;
  let context: BrowserContext;
  let baseUrl: string;

  const config: ScanConfig = {
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
    config.targetUrl = baseUrl;
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext();
  }, 30000);

  afterAll(async () => {
    await context?.close();
    await browser?.close();
    await stopTestServer();
  });

  function safeTargets(): ScanTargets {
    return {
      pages: [`${baseUrl}/safe`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };
  }

  it('SQLi: no findings on /safe', async () => {
    const findings = await sqliCheck.run(context, safeTargets(), config);
    expect(findings.length).toBe(0);
  }, 30000);

  it('CORS: no findings on /safe (no CORS headers)', async () => {
    const targets = safeTargets();
    targets.pages = [`${baseUrl}/safe`];
    const findings = await corsCheck.run(context, targets, config);
    expect(findings.length).toBe(0);
  }, 30000);

  it('Open Redirect: no findings when no redirect params', async () => {
    const targets = safeTargets();
    targets.redirectUrls = [];
    const findings = await redirectCheck.run(context, targets, config);
    expect(findings.length).toBe(0);
  }, 30000);

  it('SSRF: no findings when no URL params', async () => {
    const targets = safeTargets();
    targets.urlsWithParams = [];
    const findings = await ssrfCheck.run(context, targets, config);
    expect(findings.length).toBe(0);
  }, 30000);

  it('SSTI: no findings on /safe', async () => {
    const targets = safeTargets();
    targets.urlsWithParams = [`${baseUrl}/safe`];
    const findings = await sstiCheck.run(context, targets, config);
    expect(findings.length).toBe(0);
  }, 30000);

  it('Directory Traversal: no findings when no file params', async () => {
    const targets = safeTargets();
    targets.fileParams = [];
    const findings = await traversalCheck.run(context, targets, config);
    expect(findings.length).toBe(0);
  }, 30000);

  it('Command Injection: no findings on /safe', async () => {
    const targets = safeTargets();
    targets.urlsWithParams = [];
    targets.forms = [];
    const findings = await cmdiCheck.run(context, targets, config);
    expect(findings.length).toBe(0);
  }, 30000);
});

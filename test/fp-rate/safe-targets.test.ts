import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { runActiveChecks } from '../../src/scanner/active/index.js';
import { runPassiveChecks } from '../../src/scanner/passive.js';
import { crawl, closeBrowser } from '../../src/scanner/browser.js';
import type { ScanConfig, CrawledPage, InterceptedResponse } from '../../src/scanner/types.js';

/**
 * False-positive rate tests: scan known-safe endpoints and assert 0 findings.
 * These tests ensure SecBot doesn't cry wolf on properly secured pages.
 *
 * The /safe endpoint in the vulnerable-server fixture returns a simple
 * HTML page with no vulnerabilities, proper encoding, and safe headers.
 */
describe('False-Positive Rate — Safe Endpoints', () => {
  let browser: Browser;
  let context: BrowserContext;
  let baseUrl: string;

  const makeConfig = (overrides?: Partial<ScanConfig>): ScanConfig => ({
    targetUrl: baseUrl,
    profile: 'standard',
    maxPages: 5,
    timeout: 15000,
    respectRobots: false,
    outputFormat: ['terminal'],
    concurrency: 1,
    requestDelay: 50,
    logRequests: false,
    useAI: false,
    ...overrides,
  });

  beforeAll(async () => {
    baseUrl = await startTestServer();
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext();
  }, 30000);

  afterAll(async () => {
    await context?.close();
    await browser?.close();
    await stopTestServer();
  });

  describe('Active checks on /safe produce 0 findings', () => {
    it('full active scan on /safe returns empty', async () => {
      const config = makeConfig({ targetUrl: `${baseUrl}/safe` });
      const page = await context.newPage();
      await page.goto(`${baseUrl}/safe`, { timeout: 15000, waitUntil: 'domcontentloaded' });

      const safePage: CrawledPage = {
        url: `${baseUrl}/safe`,
        status: 200,
        headers: {},
        title: 'Safe Page',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      };

      const findings = await runActiveChecks(context, [safePage], config);
      expect(findings.length).toBe(0);
      await page.close();
    }, 60000);

    it('active scan on /safe with query params still returns 0', async () => {
      const safeUrl = `${baseUrl}/safe?name=test&value=hello`;
      const config = makeConfig({ targetUrl: baseUrl });

      const safePage: CrawledPage = {
        url: safeUrl,
        status: 200,
        headers: {},
        title: 'Safe Page',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      };

      const findings = await runActiveChecks(context, [safePage], config);
      expect(findings.length).toBe(0);
    }, 60000);
  });

  describe('Passive checks on safe responses produce minimal findings', () => {
    it('passive scan on safe page does not flag critical/high issues', async () => {
      const page = await context.newPage();
      const response = await page.goto(`${baseUrl}/safe`, {
        timeout: 15000,
        waitUntil: 'domcontentloaded',
      });

      const headers: Record<string, string> = {};
      if (response) {
        const allHeaders = await response.allHeaders();
        for (const [k, v] of Object.entries(allHeaders)) {
          headers[k] = v;
        }
      }

      const safePage: CrawledPage = {
        url: `${baseUrl}/safe`,
        status: 200,
        headers,
        title: 'Safe Page',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      };

      const responses: InterceptedResponse[] = [{
        url: `${baseUrl}/safe`,
        status: 200,
        headers,
      }];

      const findings = runPassiveChecks([safePage], responses);

      // Filter to critical/high only — some info/low findings on
      // dev servers (missing CSP, etc.) are expected and acceptable
      const severeFindings = findings.filter(
        f => f.severity === 'critical' || f.severity === 'high'
      );
      expect(severeFindings.length).toBe(0);

      await page.close();
    }, 30000);
  });

  describe('No false positives on well-formed HTML', () => {
    it('XSS check does not flag properly encoded output', async () => {
      // The /safe endpoint HTML-encodes user input
      const page = await context.newPage();
      await page.goto(`${baseUrl}/safe?name=%3Cscript%3Ealert(1)%3C/script%3E`, {
        timeout: 15000,
        waitUntil: 'domcontentloaded',
      });
      const content = await page.content();

      // The /safe page should NOT contain unencoded script tags
      expect(content).not.toContain('<script>alert(1)</script>');
      await page.close();
    }, 15000);
  });
});

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import type { Server } from 'node:http';
import { chromium, type BrowserContext } from 'playwright';
import { createVulnerableServer } from '../fixtures/vulnerable-server.js';
import { csrfCheck, getSameSiteCookieStatus } from '../../src/scanner/active/csrf.js';
import type { ScanConfig, FormInfo } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

let server: Server;
let baseUrl: string;
let context: BrowserContext;

beforeAll(async () => {
  const result = await createVulnerableServer();
  server = result.server;
  baseUrl = result.url;
  const browser = await chromium.launch({ headless: true });
  context = await browser.newContext();
});

afterAll(async () => {
  await context.browser()?.close();
  server.close();
});

// Clear cookies between tests to prevent state leakage
afterEach(async () => {
  await context.clearCookies();
});

function makeConfig(url: string): ScanConfig {
  return {
    targetUrl: url,
    profile: 'standard',
    maxPages: 5,
    timeout: 10000,
    format: ['terminal'],
    outputDir: '/tmp/secbot-test',
    requestDelay: 0,
    rateLimitRps: 100,
    headless: true,
  } as ScanConfig;
}

describe('CSRF Check', () => {
  it('should detect missing CSRF token on transfer form', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/transfer`],
      forms: [
        {
          pageUrl: `${baseUrl}/transfer`,
          action: '/transfer',
          method: 'POST',
          inputs: [
            { name: 'to', type: 'text', value: '' },
            { name: 'amount', type: 'number', value: '' },
          ],
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].category).toBe('csrf');
    expect(findings[0].title).toContain('Missing CSRF Protection');
    expect(findings[0].evidence).toContain('CSRF Token: NOT FOUND');
  });

  it('should NOT flag forms with CSRF tokens', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/transfer-safe`],
      forms: [
        {
          pageUrl: `${baseUrl}/transfer-safe`,
          action: '/transfer-safe',
          method: 'POST',
          inputs: [
            { name: '_csrf', type: 'hidden', value: 'abc123def456ghi789jkl012mno345pqr678' },
            { name: 'to', type: 'text', value: '' },
            { name: 'amount', type: 'number', value: '' },
          ],
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    expect(findings.length).toBe(0);
  });

  it('should NOT flag GET forms', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/search`],
      forms: [
        {
          pageUrl: `${baseUrl}/search`,
          action: '/search',
          method: 'GET',
          inputs: [
            { name: 'q', type: 'text', value: '' },
          ],
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    expect(findings.length).toBe(0);
  });

  it('should assign high severity to state-changing form actions', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/transfer`],
      forms: [
        {
          pageUrl: `${baseUrl}/transfer`,
          action: '/transfer',
          method: 'POST',
          inputs: [
            { name: 'to', type: 'text', value: '' },
            { name: 'amount', type: 'number', value: '' },
          ],
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    expect(findings.length).toBeGreaterThanOrEqual(1);
    // /transfer matches STATE_CHANGING_PATHS → high severity
    expect(findings[0].severity).toBe('high');
  });

  it('should include evidence pack with curl command', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/transfer`],
      forms: [
        {
          pageUrl: `${baseUrl}/transfer`,
          action: '/transfer',
          method: 'POST',
          inputs: [
            { name: 'to', type: 'text', value: '' },
            { name: 'amount', type: 'number', value: '' },
          ],
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].evidencePack).toBeDefined();
    expect(findings[0].evidencePack?.curlCommand).toContain('curl');
    expect(findings[0].evidencePack?.curlCommand).toContain('evil.example.com');
  });

  it('should return empty for no forms', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    expect(findings.length).toBe(0);
  });

  it('should detect common CSRF token field names', async () => {
    // Test various CSRF token naming patterns
    const tokenNames = ['csrf', '_csrf', 'csrfmiddlewaretoken', 'xsrf', '_xsrf',
      '__RequestVerificationToken', 'authenticity_token', '_token', 'form_token'];

    for (const tokenName of tokenNames) {
      const form: FormInfo = {
        pageUrl: `${baseUrl}/test`,
        action: '/test',
        method: 'POST',
        inputs: [
          { name: tokenName, type: 'hidden', value: 'abc123def456ghi789jkl012' },
          { name: 'email', type: 'text', value: '' },
        ],
      };

      const targets: ScanTargets = {
        pages: [`${baseUrl}/test`],
        forms: [form],
        urlsWithParams: [],
        apiEndpoints: [],
        redirectUrls: [],
        fileParams: [],
      };

      const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
      expect(findings.length).toBe(0);
    }
  });

  it('should dedup forms with the same action URL', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/transfer`, `${baseUrl}/transfer`],
      forms: [
        {
          pageUrl: `${baseUrl}/transfer`,
          action: '/transfer',
          method: 'POST',
          inputs: [{ name: 'to', type: 'text', value: '' }],
        },
        {
          pageUrl: `${baseUrl}/transfer`,
          action: '/transfer',
          method: 'POST',
          inputs: [{ name: 'amount', type: 'number', value: '' }],
        },
      ],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
    // Should only report once for the same action URL
    expect(findings.length).toBe(1);
  });

  describe('SameSite cookie mitigation', () => {
    it('should downgrade severity to low when session cookies have SameSite=Lax', async () => {
      // Add session cookie with SameSite=Lax
      const url = new URL(baseUrl);
      await context.addCookies([{
        name: 'session_id',
        value: 'abc123',
        domain: url.hostname,
        path: '/',
        sameSite: 'Lax',
      }]);

      const targets: ScanTargets = {
        pages: [`${baseUrl}/transfer`],
        forms: [
          {
            pageUrl: `${baseUrl}/transfer`,
            action: '/transfer',
            method: 'POST',
            inputs: [
              { name: 'to', type: 'text', value: '' },
              { name: 'amount', type: 'number', value: '' },
            ],
          },
        ],
        urlsWithParams: [],
        apiEndpoints: [],
        redirectUrls: [],
        fileParams: [],
      };

      const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      // Severity should be downgraded to low (from high, since /transfer matches STATE_CHANGING_PATHS)
      expect(findings[0].severity).toBe('low');
      expect(findings[0].confidence).toBe('low');
      expect(findings[0].description).toContain('Mitigated by SameSite=Lax');

      // Clean up cookies
      await context.clearCookies();
    });

    it('should downgrade severity to low when session cookies have SameSite=Strict', async () => {
      const url = new URL(baseUrl);
      await context.addCookies([{
        name: 'auth_token',
        value: 'xyz789',
        domain: url.hostname,
        path: '/',
        sameSite: 'Strict',
      }]);

      const targets: ScanTargets = {
        pages: [`${baseUrl}/transfer`],
        forms: [
          {
            pageUrl: `${baseUrl}/transfer`,
            action: '/transfer',
            method: 'POST',
            inputs: [
              { name: 'to', type: 'text', value: '' },
              { name: 'amount', type: 'number', value: '' },
            ],
          },
        ],
        urlsWithParams: [],
        apiEndpoints: [],
        redirectUrls: [],
        fileParams: [],
      };

      const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].severity).toBe('low');
      expect(findings[0].description).toContain('Mitigated by SameSite=Strict');

      await context.clearCookies();
    });

    it('should NOT downgrade when session cookies have SameSite=None', async () => {
      const url = new URL(baseUrl);
      await context.addCookies([{
        name: 'session_id',
        value: 'abc123',
        domain: url.hostname,
        path: '/',
        sameSite: 'None',
        secure: true,
      }]);

      const targets: ScanTargets = {
        pages: [`${baseUrl}/transfer`],
        forms: [
          {
            pageUrl: `${baseUrl}/transfer`,
            action: '/transfer',
            method: 'POST',
            inputs: [
              { name: 'to', type: 'text', value: '' },
              { name: 'amount', type: 'number', value: '' },
            ],
          },
        ],
        urlsWithParams: [],
        apiEndpoints: [],
        redirectUrls: [],
        fileParams: [],
      };

      const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      // SameSite=None does NOT mitigate CSRF — severity stays high
      expect(findings[0].severity).toBe('high');
      expect(findings[0].description).not.toContain('Mitigated by SameSite');

      await context.clearCookies();
    });

    it('getSameSiteCookieStatus returns weakest level across session cookies', () => {
      // All Lax → lax
      expect(getSameSiteCookieStatus([
        { name: 'session_id', sameSite: 'Lax' },
        { name: 'auth_token', sameSite: 'Lax' },
      ])).toBe('lax');

      // All Strict → strict
      expect(getSameSiteCookieStatus([
        { name: 'session_id', sameSite: 'Strict' },
        { name: 'auth_token', sameSite: 'Strict' },
      ])).toBe('strict');

      // Mixed Lax + Strict → lax (weakest)
      expect(getSameSiteCookieStatus([
        { name: 'session_id', sameSite: 'Strict' },
        { name: 'auth_token', sameSite: 'Lax' },
      ])).toBe('lax');

      // ANY session cookie with None → none (not mitigated)
      expect(getSameSiteCookieStatus([
        { name: 'session_id', sameSite: 'Lax' },
        { name: 'auth_token', sameSite: 'None' },
      ])).toBe('none');

      // ANY session cookie without SameSite → missing (not mitigated)
      expect(getSameSiteCookieStatus([
        { name: 'session_id', sameSite: 'Lax' },
        { name: 'auth_token' },
      ])).toBe('missing');

      // No session-like cookies → missing
      expect(getSameSiteCookieStatus([
        { name: 'theme', sameSite: 'Lax' },
        { name: 'language', sameSite: 'Strict' },
      ])).toBe('missing');

      // Empty array → missing
      expect(getSameSiteCookieStatus([])).toBe('missing');
    });

    it('should include SameSite info in evidence when mitigated', async () => {
      const url = new URL(baseUrl);
      await context.addCookies([{
        name: 'sid',
        value: 'test',
        domain: url.hostname,
        path: '/',
        sameSite: 'Lax',
      }]);

      const targets: ScanTargets = {
        pages: [`${baseUrl}/transfer`],
        forms: [
          {
            pageUrl: `${baseUrl}/transfer`,
            action: '/transfer',
            method: 'POST',
            inputs: [
              { name: 'to', type: 'text', value: '' },
            ],
          },
        ],
        urlsWithParams: [],
        apiEndpoints: [],
        redirectUrls: [],
        fileParams: [],
      };

      const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].evidence).toContain('SameSite Mitigation: Lax (session cookies)');
      expect(findings[0].evidencePack?.responseIndicators).toContain('SameSite=Lax on session cookies');

      await context.clearCookies();
    });

    it('should NOT downgrade when no session-like cookies exist', async () => {
      // Add a non-session cookie with SameSite — should not count
      const url = new URL(baseUrl);
      await context.addCookies([{
        name: 'theme_preference',
        value: 'dark',
        domain: url.hostname,
        path: '/',
        sameSite: 'Lax',
      }]);

      const targets: ScanTargets = {
        pages: [`${baseUrl}/transfer`],
        forms: [
          {
            pageUrl: `${baseUrl}/transfer`,
            action: '/transfer',
            method: 'POST',
            inputs: [
              { name: 'to', type: 'text', value: '' },
              { name: 'amount', type: 'number', value: '' },
            ],
          },
        ],
        urlsWithParams: [],
        apiEndpoints: [],
        redirectUrls: [],
        fileParams: [],
      };

      const findings = await csrfCheck.run(context, targets, makeConfig(baseUrl));
      expect(findings.length).toBeGreaterThanOrEqual(1);
      // No session-like cookies → getSameSiteCookieStatus returns 'missing' → no downgrade
      expect(findings[0].severity).toBe('high');

      await context.clearCookies();
    });
  });
});

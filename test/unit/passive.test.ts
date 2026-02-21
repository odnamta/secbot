import { describe, it, expect } from 'vitest';
import { runPassiveChecks } from '../../src/scanner/passive.js';
import type { CrawledPage, InterceptedResponse, CookieInfo } from '../../src/scanner/types.js';

function makeCookie(overrides: Partial<CookieInfo> = {}): CookieInfo {
  return {
    name: 'session',
    value: 'abc123',
    domain: 'example.com',
    path: '/',
    httpOnly: false,
    secure: true,
    sameSite: 'Lax',
    ...overrides,
  };
}

function makePage(overrides: Partial<CrawledPage> = {}): CrawledPage {
  return {
    url: 'https://example.com/',
    status: 200,
    headers: {},
    title: 'Test Page',
    forms: [],
    links: [],
    scripts: [],
    cookies: [],
    ...overrides,
  };
}

describe('passive checks: cookie HttpOnly heuristics', () => {
  const analyticsCookies = ['_ga', '_gid', '_gat_UA12345', '_fbp', '_gcl_au'];
  const preferenceCookies = ['locale', 'theme', 'lang', 'i18n_lang'];
  const csrfCookies = ['csrf_token', 'xsrf-token', '_csrf'];
  const utmCookies = ['__utma', '__utmz'];

  const skipCookies = [
    ...analyticsCookies,
    ...preferenceCookies,
    ...csrfCookies,
    ...utmCookies,
  ];

  for (const cookieName of skipCookies) {
    it(`does NOT trigger HttpOnly warning for "${cookieName}"`, () => {
      const page = makePage({
        cookies: [makeCookie({ name: cookieName, httpOnly: false })],
        headers: {
          'strict-transport-security': 'max-age=31536000',
          'content-security-policy': "default-src 'self'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
          'permissions-policy': 'camera=()',
        },
      });

      const findings = runPassiveChecks([page], []);
      const httpOnlyFindings = findings.filter(
        (f) => f.category === 'cookie-flags' && f.title.includes('HttpOnly'),
      );
      expect(httpOnlyFindings).toHaveLength(0);
    });
  }

  const sensitiveCookies = ['session', 'auth_token', 'jwt', 'sid', 'access_token'];

  for (const cookieName of sensitiveCookies) {
    it(`DOES trigger HttpOnly warning for "${cookieName}"`, () => {
      const page = makePage({
        cookies: [makeCookie({ name: cookieName, httpOnly: false })],
        headers: {
          'strict-transport-security': 'max-age=31536000',
          'content-security-policy': "default-src 'self'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
          'permissions-policy': 'camera=()',
        },
      });

      const findings = runPassiveChecks([page], []);
      const httpOnlyFindings = findings.filter(
        (f) => f.category === 'cookie-flags' && f.title.includes('HttpOnly'),
      );
      expect(httpOnlyFindings).toHaveLength(1);
    });
  }
});

describe('passive checks: header deduplication', () => {
  it('multiple pages missing the same header produce exactly 1 finding', () => {
    // All pages missing all security headers
    const pages = [
      makePage({ url: 'https://example.com/page1', headers: {} }),
      makePage({ url: 'https://example.com/page2', headers: {} }),
      makePage({ url: 'https://example.com/page3', headers: {} }),
    ];

    const findings = runPassiveChecks(pages, []);
    const hstsFindings = findings.filter((f) => f.title === 'Missing HSTS Header');
    const cspFindings = findings.filter((f) => f.title === 'Missing Content-Security-Policy Header');

    expect(hstsFindings).toHaveLength(1);
    expect(cspFindings).toHaveLength(1);
  });

  it('deduped finding includes affected URLs', () => {
    const pages = [
      makePage({ url: 'https://example.com/page1', headers: {} }),
      makePage({ url: 'https://example.com/page2', headers: {} }),
    ];

    const findings = runPassiveChecks(pages, []);
    const hstsFinding = findings.find((f) => f.title === 'Missing HSTS Header');

    expect(hstsFinding).toBeDefined();
    expect(hstsFinding!.affectedUrls).toBeDefined();
    expect(hstsFinding!.affectedUrls).toContain('https://example.com/page1');
    expect(hstsFinding!.affectedUrls).toContain('https://example.com/page2');
  });

  it('properly secured page returns 0 header findings', () => {
    const securedPage = makePage({
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'camera=()',
      },
    });

    const findings = runPassiveChecks([securedPage], []);
    const headerFindings = findings.filter((f) => f.category === 'security-headers');
    expect(headerFindings).toHaveLength(0);
  });

  it('still detects genuinely missing security headers', () => {
    // Page with only HSTS — missing 5 other headers
    const page = makePage({
      headers: {
        'strict-transport-security': 'max-age=31536000',
      },
    });

    const findings = runPassiveChecks([page], []);
    const headerFindings = findings.filter((f) => f.category === 'security-headers');

    // Should detect 5 missing headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
    expect(headerFindings).toHaveLength(5);
    expect(headerFindings.find((f) => f.title === 'Missing HSTS Header')).toBeUndefined();
    expect(headerFindings.find((f) => f.title === 'Missing Content-Security-Policy Header')).toBeDefined();
  });

  it('CSP weakness findings are not deduplicated (they are per-page)', () => {
    // Two pages both with unsafe-inline CSP — CSP weakness is not a "missing header" check,
    // it should still generate per-page (the dedup engine in Task 3 handles those)
    const pages = [
      makePage({
        url: 'https://example.com/page1',
        headers: { 'content-security-policy': "default-src 'self' 'unsafe-inline'" },
      }),
      makePage({
        url: 'https://example.com/page2',
        headers: { 'content-security-policy': "default-src 'self' 'unsafe-inline'" },
      }),
    ];

    const findings = runPassiveChecks(pages, []);
    const unsafeInline = findings.filter((f) => f.title === 'CSP Allows Unsafe Inline Scripts');
    // Not deduplicated at source — that's the dedup engine's job
    expect(unsafeInline).toHaveLength(2);
  });
});

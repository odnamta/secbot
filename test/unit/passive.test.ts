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

// ─── All security headers (including cross-origin) for a fully secured page ───
const allSecureHeaders: Record<string, string> = {
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
};

describe('passive checks: cross-origin isolation headers', () => {
  it('missing COOP/COEP/CORP headers generate findings', () => {
    const page = makePage({
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'camera=()',
        // No cross-origin headers
      },
    });

    const findings = runPassiveChecks([page], []);
    const coFindings = findings.filter((f) => f.category === 'cross-origin-policy');

    expect(coFindings).toHaveLength(3);
    expect(coFindings.every((f) => f.severity === 'low')).toBe(true);
    expect(coFindings.find((f) => f.title.includes('Cross-Origin-Opener-Policy'))).toBeDefined();
    expect(coFindings.find((f) => f.title.includes('Cross-Origin-Embedder-Policy'))).toBeDefined();
    expect(coFindings.find((f) => f.title.includes('Cross-Origin-Resource-Policy'))).toBeDefined();
  });

  it('correct COOP/COEP/CORP values do NOT generate findings', () => {
    const page = makePage({
      headers: { ...allSecureHeaders },
    });

    const findings = runPassiveChecks([page], []);
    const coFindings = findings.filter((f) => f.category === 'cross-origin-policy');
    expect(coFindings).toHaveLength(0);
  });

  it('CORP with same-site value does NOT generate a finding', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'cross-origin-resource-policy': 'same-site',
      },
    });

    const findings = runPassiveChecks([page], []);
    const corpFindings = findings.filter(
      (f) => f.category === 'cross-origin-policy' && f.title.includes('Resource-Policy'),
    );
    expect(corpFindings).toHaveLength(0);
  });

  it('wrong COOP value generates a finding with "Weak" title', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'cross-origin-opener-policy': 'unsafe-none',
      },
    });

    const findings = runPassiveChecks([page], []);
    const coopFindings = findings.filter(
      (f) => f.category === 'cross-origin-policy' && f.title.includes('Opener-Policy'),
    );
    expect(coopFindings).toHaveLength(1);
    expect(coopFindings[0].title).toContain('Weak');
    expect(coopFindings[0].evidence).toContain('unsafe-none');
  });

  it('cross-origin header findings are deduplicated across pages', () => {
    const pages = [
      makePage({ url: 'https://example.com/page1', headers: { ...allSecureHeaders, 'cross-origin-opener-policy': undefined as unknown as string } }),
      makePage({ url: 'https://example.com/page2', headers: { ...allSecureHeaders, 'cross-origin-opener-policy': undefined as unknown as string } }),
      makePage({ url: 'https://example.com/page3', headers: { ...allSecureHeaders, 'cross-origin-opener-policy': undefined as unknown as string } }),
    ];
    // Remove the COOP header properly
    for (const p of pages) {
      delete (p.headers as Record<string, string | undefined>)['cross-origin-opener-policy'];
    }

    const findings = runPassiveChecks(pages, []);
    const coopFindings = findings.filter(
      (f) => f.category === 'cross-origin-policy' && f.title.includes('Opener-Policy'),
    );

    expect(coopFindings).toHaveLength(1);
    expect(coopFindings[0].affectedUrls).toContain('https://example.com/page1');
    expect(coopFindings[0].affectedUrls).toContain('https://example.com/page2');
    expect(coopFindings[0].affectedUrls).toContain('https://example.com/page3');
  });
});

describe('passive checks: Permissions-Policy wildcard detection', () => {
  it('overly permissive Permissions-Policy generates a finding', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'permissions-policy': 'camera=*, microphone=*, geolocation=*',
      },
    });

    const findings = runPassiveChecks([page], []);
    const ppFindings = findings.filter((f) => f.title === 'Overly Permissive Permissions-Policy');

    expect(ppFindings).toHaveLength(1);
    expect(ppFindings[0].severity).toBe('medium');
    expect(ppFindings[0].category).toBe('security-headers');
    expect(ppFindings[0].description).toContain('camera');
    expect(ppFindings[0].description).toContain('microphone');
    expect(ppFindings[0].description).toContain('geolocation');
  });

  it('properly restricted Permissions-Policy does NOT generate a finding', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      },
    });

    const findings = runPassiveChecks([page], []);
    const ppFindings = findings.filter((f) => f.title === 'Overly Permissive Permissions-Policy');
    expect(ppFindings).toHaveLength(0);
  });

  it('partial wildcard Permissions-Policy flags only the permissive features', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'permissions-policy': 'camera=(), microphone=*, geolocation=(self)',
      },
    });

    const findings = runPassiveChecks([page], []);
    const ppFindings = findings.filter((f) => f.title === 'Overly Permissive Permissions-Policy');

    expect(ppFindings).toHaveLength(1);
    expect(ppFindings[0].description).toContain('microphone');
    expect(ppFindings[0].description).not.toContain('camera');
    expect(ppFindings[0].description).not.toContain('geolocation');
  });

  it('missing Permissions-Policy generates an info-severity finding (not a wildcard finding)', () => {
    const page = makePage({
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        // No permissions-policy at all
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-embedder-policy': 'require-corp',
        'cross-origin-resource-policy': 'same-origin',
      },
    });

    const findings = runPassiveChecks([page], []);
    const missingPP = findings.find((f) => f.title === 'Missing Permissions-Policy Header');
    const wildcardPP = findings.find((f) => f.title === 'Overly Permissive Permissions-Policy');

    expect(missingPP).toBeDefined();
    expect(missingPP!.severity).toBe('info');
    expect(wildcardPP).toBeUndefined();
  });
});

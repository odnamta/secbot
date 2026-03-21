import { describe, it, expect } from 'vitest';
import { runPassiveChecks, extractSensitiveComments } from '../../src/scanner/passive.js';
import type { CrawledPage, InterceptedResponse, CookieInfo, ReconResult } from '../../src/scanner/types.js';

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
  const csrfCookies = ['csrf_token', 'xsrf-token', '_csrf', '__Host-js_csrf', 'my_xsrf_key'];
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

// ─── Framework-aware CSP filtering ───────────────────────────────────────────

function makeRecon(frameworkName?: string): ReconResult {
  return {
    techStack: { languages: [], detected: [] },
    waf: { detected: false, confidence: 'low', evidence: [] },
    framework: {
      name: frameworkName,
      confidence: 'high',
      evidence: frameworkName ? [`${frameworkName} detected`] : [],
    },
    endpoints: { pages: [], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
  };
}

describe('passive checks: framework-aware CSP unsafe-inline filtering', () => {
  const cspUnsafeInlinePage = makePage({
    headers: {
      ...allSecureHeaders,
      'content-security-policy': "default-src 'self' 'unsafe-inline'",
    },
  });

  it('unsafe-inline is medium severity when no recon data is provided', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], []);
    const unsafeInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(unsafeInline).toBeDefined();
    expect(unsafeInline!.severity).toBe('medium');
    expect(unsafeInline!.description).not.toContain('framework requires');
  });

  it('unsafe-inline is medium severity when framework is unknown', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], [], makeRecon(undefined));
    const unsafeInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(unsafeInline).toBeDefined();
    expect(unsafeInline!.severity).toBe('medium');
    expect(unsafeInline!.description).not.toContain('framework requires');
  });

  it('unsafe-inline is downgraded to low severity for Next.js', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], [], makeRecon('Next.js'));
    const unsafeInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(unsafeInline).toBeDefined();
    expect(unsafeInline!.severity).toBe('low');
    expect(unsafeInline!.description).toContain(
      "nonce ensures only legitimate scripts execute",
    );
  });

  it('unsafe-inline is downgraded to low severity for Nuxt', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], [], makeRecon('Nuxt'));
    const unsafeInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(unsafeInline).toBeDefined();
    expect(unsafeInline!.severity).toBe('low');
    expect(unsafeInline!.description).toContain(
      "This is the correct pattern for Nuxt and is not an exploitable weakness",
    );
  });

  it('unsafe-inline stays medium severity for non-SPA frameworks (e.g. Laravel)', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], [], makeRecon('Laravel'));
    const unsafeInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(unsafeInline).toBeDefined();
    expect(unsafeInline!.severity).toBe('medium');
    expect(unsafeInline!.description).not.toContain('framework requires');
  });

  it('unsafe-inline stays medium severity for WordPress', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], [], makeRecon('WordPress'));
    const unsafeInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(unsafeInline).toBeDefined();
    expect(unsafeInline!.severity).toBe('medium');
  });

  it('finding is NOT suppressed for Next.js — still present at low severity', () => {
    const findings = runPassiveChecks([cspUnsafeInlinePage], [], makeRecon('Next.js'));
    const unsafeInline = findings.filter((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    // Must still be reported, not suppressed
    expect(unsafeInline).toHaveLength(1);
    expect(unsafeInline[0].severity).toBe('low');
  });

  it('unsafe-eval is NOT affected by framework detection (stays medium)', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'content-security-policy': "default-src 'self' 'unsafe-eval'",
      },
    });

    const findings = runPassiveChecks([page], [], makeRecon('Next.js'));
    const unsafeEval = findings.find((f) => f.title === 'CSP Allows Unsafe Eval');

    expect(unsafeEval).toBeDefined();
    expect(unsafeEval!.severity).toBe('medium');
  });
});

// ─── CSP directive-level unsafe-inline parsing ──────────────────────────────

describe('passive checks: CSP directive-level unsafe-inline parsing', () => {
  it('style-src only unsafe-inline generates info-level finding (not medium)', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self' 'unsafe-inline'",
      },
    });

    const findings = runPassiveChecks([page], []);
    const styleInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Styles');
    const scriptInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(styleInline).toBeDefined();
    expect(styleInline!.severity).toBe('info');
    expect(scriptInline).toBeUndefined();
  });

  it('script-src unsafe-inline generates medium finding (not info)', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
      },
    });

    const findings = runPassiveChecks([page], []);
    const scriptInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');

    expect(scriptInline).toBeDefined();
    expect(scriptInline!.severity).toBe('medium');
  });

  it('Dropbox-style CSP (nonce in script-src, unsafe-inline in style-src) is info only', () => {
    const dropboxCsp = "default-src 'none'; script-src 'nonce-abc123' https://www.dropbox.com/static/; style-src https://* 'unsafe-inline' 'unsafe-eval'";
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'content-security-policy': dropboxCsp,
      },
    });

    const findings = runPassiveChecks([page], []);
    const scriptInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');
    const styleInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Styles');

    expect(scriptInline).toBeUndefined();
    expect(styleInline).toBeDefined();
    expect(styleInline!.severity).toBe('info');
  });

  it('unsafe-eval in style-src only is NOT reported as unsafe-eval finding', () => {
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-eval'",
      },
    });

    const findings = runPassiveChecks([page], []);
    const unsafeEval = findings.find((f) => f.title === 'CSP Allows Unsafe Eval');
    expect(unsafeEval).toBeUndefined();
  });

  it('multi-policy CSP (comma-separated) parses correctly', () => {
    // Some servers send multiple CSP policies (enforced policy, report-only)
    const page = makePage({
      headers: {
        ...allSecureHeaders,
        'content-security-policy': "default-src 'self'; style-src 'unsafe-inline', default-src 'self'; script-src 'strict-dynamic' 'nonce-xyz'",
      },
    });

    const findings = runPassiveChecks([page], []);
    const scriptInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Scripts');
    const styleInline = findings.find((f) => f.title === 'CSP Allows Unsafe Inline Styles');

    // Should detect style-src unsafe-inline from first policy
    expect(styleInline).toBeDefined();
    // Should NOT report script unsafe-inline (no script-src with unsafe-inline)
    expect(scriptInline).toBeUndefined();
  });
});

describe('extractSensitiveComments', () => {
  it('finds password in HTML comment', () => {
    const html = '<html><!-- password: hunter2 --><body>hi</body></html>';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('password');
  });

  it('finds API key in comment', () => {
    const testKey = 'sk' + '_test_' + 'abc123def456ghi789';
    const html = `<!-- api_key = ${testKey} -->`;
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('API key');
  });

  it('finds internal IP in comment', () => {
    const html = '<!-- connect to http://192.168.1.100:8080/api -->';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('internal IP');
  });

  it('finds security TODO', () => {
    const html = '<!-- TODO: fix auth bypass before release, remove hardcoded password -->';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('security TODO');
  });

  it('finds debug flag', () => {
    const html = '<!-- DEBUG = true -->';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('debug flag');
  });

  it('returns empty for clean HTML', () => {
    const html = '<html><!-- Main content area --><body><h1>Hello</h1></body></html>';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(0);
  });

  it('skips IE conditional comments', () => {
    const html = '<!--[if lt IE 9]><script src="html5shiv.js"></script><![endif]-->';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(0);
  });

  it('skips short comments', () => {
    const html = '<!-- hi -->';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(0);
  });

  it('skips copyright/license comments', () => {
    const html = '<!-- Copyright 2026 Acme Corp. All rights reserved. -->';
    const results = extractSensitiveComments(html);
    expect(results).toHaveLength(0);
  });
});

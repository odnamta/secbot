import { describe, it, expect } from 'vitest';

describe('Pre-filter', () => {
  it('exports preFilterFindings function', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    expect(typeof preFilterFindings).toBe('function');
  });

  it('drops low confidence findings by default (minConfidence=medium)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'high' as const, category: 'xss' as const, severity: 'high' as const, title: 'XSS', description: '', url: '', evidence: '', timestamp: '' },
      { id: '2', confidence: 'low' as const, category: 'xss' as const, severity: 'low' as const, title: 'Maybe XSS', description: '', url: '', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'sqli' as const, severity: 'medium' as const, title: 'SQLi', description: '', url: '', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(2); // high + medium
    expect(result.dropped).toHaveLength(1); // low
    expect(result.dropped[0].id).toBe('2');
  });

  it('keeps all findings when threshold is low', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'low' as const, category: 'xss' as const, severity: 'low' as const, title: 'XSS', description: '', url: '', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings, 'low');
    expect(result.passed).toHaveLength(1);
    expect(result.dropped).toHaveLength(0);
  });

  it('drops low and medium when threshold is high', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'high' as const, category: 'xss' as const, severity: 'high' as const, title: 'High XSS', description: '', url: '', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'xss' as const, severity: 'medium' as const, title: 'Medium XSS', description: '', url: '', evidence: '', timestamp: '' },
      { id: '3', confidence: 'low' as const, category: 'xss' as const, severity: 'low' as const, title: 'Low XSS', description: '', url: '', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings, 'high');
    expect(result.passed).toHaveLength(1);
    expect(result.passed[0].id).toBe('1');
    expect(result.dropped).toHaveLength(2);
  });

  it('defaults missing confidence to medium', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', category: 'xss' as const, severity: 'high' as const, title: 'XSS', description: '', url: '', evidence: '', timestamp: '' },
    ] as any;
    // No confidence field — should default to medium, which passes the default threshold
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.dropped).toHaveLength(0);
  });

  // ─── Heuristic downgrade tests ────────────────────────────

  it('downgrades cross-origin isolation header findings', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing Cross-Origin-Opener-Policy Header', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Weak Cross-Origin-Embedder-Policy Header', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    // Both should be downgraded to low and dropped (default threshold is medium)
    expect(result.dropped).toHaveLength(2);
    expect(result.downgraded).toBe(2);
  });

  it('downgrades SRI findings on same-organization CDN', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'sri' as const, severity: 'medium' as const, title: 'Missing SRI', description: '', url: 'https://www.shopify.com/id', evidence: 'cdn.shopify.com/static/foo.js', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('keeps SRI findings on truly external CDN', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'sri' as const, severity: 'medium' as const, title: 'Missing SRI', description: '', url: 'https://www.example.com', evidence: 'cdn.jsdelivr.net/foo.js', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades third-party cookie flag findings', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "OptanonConsent" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "FPLC" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "_ga" Missing Secure Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(3);
    expect(result.downgraded).toBe(3);
  });

  it('keeps session cookie flag findings', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "session_id" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades CORS on 405/404 endpoints', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'high' as const, title: 'CORS Reflects Origin', description: '', url: 'https://example.com/__dux', evidence: 'HTTP 405', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('downgrades missing CSP on locale marketing pages', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'high' as const, title: 'Missing Content-Security-Policy Header', description: '', url: 'https://www.shopify.com/id', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('keeps missing CSP on app pages', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'high' as const, title: 'Missing Content-Security-Policy Header', description: '', url: 'https://admin.shopify.com/dashboard', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades Drift chat and analytics cookies', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "drift_aid" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "driftt_aid" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "_gd_session" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '4', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "_an_uid" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(4);
    expect(result.downgraded).toBe(4);
  });

  it('downgrades GDPR consent cookies (notice_behavior, consent, TAsessionID)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "notice_behavior" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "TAsessionID" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'cookie-flags' as const, severity: 'medium' as const, title: 'Cookie "cookie_consent" Missing HttpOnly Flag', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(3);
    expect(result.downgraded).toBe(3);
  });

  // ─── New bounty rejection pattern tests ─────────────────────────

  it('downgrades OPTIONS-only method exposure on public endpoints', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'broken-access-control' as const, severity: 'medium' as const, title: 'HTTP Methods Allowed', description: '', url: 'https://example.com/api/health', evidence: 'Allowed methods: OPTIONS', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('keeps broken-access-control when dangerous methods besides OPTIONS are exposed', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'broken-access-control' as const, severity: 'high' as const, title: 'HTTP Methods Allowed', description: '', url: 'https://example.com/api/users', evidence: 'Allowed methods: OPTIONS, DELETE, PUT', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades missing headers on error pages (404, 500, /error, /not-found)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing X-Frame-Options', description: '', url: 'https://example.com/404', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS', description: '', url: 'https://example.com/500', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing CSP', description: '', url: 'https://example.com/error', evidence: '', timestamp: '' },
      { id: '4', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing X-Content-Type-Options', description: '', url: 'https://example.com/not-found', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(4);
    expect(result.downgraded).toBe(4);
  });

  it('keeps security-headers findings on normal pages', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing X-Frame-Options', description: '', url: 'https://example.com/dashboard', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades CORS wildcard on non-authenticated endpoints (401)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'high' as const, title: 'CORS Wildcard', description: '', url: 'https://example.com/api/data', evidence: 'Access-Control-Allow-Origin: * — response 401 Unauthorized', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('downgrades CORS wildcard when empty body detected', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'high' as const, title: 'CORS Wildcard', description: '', url: 'https://example.com/health', evidence: 'wildcard origin allowed, Content-Length: 0', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('keeps CORS wildcard when endpoint returns user data', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'high' as const, title: 'CORS Wildcard', description: '', url: 'https://example.com/api/user', evidence: 'Access-Control-Allow-Origin: * with user profile in response body', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades missing HSTS on staging/preview/dev domains', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS Header', description: '', url: 'https://staging.example.com/', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing Strict-Transport-Security', description: '', url: 'https://preview.example.com/', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS Header', description: '', url: 'https://dev.example.com/', evidence: '', timestamp: '' },
      { id: '4', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS', description: '', url: 'https://test.example.com/', evidence: '', timestamp: '' },
      { id: '5', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS', description: '', url: 'https://sandbox.example.com/', evidence: '', timestamp: '' },
      { id: '6', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS', description: '', url: 'https://demo.example.com/login', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(6);
    expect(result.downgraded).toBe(6);
  });

  it('keeps HSTS findings on production domains', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS Header', description: '', url: 'https://www.example.com/', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades localhost-only CORS', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'medium' as const, title: 'CORS Allows Localhost', description: '', url: 'https://example.com/api', evidence: 'Access-Control-Allow-Origin: http://localhost:3000', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'medium' as const, title: 'CORS Allows Localhost', description: '', url: 'https://example.com/api', evidence: 'Access-Control-Allow-Origin: http://127.0.0.1:8080', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(2);
    expect(result.downgraded).toBe(2);
  });

  it('keeps CORS reflecting arbitrary origins (not just localhost)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'cors-misconfiguration' as const, severity: 'high' as const, title: 'CORS Reflects Origin', description: '', url: 'https://example.com/api', evidence: 'Reflects any origin including localhost', timestamp: '' },
    ];
    // This has "reflect" in evidence, so the localhost rule should NOT fire
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades X-XSS-Protection findings (deprecated header)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing X-XSS-Protection Header', description: '', url: 'https://example.com', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'low' as const, title: 'Weak Security Headers', description: '', url: 'https://example.com', evidence: 'X-XSS-Protection not set', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(2);
    expect(result.downgraded).toBe(2);
  });

  it('downgrades missing visual headers (X-Frame-Options, CSP) on API endpoints', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing X-Frame-Options Header', description: '', url: 'https://example.com/api/v1/users', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing Content-Security-Policy Header', description: '', url: 'https://example.com/api/health', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(2);
    expect(result.downgraded).toBe(2);
  });

  it('keeps non-visual header findings on API endpoints (e.g., HSTS)', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'security-headers' as const, severity: 'medium' as const, title: 'Missing HSTS Header', description: '', url: 'https://example.com/api/v1/data', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades info-disclosure on dev/staging/test/sandbox domains', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'info-disclosure' as const, severity: 'medium' as const, title: 'Exposed .env File', description: '', url: 'https://dev.example.com/.env', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'info-disclosure' as const, severity: 'medium' as const, title: 'Server Version Disclosure', description: '', url: 'https://staging.example.com/', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'info-disclosure' as const, severity: 'medium' as const, title: 'Stack Trace Exposed', description: '', url: 'https://test.example.com/api', evidence: '', timestamp: '' },
      { id: '4', confidence: 'medium' as const, category: 'info-disclosure' as const, severity: 'medium' as const, title: 'Debug Mode Enabled', description: '', url: 'https://sandbox.example.com/', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(4);
    expect(result.downgraded).toBe(4);
  });

  it('keeps info-disclosure on production domains', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'info-disclosure' as const, severity: 'medium' as const, title: 'Exposed .env File', description: '', url: 'https://www.example.com/.env', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades SRI missing for same-origin (first-party) scripts', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'sri' as const, severity: 'medium' as const, title: 'Missing SRI on Script', description: '', url: 'https://example.com/page', evidence: 'https://example.com/static/app.js missing integrity attribute', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(1);
    expect(result.downgraded).toBe(1);
  });

  it('keeps SRI missing for third-party CDN scripts', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'sri' as const, severity: 'medium' as const, title: 'Missing SRI on Script', description: '', url: 'https://example.com/page', evidence: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js missing integrity', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(1);
    expect(result.downgraded).toBe(0);
  });

  it('downgrades rate-limit findings on non-auth endpoints', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'rate-limit' as const, severity: 'medium' as const, title: 'No Rate Limiting Detected', description: '', url: 'https://example.com/api/products', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'rate-limit' as const, severity: 'medium' as const, title: 'No Rate Limiting Detected', description: '', url: 'https://example.com/search', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.dropped).toHaveLength(2);
    expect(result.downgraded).toBe(2);
  });

  it('keeps rate-limit findings on auth/login/password endpoints', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'medium' as const, category: 'rate-limit' as const, severity: 'medium' as const, title: 'No Rate Limiting on Login', description: '', url: 'https://example.com/login', evidence: '', timestamp: '' },
      { id: '2', confidence: 'medium' as const, category: 'rate-limit' as const, severity: 'medium' as const, title: 'No Rate Limiting on Register', description: '', url: 'https://example.com/auth/register', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium' as const, category: 'rate-limit' as const, severity: 'medium' as const, title: 'No Rate Limiting on Password Reset', description: '', url: 'https://example.com/forgot-password', evidence: '', timestamp: '' },
      { id: '4', confidence: 'medium' as const, category: 'rate-limit' as const, severity: 'medium' as const, title: 'No Rate Limiting on OTP', description: '', url: 'https://example.com/api/verify-otp', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings);
    expect(result.passed).toHaveLength(4);
    expect(result.downgraded).toBe(0);
  });
});

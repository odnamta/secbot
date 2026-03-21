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
});

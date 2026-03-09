import { describe, it, expect, vi } from 'vitest';
import {
  deduplicateAgainstDisclosures,
  getDisclosureRules,
} from '../../src/utils/disclosure-dedup.js';
import type { RawFinding } from '../../src/scanner/types.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

function makeFinding(overrides: Partial<RawFinding>): RawFinding {
  return {
    id: 'test-' + Math.random().toString(36).slice(2, 8),
    category: 'xss',
    severity: 'high',
    title: 'Test Finding',
    description: 'Test description',
    url: 'https://example.com/test',
    evidence: 'Test evidence',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('deduplicateAgainstDisclosures', () => {
  it('returns all findings when none match', () => {
    const findings = [
      makeFinding({ category: 'xss', title: 'Reflected XSS' }),
      makeFinding({ category: 'sqli', title: 'SQL Injection' }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(filtered).toHaveLength(2);
    expect(suppressed).toHaveLength(0);
  });

  it('suppresses Next.js X-Powered-By', () => {
    const findings = [
      makeFinding({
        category: 'security-headers',
        title: 'X-Powered-By Header Present',
        evidence: 'X-Powered-By: Next.js',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(filtered).toHaveLength(0);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].matchedRule).toBe('nextjs-powered-by');
  });

  it('suppresses Express X-Powered-By', () => {
    const findings = [
      makeFinding({
        category: 'security-headers',
        title: 'X-Powered-By: Express',
        evidence: 'X-Powered-By: Express',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].matchedRule).toBe('express-powered-by');
  });

  it('suppresses Vercel header disclosure', () => {
    const findings = [
      makeFinding({
        category: 'info-leakage',
        title: 'Information Disclosure',
        evidence: 'x-vercel-id: abc123',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].matchedRule).toBe('vercel-headers');
  });

  it('suppresses robots.txt info disclosure', () => {
    const findings = [
      makeFinding({
        category: 'info-disclosure',
        severity: 'info',
        title: 'robots.txt Found',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].matchedRule).toBe('robots-txt-disclosure');
  });

  it('suppresses missing HSTS on staging', () => {
    const findings = [
      makeFinding({
        category: 'security-headers',
        title: 'Missing Strict-Transport-Security',
        url: 'https://staging.example.com/',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].matchedRule).toBe('missing-hsts-non-production');
  });

  it('keeps missing HSTS on production', () => {
    const findings = [
      makeFinding({
        category: 'security-headers',
        title: 'Missing Strict-Transport-Security',
        url: 'https://www.example.com/',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(filtered).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('suppresses autocomplete password info', () => {
    const findings = [
      makeFinding({
        category: 'security-headers',
        severity: 'info',
        title: 'Autocomplete enabled on password field',
        description: 'Password field has autocomplete=on',
      }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].matchedRule).toBe('autocomplete-password');
  });

  it('keeps real XSS findings', () => {
    const findings = [
      makeFinding({ category: 'xss', title: 'Reflected XSS in search parameter' }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(filtered).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('keeps real SQLi findings', () => {
    const findings = [
      makeFinding({ category: 'sqli', title: 'Error-based SQL Injection' }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(filtered).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('handles mixed findings correctly', () => {
    const findings = [
      makeFinding({ category: 'xss', title: 'Real XSS' }),
      makeFinding({ category: 'security-headers', title: 'X-Powered-By: Express', evidence: 'X-Powered-By: Express' }),
      makeFinding({ category: 'sqli', title: 'Real SQLi' }),
      makeFinding({ category: 'info-disclosure', severity: 'info', title: 'robots.txt Found' }),
    ];
    const { filtered, suppressed } = deduplicateAgainstDisclosures(findings);
    expect(filtered).toHaveLength(2);
    expect(suppressed).toHaveLength(2);
  });

  it('returns empty for empty input', () => {
    const { filtered, suppressed } = deduplicateAgainstDisclosures([]);
    expect(filtered).toHaveLength(0);
    expect(suppressed).toHaveLength(0);
  });
});

describe('getDisclosureRules', () => {
  it('returns all registered rules', () => {
    const rules = getDisclosureRules();
    expect(rules.length).toBeGreaterThan(10);
    for (const rule of rules) {
      expect(rule.id).toBeTruthy();
      expect(rule.reason).toBeTruthy();
    }
  });

  it('has unique rule IDs', () => {
    const rules = getDisclosureRules();
    const ids = new Set(rules.map(r => r.id));
    expect(ids.size).toBe(rules.length);
  });
});

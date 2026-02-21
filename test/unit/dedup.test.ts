import { describe, it, expect } from 'vitest';
import { deduplicateFindings } from '../../src/utils/dedup.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    category: 'security-headers',
    severity: 'medium',
    title: 'Missing HSTS',
    description: 'Strict-Transport-Security header not set',
    url: 'https://example.com',
    evidence: 'Header missing',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('deduplicateFindings', () => {
  it('collapses identical findings across pages into one', () => {
    const findings = [
      makeFinding({ url: 'https://example.com/page1' }),
      makeFinding({ url: 'https://example.com/page2' }),
      makeFinding({ url: 'https://example.com/page3' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].affectedUrls).toEqual([
      'https://example.com/page1',
      'https://example.com/page2',
      'https://example.com/page3',
    ]);
  });

  it('keeps different finding types separate', () => {
    const findings = [
      makeFinding({ title: 'Missing HSTS', url: 'https://example.com/a' }),
      makeFinding({ title: 'Missing CSP', url: 'https://example.com/a' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('keeps different severities separate', () => {
    const findings = [
      makeFinding({ title: 'XSS', severity: 'high', url: 'https://example.com/a' }),
      makeFinding({ title: 'XSS', severity: 'medium', url: 'https://example.com/b' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('returns empty array for empty input', () => {
    expect(deduplicateFindings([])).toEqual([]);
  });

  it('deduplicates same URL appearing multiple times', () => {
    const findings = [
      makeFinding({ url: 'https://example.com/page1' }),
      makeFinding({ url: 'https://example.com/page1' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].affectedUrls).toEqual(['https://example.com/page1']);
  });

  it('preserves the first findings details', () => {
    const findings = [
      makeFinding({ url: 'https://example.com/a', evidence: 'first evidence' }),
      makeFinding({ url: 'https://example.com/b', evidence: 'second evidence' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result[0].evidence).toBe('first evidence');
  });
});

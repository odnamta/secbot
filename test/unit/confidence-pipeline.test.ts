import { describe, it, expect } from 'vitest';
import { deduplicateFindings } from '../../src/utils/dedup.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: Math.random().toString(36),
    category: 'xss',
    severity: 'high',
    title: 'XSS on /page',
    description: 'Test finding',
    url: 'https://example.com/page',
    evidence: 'proof',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('Confidence-aware dedup', () => {
  it('preserves highest confidence when merging', () => {
    const findings = [
      makeFinding({ id: '1', confidence: 'medium' }),
      makeFinding({ id: '2', confidence: 'high' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe('high');
  });

  it('defaults missing confidence to medium', () => {
    const findings = [
      makeFinding({ id: '1' }), // no confidence field
    ];
    const result = deduplicateFindings(findings);
    expect(result[0].confidence).toBe('medium');
  });

  it('keeps low when all are low', () => {
    const findings = [
      makeFinding({ id: '1', confidence: 'low' }),
      makeFinding({ id: '2', confidence: 'low' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result[0].confidence).toBe('low');
  });

  it('upgrades low to high when mixed', () => {
    const findings = [
      makeFinding({ id: '1', confidence: 'low' }),
      makeFinding({ id: '2', confidence: 'high' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result[0].confidence).toBe('high');
  });

  it('preserves medium when no high exists', () => {
    const findings = [
      makeFinding({ id: '1', confidence: 'low' }),
      makeFinding({ id: '2', confidence: 'medium' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result[0].confidence).toBe('medium');
  });

  it('merges affectedUrls correctly with confidence', () => {
    const findings = [
      makeFinding({ id: '1', url: 'https://a.com/1', confidence: 'medium' }),
      makeFinding({ id: '2', url: 'https://a.com/2', confidence: 'high' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].affectedUrls).toContain('https://a.com/1');
    expect(result[0].affectedUrls).toContain('https://a.com/2');
    expect(result[0].confidence).toBe('high');
  });
});

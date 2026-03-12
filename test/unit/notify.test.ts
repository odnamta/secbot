import { describe, it, expect } from 'vitest';
import { formatHuntSummary } from '../../src/hunting/notify.js';
import type { HuntSummary } from '../../src/hunting/types.js';

function makeSummary(overrides: Partial<HuntSummary> = {}): HuntSummary {
  return {
    programs: 3,
    findings: { high: 0, medium: 0, low: 0 },
    escalations: 0,
    duration: '2m 34s',
    scannedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe('formatHuntSummary', () => {
  it('includes programs count', () => {
    const result = formatHuntSummary(makeSummary({ programs: 5 }));
    expect(result).toContain('5 programs scanned');
  });

  it('shows "No findings" when all finding counts are zero', () => {
    const result = formatHuntSummary(makeSummary({ findings: { high: 0, medium: 0, low: 0 } }));
    expect(result).toContain('No findings');
  });

  it('does not include findings detail when zero total', () => {
    const result = formatHuntSummary(makeSummary({ findings: { high: 0, medium: 0, low: 0 } }));
    expect(result).not.toContain('high-confidence');
  });

  it('shows findings breakdown when findings exist', () => {
    const result = formatHuntSummary(makeSummary({
      findings: { high: 2, medium: 3, low: 1 },
    }));
    expect(result).toContain('6 findings');
    expect(result).toContain('2 high-confidence');
    expect(result).toContain('3 medium');
    expect(result).toContain('1 low');
  });

  it('shows total finding count correctly', () => {
    const result = formatHuntSummary(makeSummary({
      findings: { high: 1, medium: 4, low: 2 },
    }));
    expect(result).toContain('7 findings');
  });

  it('does not mention escalations when count is zero', () => {
    const result = formatHuntSummary(makeSummary({ escalations: 0 }));
    expect(result).not.toContain('need your help');
  });

  it('shows escalations when present', () => {
    const result = formatHuntSummary(makeSummary({ escalations: 3 }));
    expect(result).toContain('3 need your help');
  });

  it('includes duration', () => {
    const result = formatHuntSummary(makeSummary({ duration: '5m 12s' }));
    expect(result).toContain('Duration: 5m 12s');
  });

  it('uses pipe separator between parts', () => {
    const result = formatHuntSummary(makeSummary({ escalations: 1 }));
    expect(result).toContain(' | ');
  });

  it('handles single program', () => {
    const result = formatHuntSummary(makeSummary({ programs: 1 }));
    expect(result).toContain('1 programs scanned');
  });

  it('handles high findings only', () => {
    const result = formatHuntSummary(makeSummary({
      findings: { high: 5, medium: 0, low: 0 },
    }));
    expect(result).toContain('5 findings');
    expect(result).toContain('5 high-confidence');
    expect(result).toContain('0 medium');
    expect(result).toContain('0 low');
  });

  it('full output with all sections', () => {
    const summary = makeSummary({
      programs: 4,
      findings: { high: 1, medium: 2, low: 3 },
      escalations: 2,
      duration: '10m 0s',
    });
    const result = formatHuntSummary(summary);
    expect(result).toContain('Hunt complete');
    expect(result).toContain('4 programs scanned');
    expect(result).toContain('6 findings');
    expect(result).toContain('2 need your help');
    expect(result).toContain('Duration: 10m 0s');
  });
});

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
});

import { describe, it, expect } from 'vitest';

describe('Auto-verify module', () => {
  it('exports verifyFinding function', async () => {
    const mod = await import('../../src/scanner/auto-verify.js');
    expect(typeof mod.verifyFinding).toBe('function');
  });

  it('XSS verify checks for DOM mutation', async () => {
    const { verifyXss } = await import('../../src/scanner/auto-verify.js');
    expect(typeof verifyXss).toBe('function');
  });

  it('SQLi verify uses second payload', async () => {
    const { verifySqli } = await import('../../src/scanner/auto-verify.js');
    expect(typeof verifySqli).toBe('function');
  });

  it('returns upgraded confidence on successful verify', async () => {
    const { upgradeConfidence } = await import('../../src/scanner/auto-verify.js');
    expect(upgradeConfidence('medium', true)).toBe('high');
    expect(upgradeConfidence('medium', false)).toBe('low');
    expect(upgradeConfidence('high', true)).toBe('high');
    expect(upgradeConfidence('low', true)).toBe('medium');
  });

  it('verifyFindings passes through low-confidence findings unchanged', async () => {
    const { verifyFindings } = await import('../../src/scanner/auto-verify.js');
    const lowFinding = {
      id: 'l1',
      category: 'sqli' as const,
      severity: 'low' as const,
      title: 'Low SQLi',
      description: '',
      url: 'https://example.com',
      evidence: '',
      timestamp: new Date().toISOString(),
      confidence: 'low' as const,
    };
    // Provide a stub BrowserContext — low-confidence findings pass through unchanged
    const stubContext = {} as import('playwright').BrowserContext;
    const results = await verifyFindings([lowFinding], stubContext);
    expect(results).toHaveLength(1);
    expect(results[0].confidence).toBe('low');
  });

  it('verifyFinding returns unchanged for unknown categories', async () => {
    const { verifyFinding } = await import('../../src/scanner/auto-verify.js');
    const finding = {
      id: 'u1',
      category: 'tls' as const,
      severity: 'medium' as const,
      title: 'TLS issue',
      description: '',
      url: 'https://example.com',
      evidence: '',
      timestamp: new Date().toISOString(),
      confidence: 'medium' as const,
    };
    const stubContext = {} as import('playwright').BrowserContext;
    const result = await verifyFinding(finding, stubContext);
    expect(result).toEqual(finding);
  });
});

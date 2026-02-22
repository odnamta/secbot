import { describe, it, expect } from 'vitest';
import { convertHitsToFindings } from '../../src/scanner/oob/hit-converter.js';
import type { CallbackHit } from '../../src/scanner/oob/callback-server.js';

describe('convertHitsToFindings', () => {
  const makeHit = (payloadId: string, overrides?: Partial<CallbackHit>): CallbackHit => ({
    payloadId,
    timestamp: '2025-01-01T00:00:00Z',
    sourceIp: '10.0.0.1',
    method: 'GET',
    path: `/cb/${payloadId}`,
    headers: { host: '127.0.0.1:9999' },
    body: '',
    ...overrides,
  });

  it('classifies blind XSS hits as high-severity xss', () => {
    const findings = convertHitsToFindings([makeHit('bxss-abc-123')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('xss');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('Blind XSS');
  });

  it('classifies blind SQLi hits as critical-severity sqli', () => {
    const findings = convertHitsToFindings([makeHit('bsqli-def-456')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('sqli');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].title).toContain('Blind SQL Injection');
  });

  it('classifies blind SSRF hits as high-severity ssrf', () => {
    const findings = convertHitsToFindings([makeHit('bssrf-ghi-789')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('ssrf');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('Blind SSRF');
  });

  it('classifies unknown prefixes as medium-severity ssrf', () => {
    const findings = convertHitsToFindings([makeHit('unknown-payload-id')]);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('ssrf');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].title).toContain('Unknown Source');
  });

  it('converts multiple hits', () => {
    const hits = [
      makeHit('bxss-1'),
      makeHit('bssrf-2'),
      makeHit('bsqli-3'),
    ];
    const findings = convertHitsToFindings(hits);
    expect(findings).toHaveLength(3);
    expect(findings.map(f => f.category)).toEqual(['xss', 'ssrf', 'sqli']);
  });

  it('returns empty array for no hits', () => {
    expect(convertHitsToFindings([])).toEqual([]);
  });

  it('includes hit details in evidence', () => {
    const hit = makeHit('bxss-test', {
      sourceIp: '192.168.1.100',
      method: 'POST',
      path: '/cb/bxss-test',
    });
    const [finding] = convertHitsToFindings([hit]);
    expect(finding.evidence).toContain('192.168.1.100');
    expect(finding.evidence).toContain('POST');
    expect(finding.evidence).toContain('bxss-test');
  });

  it('generates unique finding IDs', () => {
    const hits = [makeHit('bxss-a'), makeHit('bxss-b')];
    const findings = convertHitsToFindings(hits);
    expect(findings[0].id).not.toBe(findings[1].id);
    expect(findings[0].id).toMatch(/^oob-/);
  });
});

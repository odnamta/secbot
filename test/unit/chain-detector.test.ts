import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { detectChains } from '../../src/scanner/active/chain-detector.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding>): RawFinding {
  return {
    id: randomUUID(),
    category: 'xss',
    severity: 'high',
    title: 'Test Finding',
    description: 'Test description',
    url: 'https://example.com',
    evidence: 'test evidence',
    timestamp: new Date().toISOString(),
    confidence: 'medium',
    ...overrides,
  };
}

describe('Chain Detector', () => {
  it('should detect XSS + CSRF chain', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'xss', title: 'Reflected XSS' }),
      makeFinding({ category: 'csrf', title: 'Missing CSRF Protection on POST Form' }),
    ];
    const chains = detectChains(findings);
    expect(chains.length).toBeGreaterThanOrEqual(1);
    const xssCsrf = chains.find((c) => c.name.includes('XSS') && c.name.includes('CSRF'));
    expect(xssCsrf).toBeDefined();
    expect(xssCsrf!.severity).toBe('critical');
  });

  it('should detect CSRF + weak SameSite cookie chain', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'csrf', title: 'Missing CSRF Protection on POST Form' }),
      makeFinding({
        category: 'cookie-flags',
        title: 'Cookie Missing SameSite Attribute',
        description: 'Session cookie without SameSite protection',
      }),
    ];
    const chains = detectChains(findings);
    const csrfCookie = chains.find((c) => c.name.includes('CSRF') && c.name.includes('SameSite'));
    expect(csrfCookie).toBeDefined();
    expect(csrfCookie!.severity).toBe('high');
  });

  it('should detect redirect + SSRF chain', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'open-redirect', title: 'Open Redirect' }),
      makeFinding({ category: 'ssrf', title: 'SSRF' }),
    ];
    const chains = detectChains(findings);
    const redirectSsrf = chains.find((c) => c.name.includes('Redirect') && c.name.includes('SSRF'));
    expect(redirectSsrf).toBeDefined();
    expect(redirectSsrf!.severity).toBe('critical');
  });

  it('should detect CORS + XSS chain', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'cors-misconfiguration', title: 'CORS Reflects Origin' }),
      makeFinding({ category: 'xss', title: 'Reflected XSS' }),
    ];
    const chains = detectChains(findings);
    const corsXss = chains.find((c) => c.name.includes('CORS') && c.name.includes('XSS'));
    expect(corsXss).toBeDefined();
  });

  it('should return empty for no matching chains', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'tls', title: 'Weak TLS' }),
      makeFinding({ category: 'sri', title: 'Missing SRI' }),
    ];
    const chains = detectChains(findings);
    expect(chains.length).toBe(0);
  });

  it('should include component finding IDs in chain', () => {
    const xss = makeFinding({ category: 'xss', title: 'XSS' });
    const csrf = makeFinding({ category: 'csrf', title: 'Missing CSRF' });
    const chains = detectChains([xss, csrf]);
    const chain = chains.find((c) => c.name.includes('CSRF'));
    expect(chain).toBeDefined();
    expect(chain!.components).toContain(xss.id);
    expect(chain!.components).toContain(csrf.id);
  });

  it('should NOT form chains from low-confidence findings', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'xss', title: 'Reflected XSS', confidence: 'low' }),
      makeFinding({ category: 'csrf', title: 'Missing CSRF Protection', confidence: 'medium' }),
    ];
    const chains = detectChains(findings);
    // XSS is low-confidence, so XSS+CSRF chain should not form
    const xssCsrf = chains.find((c) => c.name.includes('XSS') && c.name.includes('CSRF'));
    expect(xssCsrf).toBeUndefined();
  });

  it('should form chains from high-confidence findings', () => {
    const findings: RawFinding[] = [
      makeFinding({ category: 'xss', title: 'Reflected XSS', confidence: 'high' }),
      makeFinding({ category: 'csrf', title: 'Missing CSRF Protection', confidence: 'high' }),
    ];
    const chains = detectChains(findings);
    const xssCsrf = chains.find((c) => c.name.includes('XSS') && c.name.includes('CSRF'));
    expect(xssCsrf).toBeDefined();
    expect(xssCsrf!.severity).toBe('critical');
  });
});

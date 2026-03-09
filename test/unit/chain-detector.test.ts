import { describe, it, expect } from 'vitest';
import { detectChains } from '../../src/scanner/active/chain-detector.js';
import type { RawFinding, CheckCategory } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> & { category: CheckCategory }): RawFinding {
  return {
    id: `f-${overrides.category}-${Math.random().toString(36).slice(2)}`,
    severity: 'medium',
    title: `Test ${overrides.category} finding`,
    description: `Description for ${overrides.category}`,
    url: 'https://example.com/page',
    evidence: 'Test evidence',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('detectChains', () => {
  it('returns empty array when no chains detected', () => {
    const findings = [
      makeFinding({ category: 'xss' }),
    ];
    const chains = detectChains(findings);
    expect(chains).toEqual([]);
  });

  it('returns empty array for empty findings', () => {
    expect(detectChains([])).toEqual([]);
  });

  describe('Open Redirect + SSRF → Internal SSRF', () => {
    it('detects chain when both findings exist on same domain', () => {
      const findings = [
        makeFinding({ category: 'open-redirect', url: 'https://example.com/redirect' }),
        makeFinding({ category: 'ssrf', url: 'https://example.com/api/fetch' }),
      ];
      const chains = detectChains(findings);
      expect(chains).toHaveLength(1);
      expect(chains[0].name).toContain('Open Redirect');
      expect(chains[0].name).toContain('SSRF');
      expect(chains[0].severity).toBe('critical');
      expect(chains[0].components).toHaveLength(2);
    });

    it('detects chain even on different domains', () => {
      const findings = [
        makeFinding({ category: 'open-redirect', url: 'https://example.com/redirect' }),
        makeFinding({ category: 'ssrf', url: 'https://api.example.com/fetch' }),
      ];
      const chains = detectChains(findings);
      expect(chains).toHaveLength(1);
    });

    it('does not detect chain when only redirect exists', () => {
      const findings = [
        makeFinding({ category: 'open-redirect' }),
      ];
      const chains = detectChains(findings);
      const ssrfChain = chains.find(c => c.name.includes('SSRF'));
      expect(ssrfChain).toBeUndefined();
    });
  });

  describe('XSS + CSRF → Account Takeover', () => {
    it('detects chain when XSS and missing CSRF protection exist', () => {
      const findings = [
        makeFinding({ category: 'xss', title: 'Reflected XSS' }),
        makeFinding({
          category: 'cookie-flags',
          title: 'Missing SameSite cookie flag',
          description: 'Cookie lacks SameSite attribute, vulnerable to cross-site request forgery (CSRF)',
        }),
      ];
      const chains = detectChains(findings);
      const atoChain = chains.find(c => c.name.includes('Account Takeover'));
      expect(atoChain).toBeDefined();
      expect(atoChain!.severity).toBe('critical');
      expect(atoChain!.components).toHaveLength(2);
    });

    it('detects chain with security-headers CSRF mention', () => {
      const findings = [
        makeFinding({ category: 'xss' }),
        makeFinding({
          category: 'security-headers',
          title: 'No CSRF protection detected',
          description: 'Application does not implement CSRF tokens',
        }),
      ];
      const chains = detectChains(findings);
      const atoChain = chains.find(c => c.name.includes('Account Takeover'));
      expect(atoChain).toBeDefined();
    });

    it('does not detect chain when XSS alone exists', () => {
      const findings = [
        makeFinding({ category: 'xss' }),
      ];
      const chains = detectChains(findings);
      const atoChain = chains.find(c => c.name.includes('Account Takeover'));
      expect(atoChain).toBeUndefined();
    });
  });

  describe('Info Disclosure + IDOR → Data Breach', () => {
    it('detects chain with info-disclosure and IDOR', () => {
      const findings = [
        makeFinding({ category: 'info-disclosure', title: 'Exposed .env file' }),
        makeFinding({ category: 'idor', title: 'IDOR on user profile' }),
      ];
      const chains = detectChains(findings);
      const dataChain = chains.find(c => c.name.includes('Data Breach'));
      expect(dataChain).toBeDefined();
      expect(dataChain!.severity).toBe('critical');
      expect(dataChain!.components).toHaveLength(2);
    });

    it('detects chain with info-leakage and IDOR', () => {
      const findings = [
        makeFinding({ category: 'info-leakage', title: 'Server version disclosed' }),
        makeFinding({ category: 'idor', title: 'IDOR on API endpoint' }),
      ];
      const chains = detectChains(findings);
      const dataChain = chains.find(c => c.name.includes('Data Breach'));
      expect(dataChain).toBeDefined();
    });

    it('does not detect chain without IDOR', () => {
      const findings = [
        makeFinding({ category: 'info-disclosure' }),
      ];
      const chains = detectChains(findings);
      const dataChain = chains.find(c => c.name.includes('Data Breach'));
      expect(dataChain).toBeUndefined();
    });
  });

  describe('CORS + XSS → Cross-Origin Data Theft', () => {
    it('detects chain with CORS misconfiguration and XSS', () => {
      const findings = [
        makeFinding({ category: 'cors-misconfiguration', title: 'Wildcard CORS' }),
        makeFinding({ category: 'xss', title: 'Stored XSS' }),
      ];
      const chains = detectChains(findings);
      const corsChain = chains.find(c => c.name.includes('Cross-Origin Data Theft'));
      expect(corsChain).toBeDefined();
      expect(corsChain!.severity).toBe('high');
      expect(corsChain!.components).toHaveLength(2);
    });

    it('does not detect chain with CORS alone', () => {
      const findings = [
        makeFinding({ category: 'cors-misconfiguration' }),
      ];
      const chains = detectChains(findings);
      const corsChain = chains.find(c => c.name.includes('Cross-Origin Data Theft'));
      expect(corsChain).toBeUndefined();
    });
  });

  describe('JWT Weak Secret + Missing Rate Limit → Auth Bypass', () => {
    it('detects chain with weak JWT secret and missing rate limit', () => {
      const findings = [
        makeFinding({
          category: 'jwt',
          title: 'JWT Weak Secret',
          description: 'JWT signed with a weak secret key that can be brute-forced',
        }),
        makeFinding({ category: 'rate-limit', title: 'No rate limiting on login endpoint' }),
      ];
      const chains = detectChains(findings);
      const authChain = chains.find(c => c.name.includes('Authentication Bypass'));
      expect(authChain).toBeDefined();
      expect(authChain!.severity).toBe('critical');
      expect(authChain!.components).toHaveLength(2);
    });

    it('detects chain with none algorithm JWT', () => {
      const findings = [
        makeFinding({
          category: 'jwt',
          title: 'JWT None Algorithm Accepted',
          description: 'Server accepts JWT with none algorithm bypass',
        }),
        makeFinding({ category: 'rate-limit' }),
      ];
      const chains = detectChains(findings);
      const authChain = chains.find(c => c.name.includes('Authentication Bypass'));
      expect(authChain).toBeDefined();
    });

    it('does not detect chain when JWT finding is not about weak secrets', () => {
      const findings = [
        makeFinding({
          category: 'jwt',
          title: 'JWT Missing Expiry',
          description: 'JWT token does not contain exp claim',
        }),
        makeFinding({ category: 'rate-limit' }),
      ];
      const chains = detectChains(findings);
      const authChain = chains.find(c => c.name.includes('Authentication Bypass'));
      expect(authChain).toBeUndefined();
    });

    it('does not detect chain without rate-limit finding', () => {
      const findings = [
        makeFinding({
          category: 'jwt',
          title: 'JWT Weak Secret',
          description: 'Weak secret key',
        }),
      ];
      const chains = detectChains(findings);
      const authChain = chains.find(c => c.name.includes('Authentication Bypass'));
      expect(authChain).toBeUndefined();
    });
  });

  describe('multiple chains', () => {
    it('detects multiple chains simultaneously', () => {
      const findings = [
        makeFinding({ category: 'open-redirect' }),
        makeFinding({ category: 'ssrf' }),
        makeFinding({ category: 'xss' }),
        makeFinding({
          category: 'security-headers',
          title: 'Missing CSRF token',
          description: 'No CSRF protection',
        }),
        makeFinding({ category: 'cors-misconfiguration' }),
      ];
      const chains = detectChains(findings);
      // Should detect: redirect+ssrf, xss+csrf, cors+xss
      expect(chains.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('VulnChain structure', () => {
    it('has correct fields', () => {
      const findings = [
        makeFinding({ category: 'open-redirect', id: 'redirect-1' }),
        makeFinding({ category: 'ssrf', id: 'ssrf-1' }),
      ];
      const chains = detectChains(findings);
      expect(chains).toHaveLength(1);
      const chain = chains[0];
      expect(chain).toHaveProperty('name');
      expect(chain).toHaveProperty('severity');
      expect(chain).toHaveProperty('description');
      expect(chain).toHaveProperty('components');
      expect(chain).toHaveProperty('impact');
      expect(chain.components).toContain('redirect-1');
      expect(chain.components).toContain('ssrf-1');
      expect(typeof chain.description).toBe('string');
      expect(typeof chain.impact).toBe('string');
      expect(chain.description.length).toBeGreaterThan(0);
      expect(chain.impact.length).toBeGreaterThan(0);
    });
  });
});

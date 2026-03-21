import { describe, it, expect } from 'vitest';
import { getCvssForFinding, inferCategoryFromTitle } from '../../src/utils/cvss.js';
import type { CheckCategory, Severity } from '../../src/scanner/types.js';

// All check categories defined in the codebase
const ALL_CATEGORIES: CheckCategory[] = [
  'security-headers', 'cookie-flags', 'info-leakage', 'mixed-content',
  'sensitive-url-data', 'xss', 'sqli', 'open-redirect', 'cross-origin-policy',
  'cors-misconfiguration', 'directory-traversal', 'ssrf', 'ssti', 'idor',
  'command-injection', 'tls', 'sri', 'info-disclosure', 'js-cve',
  'crlf-injection', 'rate-limit', 'jwt', 'race-condition', 'host-header',
  'graphql', 'file-upload', 'broken-access-control', 'business-logic',
  'websocket', 'api-versioning', 'subdomain-takeover', 'oauth',
  'cache-poisoning', 'csrf', 'prototype-pollution', 'xxe',
  'insecure-deserialization', 'request-smuggling', 'ldap-injection',
  'clickjacking', 'vuln-chain',
];

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

describe('CVSS 3.1 scoring', () => {
  describe('getCvssForFinding', () => {
    it('returns valid CVSS 3.1 vector for every check category', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'high');
        expect(result.vector).toMatch(/^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/);
      }
    });

    it('returns score between 0.0 and 10.0 for all categories', () => {
      for (const cat of ALL_CATEGORIES) {
        for (const sev of SEVERITIES) {
          const result = getCvssForFinding(cat, sev);
          expect(result.score).toBeGreaterThanOrEqual(0.0);
          expect(result.score).toBeLessThanOrEqual(10.0);
        }
      }
    });

    it('critical severity scores >= 9.0', () => {
      // Categories with high base scores should be >= 9.0 at critical
      const criticalCategories: CheckCategory[] = ['sqli', 'command-injection', 'ssti', 'insecure-deserialization'];
      for (const cat of criticalCategories) {
        const result = getCvssForFinding(cat, 'critical');
        expect(result.score).toBeGreaterThanOrEqual(9.0);
        expect(result.rating).toBe('Critical');
      }
    });

    it('high severity scores are in range 7.0-8.9', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'high');
        expect(result.score).toBeGreaterThanOrEqual(7.0);
        expect(result.score).toBeLessThanOrEqual(8.9);
        expect(result.rating).toBe('High');
      }
    });

    it('medium severity scores are in range 4.0-6.9', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'medium');
        expect(result.score).toBeGreaterThanOrEqual(4.0);
        expect(result.score).toBeLessThanOrEqual(6.9);
        expect(result.rating).toBe('Medium');
      }
    });

    it('low severity scores are in range 0.1-3.9', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'low');
        expect(result.score).toBeGreaterThanOrEqual(0.1);
        expect(result.score).toBeLessThanOrEqual(3.9);
        expect(result.rating).toBe('Low');
      }
    });

    it('info severity always returns 0.0 with None rating', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'info');
        expect(result.score).toBe(0.0);
        expect(result.rating).toBe('None');
      }
    });

    it('preserves base score when it falls within the severity range', () => {
      // XSS base score is 6.1, medium range is 4.0-6.9 -> should keep 6.1
      const result = getCvssForFinding('xss', 'medium');
      expect(result.score).toBe(6.1);
    });

    it('clamps score down when base exceeds severity ceiling', () => {
      // SQLi base score is 9.8, medium range max is 6.9 -> should clamp to 6.9
      const result = getCvssForFinding('sqli', 'medium');
      expect(result.score).toBe(6.9);
    });

    it('raises score when base is below severity floor', () => {
      // Clickjacking base score is 4.3, high range min is 7.0 -> should raise to 7.0
      const result = getCvssForFinding('clickjacking', 'high');
      expect(result.score).toBe(7.0);
    });

    it('returns correct rating labels', () => {
      expect(getCvssForFinding('sqli', 'critical').rating).toBe('Critical');
      expect(getCvssForFinding('sqli', 'high').rating).toBe('High');
      expect(getCvssForFinding('sqli', 'medium').rating).toBe('Medium');
      expect(getCvssForFinding('sqli', 'low').rating).toBe('Low');
      expect(getCvssForFinding('sqli', 'info').rating).toBe('None');
    });

    it('vuln-chain at critical returns 10.0', () => {
      const result = getCvssForFinding('vuln-chain', 'critical');
      expect(result.score).toBe(10.0);
      expect(result.rating).toBe('Critical');
    });

    it('scores are rounded to one decimal place', () => {
      for (const cat of ALL_CATEGORIES) {
        for (const sev of SEVERITIES) {
          const result = getCvssForFinding(cat, sev);
          const rounded = Math.round(result.score * 10) / 10;
          expect(result.score).toBe(rounded);
        }
      }
    });
  });

  describe('inferCategoryFromTitle', () => {
    it('maps XSS titles correctly', () => {
      expect(inferCategoryFromTitle('Reflected XSS in /search')).toBe('xss');
      expect(inferCategoryFromTitle('Stored Cross-Site Scripting')).toBe('xss');
    });

    it('maps SQL injection titles correctly', () => {
      expect(inferCategoryFromTitle('SQL Injection in login form')).toBe('sqli');
      expect(inferCategoryFromTitle('Blind SQLi via id parameter')).toBe('sqli');
    });

    it('maps command injection titles correctly', () => {
      expect(inferCategoryFromTitle('OS Command Injection in ping utility')).toBe('command-injection');
      expect(inferCategoryFromTitle('CMDi via filename parameter')).toBe('command-injection');
    });

    it('maps SSRF titles correctly', () => {
      expect(inferCategoryFromTitle('SSRF via URL parameter')).toBe('ssrf');
      expect(inferCategoryFromTitle('Server-Side Request Forgery in webhook')).toBe('ssrf');
    });

    it('maps SSTI titles correctly', () => {
      expect(inferCategoryFromTitle('Server-Side Template Injection')).toBe('ssti');
      expect(inferCategoryFromTitle('SSTI via name parameter')).toBe('ssti');
    });

    it('maps CORS titles correctly', () => {
      expect(inferCategoryFromTitle('CORS Misconfiguration on /api/data')).toBe('cors-misconfiguration');
    });

    it('maps CSRF titles correctly', () => {
      expect(inferCategoryFromTitle('Missing CSRF token on password change')).toBe('csrf');
      expect(inferCategoryFromTitle('Cross-Site Request Forgery')).toBe('csrf');
      expect(inferCategoryFromTitle('Content-Type Confusion CSRF bypass')).toBe('csrf');
    });

    it('maps JWT titles correctly', () => {
      expect(inferCategoryFromTitle('JWT none algorithm bypass')).toBe('jwt');
    });

    it('maps prototype pollution titles correctly', () => {
      expect(inferCategoryFromTitle('Prototype Pollution via __proto__')).toBe('prototype-pollution');
    });

    it('maps XXE titles correctly', () => {
      expect(inferCategoryFromTitle('XXE in XML parser')).toBe('xxe');
      expect(inferCategoryFromTitle('XML External Entity injection')).toBe('xxe');
    });

    it('maps request smuggling titles correctly', () => {
      expect(inferCategoryFromTitle('HTTP Request Smuggling (CL.TE)')).toBe('request-smuggling');
    });

    it('maps deserialization titles correctly', () => {
      expect(inferCategoryFromTitle('Insecure Deserialization in Java endpoint')).toBe('insecure-deserialization');
    });

    it('maps LDAP injection titles correctly', () => {
      expect(inferCategoryFromTitle('LDAP Injection in user search')).toBe('ldap-injection');
    });

    it('maps clickjacking titles correctly', () => {
      expect(inferCategoryFromTitle('Clickjacking on account settings')).toBe('clickjacking');
      expect(inferCategoryFromTitle('UI Redressing vulnerability')).toBe('clickjacking');
    });

    it('maps broken access control titles correctly', () => {
      expect(inferCategoryFromTitle('Broken Access Control on admin panel')).toBe('broken-access-control');
      expect(inferCategoryFromTitle('BFLA in /api/admin/users')).toBe('broken-access-control');
      expect(inferCategoryFromTitle('Mass Assignment in user profile')).toBe('broken-access-control');
      expect(inferCategoryFromTitle('HTTP Method Override ACL bypass')).toBe('broken-access-control');
    });

    it('maps info-disclosure related titles correctly', () => {
      expect(inferCategoryFromTitle('Timing Attack on login endpoint')).toBe('info-disclosure');
      expect(inferCategoryFromTitle('Username Enumeration via response timing')).toBe('info-disclosure');
      expect(inferCategoryFromTitle('Verbose Error messages exposed')).toBe('info-disclosure');
      expect(inferCategoryFromTitle('Stack Trace in error response')).toBe('info-disclosure');
    });

    it('maps CRLF/email injection titles correctly', () => {
      expect(inferCategoryFromTitle('CRLF Injection in redirect header')).toBe('crlf-injection');
      expect(inferCategoryFromTitle('Email Injection via contact form')).toBe('crlf-injection');
      expect(inferCategoryFromTitle('SMTP Header Injection')).toBe('crlf-injection');
    });

    it('maps XPath injection to sqli category', () => {
      expect(inferCategoryFromTitle('XPath Injection in XML query')).toBe('sqli');
    });

    it('maps security header titles correctly', () => {
      expect(inferCategoryFromTitle('Missing HSTS header')).toBe('security-headers');
      expect(inferCategoryFromTitle('Weak Content-Security-Policy')).toBe('security-headers');
    });

    it('returns info-disclosure as fallback for unknown titles', () => {
      expect(inferCategoryFromTitle('Something completely unknown')).toBe('info-disclosure');
    });

    it('maps vuln-chain titles correctly', () => {
      expect(inferCategoryFromTitle('Vulnerability Chain: redirect + SSRF')).toBe('vuln-chain');
    });

    it('maps subdomain takeover titles correctly', () => {
      expect(inferCategoryFromTitle('Subdomain Takeover on staging.example.com')).toBe('subdomain-takeover');
    });

    it('maps OAuth titles correctly', () => {
      expect(inferCategoryFromTitle('OAuth redirect_uri bypass')).toBe('oauth');
    });
  });

  describe('CVSS vector format', () => {
    it('all vectors start with CVSS:3.1 prefix', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'high');
        expect(result.vector).toMatch(/^CVSS:3\.1\//);
      }
    });

    it('all vectors use Network attack vector (web vulnerabilities)', () => {
      for (const cat of ALL_CATEGORIES) {
        const result = getCvssForFinding(cat, 'high');
        expect(result.vector).toContain('AV:N');
      }
    });
  });

  describe('specific category scores', () => {
    it('SQLi has base score 9.8 (critical-tier)', () => {
      const result = getCvssForFinding('sqli', 'critical');
      expect(result.score).toBe(9.8);
    });

    it('XSS has base score 6.1 (medium-tier)', () => {
      const result = getCvssForFinding('xss', 'medium');
      expect(result.score).toBe(6.1);
    });

    it('SSRF has base score 8.6 at high severity', () => {
      const result = getCvssForFinding('ssrf', 'high');
      expect(result.score).toBe(8.6);
    });

    it('race-condition uses High attack complexity', () => {
      const result = getCvssForFinding('race-condition', 'medium');
      expect(result.vector).toContain('AC:H');
    });

    it('clickjacking base score is 4.3', () => {
      const result = getCvssForFinding('clickjacking', 'medium');
      expect(result.score).toBe(4.3);
    });
  });
});

/**
 * Vulnerability Chain Detection
 *
 * Analyzes raw findings for combinations that form attack chains
 * with higher real-world impact than individual findings.
 */

import type { RawFinding, CheckCategory } from '../types.js';

export interface VulnChain {
  name: string;
  severity: 'critical' | 'high';
  description: string;
  components: string[]; // finding IDs
  impact: string;
}

interface ChainRule {
  name: string;
  severity: 'critical' | 'high';
  description: string;
  impact: string;
  /** Return matching finding IDs if chain conditions are met, or null if not */
  match(findings: RawFinding[]): string[] | null;
}

/**
 * Check if two findings share the same domain.
 */
function sameDomain(a: RawFinding, b: RawFinding): boolean {
  try {
    const domainA = new URL(a.url).hostname;
    const domainB = new URL(b.url).hostname;
    return domainA === domainB;
  } catch {
    return false;
  }
}

/**
 * Find findings by category.
 */
function findByCategory(findings: RawFinding[], category: CheckCategory): RawFinding[] {
  return findings.filter((f) => f.category === category);
}

const CHAIN_RULES: ChainRule[] = [
  // 1. Open Redirect + SSRF = Internal SSRF
  {
    name: 'Open Redirect + SSRF → Internal SSRF',
    severity: 'critical',
    description:
      'An open redirect can be chained with SSRF to bypass URL allowlists and access internal services. ' +
      'The attacker uses the open redirect as a trusted hop to redirect SSRF requests to internal endpoints.',
    impact:
      'Access to internal services, cloud metadata endpoints, and internal APIs that should not be externally reachable.',
    match(findings) {
      const redirects = findByCategory(findings, 'open-redirect');
      const ssrfs = findByCategory(findings, 'ssrf');
      if (redirects.length === 0 || ssrfs.length === 0) return null;

      // Find pairs on the same domain
      for (const redirect of redirects) {
        for (const ssrf of ssrfs) {
          if (sameDomain(redirect, ssrf)) {
            return [redirect.id, ssrf.id];
          }
        }
      }
      // Even if different domains in same scan scope, the chain is still viable
      return [redirects[0].id, ssrfs[0].id];
    },
  },

  // 2. XSS + CSRF = Account Takeover
  {
    name: 'XSS + Missing CSRF Protection → Account Takeover',
    severity: 'critical',
    description:
      'Cross-site scripting combined with missing CSRF protection enables full account takeover. ' +
      'An attacker can use XSS to execute arbitrary actions as the victim without CSRF token validation.',
    impact:
      'Full account takeover — attacker can change passwords, email, and perform privileged actions as the victim.',
    match(findings) {
      const xssFindings = findByCategory(findings, 'xss');
      if (xssFindings.length === 0) return null;

      // Look for CSRF-related findings in security headers or cookie flags
      const csrfMissing = findings.filter(
        (f) =>
          (f.category === 'security-headers' || f.category === 'cookie-flags') &&
          /csrf|samesite|cross-site/i.test(f.title + ' ' + f.description),
      );

      if (csrfMissing.length === 0) return null;
      return [xssFindings[0].id, csrfMissing[0].id];
    },
  },

  // 3. Info Disclosure + IDOR = Data Breach
  {
    name: 'Information Disclosure + IDOR → Data Breach',
    severity: 'critical',
    description:
      'Exposed sensitive information combined with insecure direct object references enables mass data extraction. ' +
      'The disclosed information (e.g., internal IDs, user enumeration) can be used to systematically exploit IDOR.',
    impact:
      'Mass data breach — attacker can enumerate and access all user records, personal data, and business information.',
    match(findings) {
      const infoDisclosure = [
        ...findByCategory(findings, 'info-disclosure'),
        ...findByCategory(findings, 'info-leakage'),
      ];
      const idors = findByCategory(findings, 'idor');
      if (infoDisclosure.length === 0 || idors.length === 0) return null;
      return [infoDisclosure[0].id, idors[0].id];
    },
  },

  // 4. CORS + XSS = Cross-Origin Data Theft
  {
    name: 'CORS Misconfiguration + XSS → Cross-Origin Data Theft',
    severity: 'high',
    description:
      'A CORS misconfiguration combined with XSS allows an attacker to steal data cross-origin. ' +
      'The XSS can be used to make authenticated requests to the misconfigured CORS endpoint and exfiltrate data.',
    impact:
      'Cross-origin data theft — attacker can read sensitive API responses, user data, and tokens from other origins.',
    match(findings) {
      const cors = findByCategory(findings, 'cors-misconfiguration');
      const xss = findByCategory(findings, 'xss');
      if (cors.length === 0 || xss.length === 0) return null;
      return [cors[0].id, xss[0].id];
    },
  },

  // 5. JWT Weak Secret + Missing Rate Limit = Auth Bypass
  {
    name: 'JWT Weak Secret + Missing Rate Limit → Authentication Bypass',
    severity: 'critical',
    description:
      'A JWT signed with a weak/guessable secret combined with missing rate limiting enables authentication bypass. ' +
      'Without rate limiting, the attacker can brute-force the JWT secret and forge tokens for any user.',
    impact:
      'Full authentication bypass — attacker can forge JWT tokens for any user including administrators.',
    match(findings) {
      const jwtFindings = findByCategory(findings, 'jwt');
      const rateLimitFindings = findByCategory(findings, 'rate-limit');
      if (jwtFindings.length === 0 || rateLimitFindings.length === 0) return null;

      // JWT finding should mention weak secret specifically
      const weakJwt = jwtFindings.find(
        (f) => /weak.*(secret|key|sign)|none.*alg|algorithm/i.test(f.title + ' ' + f.description),
      );
      if (!weakJwt) return null;

      return [weakJwt.id, rateLimitFindings[0].id];
    },
  },
];

/**
 * Detect vulnerability chains from a set of raw findings.
 *
 * Should be called after deduplication and before AI validation.
 * Returns chains where multiple findings combine for greater impact.
 */
export function detectChains(findings: RawFinding[]): VulnChain[] {
  const chains: VulnChain[] = [];

  for (const rule of CHAIN_RULES) {
    const componentIds = rule.match(findings);
    if (componentIds) {
      chains.push({
        name: rule.name,
        severity: rule.severity,
        description: rule.description,
        components: componentIds,
        impact: rule.impact,
      });
    }
  }

  return chains;
}

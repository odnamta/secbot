import type { CheckCategory, Severity } from '../scanner/types.js';

/**
 * CVSS 3.1 base score mapping for all SecBot check categories.
 *
 * Each entry contains the CVSS vector string and pre-computed base score
 * for the "worst-case" variant of that vulnerability class. The score
 * is then adjusted downward when the finding's actual severity is lower
 * than the vector implies.
 *
 * Vector components:
 *   AV  = Attack Vector (N=Network)
 *   AC  = Attack Complexity (L=Low, H=High)
 *   PR  = Privileges Required (N=None, L=Low, H=High)
 *   UI  = User Interaction (N=None, R=Required)
 *   S   = Scope (U=Unchanged, C=Changed)
 *   C/I/A = Confidentiality / Integrity / Availability (N/L/H)
 */

export interface CvssResult {
  vector: string;
  score: number;
  /** Human-readable CVSS severity label */
  rating: 'Critical' | 'High' | 'Medium' | 'Low' | 'None';
}

interface CvssEntry {
  vector: string;
  score: number;
}

const CVSS_VECTORS: Record<CheckCategory, CvssEntry> = {
  // ─── Active checks (high impact) ───────────────────────────────
  'xss': {
    // Reflected XSS: user interaction required, scope changed (browser context)
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    score: 6.1,
  },
  'sqli': {
    // SQL injection: full DB compromise possible
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8,
  },
  'ssrf': {
    // SSRF: network-level access from server, scope changed
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    score: 8.6,
  },
  'ssti': {
    // Server-Side Template Injection: often leads to RCE
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8,
  },
  'command-injection': {
    // OS command injection: full system compromise
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8,
  },
  'directory-traversal': {
    // Path traversal: read arbitrary files
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    score: 7.5,
  },
  'open-redirect': {
    // Open redirect: phishing enabler, low direct impact
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    score: 6.1,
  },
  'cors-misconfiguration': {
    // CORS misconfiguration: credential theft via cross-origin
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N',
    score: 7.4,
  },
  'idor': {
    // Insecure Direct Object Reference: unauthorized data access
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    score: 8.1,
  },
  'crlf-injection': {
    // CRLF injection / HTTP response splitting
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    score: 6.1,
  },
  'jwt': {
    // JWT security issues: authentication bypass
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    score: 9.1,
  },
  'race-condition': {
    // Race condition / TOCTOU: high attack complexity
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N',
    score: 5.9,
  },
  'graphql': {
    // GraphQL introspection / depth abuse: info disclosure + DoS
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L',
    score: 6.5,
  },
  'host-header': {
    // Host header injection: cache poisoning / password reset
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
    score: 6.5,
  },
  'file-upload': {
    // Unrestricted file upload: can lead to RCE
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    score: 8.8,
  },
  'broken-access-control': {
    // Broken access control: unauthorized actions
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    score: 8.1,
  },
  'business-logic': {
    // Business logic flaws: varies widely, moderate default
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
    score: 7.5,
  },
  'websocket': {
    // WebSocket security: auth bypass + injection
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    score: 6.5,
  },
  'subdomain-takeover': {
    // Subdomain takeover: full control of subdomain
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N',
    score: 7.2,
  },
  'oauth': {
    // OAuth misconfiguration: account takeover
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
    score: 9.3,
  },
  'cache-poisoning': {
    // Web cache poisoning: deliver malicious content to users
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
    score: 7.5,
  },
  'csrf': {
    // Cross-Site Request Forgery: state-changing actions
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
    score: 6.5,
  },
  'prototype-pollution': {
    // Prototype pollution: can lead to XSS or RCE
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    score: 7.3,
  },
  'xxe': {
    // XML External Entity: file read, SSRF, DoS
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H',
    score: 9.1,
  },
  'insecure-deserialization': {
    // Insecure deserialization: often leads to RCE
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8,
  },
  'request-smuggling': {
    // HTTP request smuggling: high complexity, high impact
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N',
    score: 8.7,
  },
  'ldap-injection': {
    // LDAP injection: auth bypass + data exfiltration
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    score: 9.1,
  },
  'clickjacking': {
    // Clickjacking / UI redressing: user interaction required
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
    score: 4.3,
  },

  // ─── Passive checks (lower impact) ─────────────────────────────
  'security-headers': {
    // Missing security headers: defense-in-depth
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    score: 5.3,
  },
  'cookie-flags': {
    // Insecure cookie flags: session exposure
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
  },
  'info-leakage': {
    // Information leakage in headers/responses
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
  },
  'mixed-content': {
    // Mixed content: MITM downgrade
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
    score: 4.2,
  },
  'sensitive-url-data': {
    // Sensitive data in URL parameters
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
  },
  'cross-origin-policy': {
    // Cross-origin policy issues (COOP/COEP/CORP)
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    score: 5.3,
  },

  // ─── Other active checks ──────────────────────────────────────
  'tls': {
    // TLS/crypto weaknesses
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    score: 5.9,
  },
  'sri': {
    // Missing Subresource Integrity
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
    score: 4.2,
  },
  'info-disclosure': {
    // Information disclosure (exposed .git, .env, source maps)
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    score: 7.5,
  },
  'js-cve': {
    // Known JS library CVEs: varies, moderate default
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    score: 6.5,
  },
  'rate-limit': {
    // Missing rate limiting: brute-force enabler
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
  },
  'api-versioning': {
    // Deprecated API versions exposed
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3,
  },

  // ─── Meta ──────────────────────────────────────────────────────
  'vuln-chain': {
    // Vulnerability chain: combined impact, high by nature
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    score: 10.0,
  },
};

/** Severity floor/ceiling ranges for CVSS score adjustment */
const SEVERITY_RANGES: Record<Severity, { min: number; max: number }> = {
  critical: { min: 9.0, max: 10.0 },
  high:     { min: 7.0, max: 8.9 },
  medium:   { min: 4.0, max: 6.9 },
  low:      { min: 0.1, max: 3.9 },
  info:     { min: 0.0, max: 0.0 },
};

/**
 * Map a CVSS numeric score to its qualitative rating.
 */
function scoreToRating(score: number): CvssResult['rating'] {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0.0) return 'Low';
  return 'None';
}

/**
 * Get CVSS 3.1 base score for a finding based on its check category and severity.
 *
 * The base vector comes from the category mapping. If the finding's severity
 * is lower than what the base score implies (e.g., base is 9.8 but severity
 * is 'medium'), the score is clamped into the severity's expected range.
 *
 * This ensures CVSS scores are consistent with the severity labels assigned
 * by the AI validator.
 */
export function getCvssForFinding(category: CheckCategory, severity: Severity): CvssResult {
  const entry = CVSS_VECTORS[category];
  if (!entry) {
    // Fallback for unknown categories
    return {
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
      score: 5.3,
      rating: 'Medium',
    };
  }

  // Info severity always returns 0.0
  if (severity === 'info') {
    return {
      vector: entry.vector,
      score: 0.0,
      rating: 'None',
    };
  }

  const range = SEVERITY_RANGES[severity];
  let adjustedScore = entry.score;

  // If the base score is above the severity's ceiling, clamp it down
  if (adjustedScore > range.max) {
    adjustedScore = range.max;
  }

  // If the base score is below the severity's floor, bring it up
  if (adjustedScore < range.min) {
    adjustedScore = range.min;
  }

  // Round to one decimal place
  adjustedScore = Math.round(adjustedScore * 10) / 10;

  return {
    vector: entry.vector,
    score: adjustedScore,
    rating: scoreToRating(adjustedScore),
  };
}

/**
 * Infer a CheckCategory from an InterpretedFinding's title.
 * Used when only an InterpretedFinding is available (no raw finding category).
 */
export function inferCategoryFromTitle(title: string): CheckCategory {
  const t = title.toLowerCase();

  // vuln-chain must be checked early — titles like "Vulnerability Chain: redirect + SSRF"
  // would otherwise match ssrf or open-redirect
  if (t.includes('vuln') && t.includes('chain')) return 'vuln-chain';

  // xpath must be checked before directory-traversal (contains "path")
  if (t.includes('xpath')) return 'sqli'; // xpath-injection maps to sqli category

  if (t.includes('xss') || t.includes('cross-site scripting')) return 'xss';
  if (t.includes('sqli') || t.includes('sql injection') || t.includes('sql ')) return 'sqli';
  if (t.includes('command injection') || t.includes('cmdi') || t.includes('os injection')) return 'command-injection';
  if (t.includes('ssrf') || t.includes('server-side request')) return 'ssrf';
  if (t.includes('ssti') || t.includes('template injection')) return 'ssti';
  if (t.includes('cors')) return 'cors-misconfiguration';
  if (t.includes('open redirect') || t.includes('url redirect')) return 'open-redirect';
  if (t.includes('traversal') || t.includes('path ') || t.includes('lfi') || t.includes('directory traversal')) return 'directory-traversal';
  if (t.includes('csrf') || t.includes('cross-site request forgery') || t.includes('content-type confusion')) return 'csrf';
  if (t.includes('idor') || t.includes('insecure direct object')) return 'idor';
  if (t.includes('jwt') || t.includes('json web token')) return 'jwt';
  if (t.includes('race condition') || t.includes('toctou')) return 'race-condition';
  if (t.includes('graphql')) return 'graphql';
  if (t.includes('crlf') || t.includes('header injection') || t.includes('response splitting') || t.includes('email injection') || t.includes('smtp')) return 'crlf-injection';
  if (t.includes('host header')) return 'host-header';
  if (t.includes('file upload')) return 'file-upload';
  if (t.includes('access control') || t.includes('authorization') || t.includes('bfla') || t.includes('mass assignment') || t.includes('method override')) return 'broken-access-control';
  if (t.includes('business logic') || t.includes('price') || t.includes('workflow')) return 'business-logic';
  if (t.includes('websocket')) return 'websocket';
  if (t.includes('subdomain') || t.includes('takeover')) return 'subdomain-takeover';
  if (t.includes('oauth') || t.includes('openid')) return 'oauth';
  if (t.includes('cache poison')) return 'cache-poisoning';
  if (t.includes('prototype pollution')) return 'prototype-pollution';
  if (t.includes('xxe') || t.includes('xml external') || t.includes('xml entity')) return 'xxe';
  if (t.includes('deserialization')) return 'insecure-deserialization';
  if (t.includes('request smuggling')) return 'request-smuggling';
  if (t.includes('ldap')) return 'ldap-injection';
  if (t.includes('clickjack') || t.includes('ui redress')) return 'clickjacking';
  if (t.includes('timing') || t.includes('user enum') || t.includes('username enum') || t.includes('verbose error') || t.includes('debug mode') || t.includes('stack trace')) return 'info-disclosure';
  if (t.includes('sri') || t.includes('subresource integrity')) return 'sri';
  if (t.includes('tls') || t.includes('ssl') || t.includes('certificate')) return 'tls';
  if (t.includes('cve') || t.includes('vulnerable librar')) return 'js-cve';
  if (t.includes('rate limit') || t.includes('brute force')) return 'rate-limit';
  if (t.includes('api version') || t.includes('deprecated api')) return 'api-versioning';
  if (t.includes('info') && (t.includes('disclosure') || t.includes('leakage') || t.includes('exposed'))) return 'info-disclosure';
  if (t.includes('security header') || t.includes('hsts') || t.includes('csp') || t.includes('content-security')) return 'security-headers';
  if (t.includes('cookie')) return 'cookie-flags';
  if (t.includes('mixed content')) return 'mixed-content';
  if (t.includes('sensitive') && t.includes('url')) return 'sensitive-url-data';
  if (t.includes('cross-origin') && (t.includes('policy') || t.includes('opener') || t.includes('embedder'))) return 'cross-origin-policy';
  if (t.includes('vuln') && t.includes('chain')) return 'vuln-chain';

  // Default fallback
  return 'info-disclosure';
}

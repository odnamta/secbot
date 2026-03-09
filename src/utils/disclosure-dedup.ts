/**
 * Finding Dedup Against Public Disclosures
 *
 * Filters out findings that match known publicly disclosed vulnerabilities
 * or common "won't fix" patterns that bug bounty programs reject.
 * Prevents wasting time reporting known issues.
 */

import type { RawFinding } from '../scanner/types.js';
import { log } from './logger.js';

export interface DisclosureMatch {
  findingId: string;
  matchedRule: string;
  reason: string;
}

interface DisclosureRule {
  /** Rule identifier */
  id: string;
  /** Human-readable reason why this is a known/rejected finding */
  reason: string;
  /** Returns true if the finding matches this known disclosure pattern */
  matches(finding: RawFinding): boolean;
}

/**
 * Known disclosure patterns — findings that bounty programs commonly reject.
 *
 * Categories:
 * 1. Framework defaults that are "by design" (not bugs)
 * 2. Informational findings that have no security impact
 * 3. Known CVEs in vendor-maintained components (vendor responsibility)
 * 4. Common false positives from automated scanners
 */
const DISCLOSURE_RULES: DisclosureRule[] = [
  // ─── Framework Defaults (By Design) ──────────────────────
  {
    id: 'nextjs-powered-by',
    reason: 'Next.js X-Powered-By header is a framework default. Not a security issue — remove via next.config.js if desired.',
    matches: (f) =>
      f.category === 'security-headers' &&
      /x-powered-by.*next/i.test(f.title + ' ' + f.evidence),
  },
  {
    id: 'express-powered-by',
    reason: 'Express X-Powered-By header is a framework default. Informational only — disable via app.disable("x-powered-by").',
    matches: (f) =>
      f.category === 'security-headers' &&
      /x-powered-by.*express/i.test(f.title + ' ' + f.evidence),
  },
  {
    id: 'vercel-headers',
    reason: 'Vercel platform headers (x-vercel-id, x-vercel-cache) are infrastructure metadata. Not a vulnerability.',
    matches: (f) =>
      f.category === 'info-leakage' &&
      /x-vercel/i.test(f.evidence),
  },
  {
    id: 'cloudflare-headers',
    reason: 'Cloudflare headers (cf-ray, cf-cache-status) are CDN metadata. Not a vulnerability.',
    matches: (f) =>
      f.category === 'info-leakage' &&
      /cf-ray|cf-cache/i.test(f.evidence) &&
      !/credential|token|key|secret/i.test(f.evidence),
  },

  // ─── Low-Impact Informational Findings ───────────────────
  {
    id: 'missing-csp-static',
    reason: 'Missing CSP on static/marketing sites with no user input is informational. Most bounty programs reject this.',
    matches: (f) =>
      f.category === 'security-headers' &&
      /content-security-policy/i.test(f.title) &&
      f.severity === 'info',
  },
  {
    id: 'missing-hsts-non-production',
    reason: 'Missing HSTS on non-production (staging, dev, localhost) environments is expected and not a valid finding.',
    matches: (f) =>
      f.category === 'security-headers' &&
      /strict-transport/i.test(f.title) &&
      /(staging|dev|localhost|127\.0\.0\.1|\.local)/i.test(f.url),
  },
  {
    id: 'server-version-disclosure',
    reason: 'Server version disclosure alone is typically informational. Only impactful when combined with a known CVE for that version.',
    matches: (f) =>
      f.category === 'info-leakage' &&
      /server.*version|version.*disclosure/i.test(f.title) &&
      f.severity === 'info',
  },

  // ─── Common Scanner False Positives ──────────────────────
  {
    id: 'cors-same-origin',
    reason: 'CORS reflecting the same origin back is standard behavior, not a misconfiguration.',
    matches: (f) => {
      if (f.category !== 'cors-misconfiguration') return false;
      // If the evidence shows origin reflection of the same domain, it's not a vuln
      const evidenceLower = f.evidence.toLowerCase();
      try {
        const findingHost = new URL(f.url).hostname;
        return evidenceLower.includes(findingHost) && !evidenceLower.includes('null') && !evidenceLower.includes('*');
      } catch {
        return false;
      }
    },
  },
  {
    id: 'open-redirect-to-same-domain',
    reason: 'Redirect within the same domain/subdomain hierarchy is not an open redirect vulnerability.',
    matches: (f) => {
      if (f.category !== 'open-redirect') return false;
      // If redirect stays within same domain, not a vuln
      const evidenceLower = f.evidence.toLowerCase();
      try {
        const host = new URL(f.url).hostname.replace(/^www\./, '');
        return evidenceLower.includes(host) && !evidenceLower.includes('external') && !evidenceLower.includes('canary');
      } catch {
        return false;
      }
    },
  },
  {
    id: 'self-xss',
    reason: 'Self-XSS (only exploitable against yourself, e.g., in profile fields visible only to the author) is rejected by most bounty programs.',
    matches: (f) =>
      f.category === 'xss' &&
      /self[- ]?xss|own.*profile|visible.*only.*to/i.test(f.title + ' ' + f.description + ' ' + f.evidence),
  },
  {
    id: 'clickjacking-no-sensitive-action',
    reason: 'Clickjacking (missing X-Frame-Options) on pages without sensitive actions (static content, marketing pages) is rejected.',
    matches: (f) =>
      f.category === 'security-headers' &&
      /x-frame-options|frame-ancestors/i.test(f.title) &&
      f.severity === 'info',
  },

  // ─── Known "Won\'t Fix" Patterns ─────────────────────────
  {
    id: 'robots-txt-disclosure',
    reason: 'robots.txt is intentionally public. Listing disallowed paths is not information disclosure.',
    matches: (f) =>
      f.category === 'info-disclosure' &&
      /robots\.txt/i.test(f.title) &&
      f.severity === 'info',
  },
  {
    id: 'security-txt-present',
    reason: 'security.txt is a best practice (RFC 9116). Its presence is positive, not a finding.',
    matches: (f) =>
      f.category === 'info-disclosure' &&
      /security\.txt/i.test(f.title) &&
      f.severity === 'info',
  },
  {
    id: 'autocomplete-password',
    reason: 'Autocomplete on password fields is a browser feature. Modern guidance says disabling it reduces security (users pick weaker passwords).',
    matches: (f) =>
      /autocomplete.*password/i.test(f.title + ' ' + f.description) &&
      f.severity === 'info',
  },
];

/**
 * Check findings against known public disclosure patterns.
 *
 * Returns findings that should be suppressed (matched known disclosures)
 * and filtered findings (kept for reporting).
 */
export function deduplicateAgainstDisclosures(
  findings: RawFinding[],
): { filtered: RawFinding[]; suppressed: DisclosureMatch[] } {
  const suppressed: DisclosureMatch[] = [];
  const filtered: RawFinding[] = [];

  for (const finding of findings) {
    const matchedRule = DISCLOSURE_RULES.find((rule) => {
      try {
        return rule.matches(finding);
      } catch {
        return false;
      }
    });

    if (matchedRule) {
      suppressed.push({
        findingId: finding.id,
        matchedRule: matchedRule.id,
        reason: matchedRule.reason,
      });
      log.debug(`Suppressed "${finding.title}" — ${matchedRule.id}: ${matchedRule.reason}`);
    } else {
      filtered.push(finding);
    }
  }

  if (suppressed.length > 0) {
    log.info(`Disclosure dedup: ${suppressed.length} finding(s) matched known patterns, ${filtered.length} kept`);
  }

  return { filtered, suppressed };
}

/**
 * Get all registered disclosure rules (for documentation/debugging).
 */
export function getDisclosureRules(): { id: string; reason: string }[] {
  return DISCLOSURE_RULES.map((r) => ({ id: r.id, reason: r.reason }));
}

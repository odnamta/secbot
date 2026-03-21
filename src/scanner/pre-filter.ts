import type { RawFinding, Confidence } from './types.js';
import type { FPMemory } from '../learning/fp-memory.js';
import { log } from '../utils/logger.js';

const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
const DOWNGRADE_MAP: Record<Confidence, Confidence> = { high: 'medium', medium: 'low', low: 'low' };

export interface PreFilterResult {
  passed: RawFinding[];
  dropped: RawFinding[];
  downgraded: number;
}

/**
 * Heuristic rules that downgrade findings commonly rejected by bounty programs.
 * These run BEFORE confidence threshold filtering.
 */
function applyHeuristicDowngrades(finding: RawFinding): { downgrade: boolean; reason?: string } {
  const title = finding.title.toLowerCase();
  const category = finding.category;
  const evidence = (finding.evidence ?? '').toLowerCase();

  // 1. Cross-origin isolation headers are defense-in-depth, never accepted
  if (/cross-origin-(opener|embedder|resource)-policy/i.test(finding.title)) {
    return { downgrade: true, reason: 'cross-origin isolation header (defense-in-depth)' };
  }

  // 2. SRI on same-origin CDN (e.g., cdn.shopify.com for shopify.com) — low bounty potential
  if (category === 'sri' && finding.url) {
    try {
      const targetHost = new URL(finding.url).hostname.replace(/^www\./, '');
      // If evidence references resources from the same org's CDN, downgrade
      if (evidence.includes(`cdn.${targetHost}`) || evidence.includes(targetHost)) {
        return { downgrade: true, reason: 'SRI on same-organization CDN' };
      }
    } catch { /* ignore URL parse errors */ }
  }

  // 3. Cookie findings on marketing/tracking cookies — always low priority
  if (category === 'cookie-flags' && title.includes('cookie')) {
    const cookieMatch = title.match(/cookie\s+"([^"]+)"/i);
    if (cookieMatch) {
      const cookieName = cookieMatch[1];
      // Third-party analytics/marketing cookies + consent + tracking
      if (/^(_ga|_gid|_gat|_gcl|_fbp|_fbc|__utm|_mkto_|_biz|mto_|_vwo|_vis_opt|_sp_id|_sp_ses|OptanonConsent|OptanonAlertBoxClosed|g_state|FPLC|FPID|_hj|_clck|_clsk|hubspot|__hs|__hssc|__hssrc|intercom|amplitude|mp_|fs_uid|loglevel|_tt_|li_|bcookie|NID|ab\.|_pin_|_hp2_|notice_|consent|cookie_?consent|TAsessionID|TA_|_lo_|_lorid|drift|driftt_|_gd_|_an_uid|country|timezone|region|language|locale|lang|_dc_|__dc|_parsely|__cfduid|_pk_|sc_anonymous|_ce\.|_stid|_derived_epik|pxcts|_pxvid|datadome|__zlcmid|_uetsid|_uetvid|_scid|_sctr|lastExternalReferrer)/i.test(cookieName)) {
        return { downgrade: true, reason: `third-party cookie "${cookieName}"` };
      }
    }
  }

  // 4. Missing CSP on static/marketing pages (no interactive forms, no user data)
  if (title.includes('content-security-policy') && title.includes('missing')) {
    // Marketing locale pages like /id, /en, /fr
    if (finding.url && /\/[a-z]{2}(-[a-z]{2})?\/?(\?.*)?$/i.test(new URL(finding.url).pathname)) {
      return { downgrade: true, reason: 'missing CSP on locale/marketing page' };
    }
  }

  // 5. CORS on non-functional endpoints with no useful response
  if (category === 'cors-misconfiguration') {
    const statusMatch = evidence.match(/http\/?\s*(\d{3})/i) ?? evidence.match(/status[:\s]+(\d{3})/i);
    if (statusMatch) {
      const status = parseInt(statusMatch[1], 10);
      if (status === 405 || status === 404 || status === 403) {
        return { downgrade: true, reason: `CORS on ${status} endpoint (non-functional)` };
      }
    }
  }

  // 6. OPTIONS method allowed on public endpoints — bounty programs don't consider
  //    OPTIONS exposure as a vulnerability since it's required for CORS preflight
  if (category === 'broken-access-control' && /options/i.test(evidence)) {
    // Only downgrade if the finding is exclusively about OPTIONS method
    const methodMentions = evidence.match(/\b(GET|POST|PUT|DELETE|PATCH|TRACE|CONNECT)\b/gi);
    if (!methodMentions || methodMentions.length === 0) {
      return { downgrade: true, reason: 'OPTIONS-only method exposure (CORS preflight, not exploitable)' };
    }
  }

  // 7. Missing CSP/headers on error pages — error pages are not interactive,
  //    bounty programs consistently reject header findings on 404/500/error pages
  if (category === 'security-headers' && finding.url) {
    try {
      const urlPath = new URL(finding.url).pathname.toLowerCase();
      if (/\/(404|500|error|not-found|not_found)\b/.test(urlPath)) {
        return { downgrade: true, reason: 'missing headers on error page (non-interactive)' };
      }
    } catch { /* ignore URL parse errors */ }
  }

  // 8. CORS wildcard on non-authenticated endpoints — Access-Control-Allow-Origin: *
  //    is safe when the endpoint returns no user-specific data (401/403 = no session)
  if (category === 'cors-misconfiguration') {
    const hasWildcard = evidence.includes('*') || evidence.includes('wildcard');
    if (hasWildcard) {
      const status401or403 = /\b(401|403)\b/.test(evidence) || /unauthorized|forbidden/i.test(evidence);
      const noUserData = /no\s+user\s+data|empty\s+body|content-length:\s*0/i.test(evidence);
      if (status401or403 || noUserData) {
        return { downgrade: true, reason: 'CORS wildcard on non-authenticated endpoint (no user data exposure)' };
      }
    }
  }

  // 9. Missing HSTS on staging/preview/dev domains — non-production environments
  //    are explicitly out of scope or low priority for all major bounty platforms
  if (category === 'security-headers' && /hsts|strict-transport-security/i.test(title)) {
    if (finding.url) {
      try {
        const hostname = new URL(finding.url).hostname.toLowerCase();
        if (/\b(staging|preview|dev|test|sandbox|demo)\b/.test(hostname) ||
            hostname.startsWith('staging.') || hostname.startsWith('preview.') ||
            hostname.startsWith('dev.') || hostname.startsWith('test.') ||
            hostname.startsWith('sandbox.') || hostname.startsWith('demo.')) {
          return { downgrade: true, reason: 'missing HSTS on non-production domain' };
        }
      } catch { /* ignore URL parse errors */ }
    }
  }

  // 10. Localhost-only CORS — allowing localhost/127.0.0.1 origins is not exploitable
  //     in production; bounty programs reject these as development artifacts
  if (category === 'cors-misconfiguration') {
    if (/localhost|127\.0\.0\.1/i.test(evidence) && !/reflect/i.test(evidence)) {
      return { downgrade: true, reason: 'CORS allows localhost only (not exploitable in production)' };
    }
  }

  // 11. X-XSS-Protection informational — this header is deprecated and ignored by
  //     modern browsers; bounty programs treat it as informational, never accepted
  if (/x-xss-protection/i.test(title) || /x-xss-protection/i.test(evidence)) {
    return { downgrade: true, reason: 'X-XSS-Protection is deprecated (informational only)' };
  }

  // 12. Missing visual headers on API-only endpoints — X-Frame-Options and CSP
  //     protect against UI-based attacks; APIs don't render HTML so these are noise
  if (category === 'security-headers' && finding.url) {
    try {
      const urlPath = new URL(finding.url).pathname.toLowerCase();
      if (/^\/api(\/|$)/.test(urlPath)) {
        if (/x-frame-options|content-security-policy|frame-options/i.test(title)) {
          return { downgrade: true, reason: 'missing visual headers on API endpoint (no HTML rendering)' };
        }
      }
    } catch { /* ignore URL parse errors */ }
  }

  // 13. Info-disclosure on dev/staging URLs — dev environments intentionally expose
  //     debug info; bounty programs exclude non-production assets from scope
  if (category === 'info-disclosure' && finding.url) {
    try {
      const hostname = new URL(finding.url).hostname.toLowerCase();
      if (/\b(dev|staging|test|sandbox)\b/.test(hostname) ||
          hostname.startsWith('dev.') || hostname.startsWith('staging.') ||
          hostname.startsWith('test.') || hostname.startsWith('sandbox.')) {
        return { downgrade: true, reason: 'info-disclosure on non-production domain' };
      }
    } catch { /* ignore URL parse errors */ }
  }

  // 14. SRI missing for first-party (same-origin) scripts — SRI protects against
  //     CDN compromise; same-origin scripts are already trusted, bounty programs reject
  if (category === 'sri' && finding.url && evidence) {
    try {
      const targetHost = new URL(finding.url).hostname.replace(/^www\./, '');
      // Check if all referenced scripts in the evidence are same-origin
      const scriptUrls = evidence.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
      if (scriptUrls.length > 0) {
        const allSameOrigin = scriptUrls.every(su => {
          try {
            const scriptHost = new URL(su).hostname.replace(/^www\./, '');
            return scriptHost === targetHost;
          } catch { return false; }
        });
        if (allSameOrigin) {
          return { downgrade: true, reason: 'SRI missing for same-origin scripts (not a CDN integrity risk)' };
        }
      }
    } catch { /* ignore URL parse errors */ }
  }

  // 15. Security-headers on CDN-managed targets (Vercel, Cloudflare) — these platforms
  //     inject standard security headers at the edge; missing headers in app code
  //     are covered by the CDN and bounty programs reject these as non-issues
  if (category === 'security-headers') {
    const responseHeaders = finding.response?.headers ?? {};
    const evidenceLower = evidence;
    const isVercelTarget = responseHeaders['server']?.includes('Vercel') ||
      responseHeaders['x-vercel-id'] !== undefined ||
      (finding.url && /\.vercel\.app\b/i.test(finding.url)) ||
      evidenceLower.includes('vercel');
    const isCloudflareTarget = responseHeaders['server']?.includes('cloudflare') ||
      responseHeaders['cf-ray'] !== undefined ||
      evidenceLower.includes('cloudflare');
    if (isVercelTarget || isCloudflareTarget) {
      return { downgrade: true, reason: `security-headers on CDN-managed target (${isVercelTarget ? 'Vercel' : 'Cloudflare'})` };
    }
  }

  // 16. Rate-limit missing on non-auth endpoints — bounty programs only care about
  //     rate limiting on auth/login/registration flows to prevent brute-force
  if (category === 'rate-limit' && finding.url) {
    try {
      const urlLower = new URL(finding.url).pathname.toLowerCase() + new URL(finding.url).search.toLowerCase();
      if (!/\b(auth|login|log-in|signin|sign-in|register|signup|sign-up|password|forgot|reset|otp|verify|mfa|2fa)\b/.test(urlLower)) {
        return { downgrade: true, reason: 'rate-limit missing on non-auth endpoint (low bounty impact)' };
      }
    } catch { /* ignore URL parse errors */ }
  }

  return { downgrade: false };
}

export function preFilterFindings(
  findings: RawFinding[],
  minConfidence: Confidence = 'medium',
  fpMemory?: FPMemory,
): PreFilterResult {
  const threshold = CONFIDENCE_ORDER[minConfidence];
  const passed: RawFinding[] = [];
  const dropped: RawFinding[] = [];
  let downgraded = 0;
  for (const f of findings) {
    let confidence = (f.confidence as Confidence) ?? 'medium';

    // Apply heuristic downgrades for bounty-program noise
    const heuristic = applyHeuristicDowngrades(f);
    if (heuristic.downgrade) {
      confidence = DOWNGRADE_MAP[confidence];
      f.confidence = confidence;
      downgraded++;
      log.debug(`Pre-filter downgraded: "${f.title}" — ${heuristic.reason}`);
    }

    // Downgrade confidence if finding matches a known false positive pattern
    if (fpMemory) {
      const adjustment = fpMemory.confidenceAdjustment(f.category, f.title);
      if (adjustment === 'downgrade') {
        confidence = DOWNGRADE_MAP[confidence];
        f.confidence = confidence;
        downgraded++;
      }
    }

    const level = CONFIDENCE_ORDER[confidence];
    if (level >= threshold) {
      passed.push(f);
    } else {
      dropped.push(f);
    }
  }
  return { passed, dropped, downgraded };
}

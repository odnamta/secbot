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

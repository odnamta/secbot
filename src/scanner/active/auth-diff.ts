import { randomUUID } from 'node:crypto';
import { chromium, type BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/**
 * Two-User Authorization Testing (Auth Diff) — CWE-639, CWE-284, OWASP A01:2021.
 *
 * The #1 accepted bug bounty finding type: privilege escalation via
 * broken authorization between users.
 *
 * Requires --auth (User A) and --idor-alt-auth (User B).
 * 1. Collects all authenticated API responses from User A's crawl
 * 2. Replays each request as User B
 * 3. Compares: if User B gets the same data, broken access control confirmed
 *
 * Unlike the IDOR check (which tests sequential/guessable IDs), auth-diff tests
 * every API endpoint for cross-user data leakage regardless of ID format.
 */

/** Response fields that indicate user-specific data (not public/generic content) */
const USER_DATA_RE = /["'](?:email|name|first_?name|last_?name|phone|address|account|balance|order|payment|credit|ssn|dob|birth|salary|password|secret|token|api_?key|private|personal|profile|social_?security|bank|routing|card_?number|cvv|expir)["']\s*:/i;

/** Response fields indicating the response identifies a specific user/account */
const IDENTITY_RE = /["'](?:user_?id|account_?id|owner|created_?by|author|member_?id|customer_?id|tenant_?id|org_?id)["']\s*:/i;

/** Shared/public content that is the same for all users (not an authz issue) */
const PUBLIC_CONTENT_RE = /["'](?:version|status|healthcheck|ping|csrf|nonce|locale|language|currency|timezone)["']\s*:/i;

/** Static asset extensions to skip */
const STATIC_ASSET_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|mp[34]|webm)(\?|$)/i;

/**
 * Compare two response bodies for similarity using Jaccard coefficient on JSON keys.
 * Returns a value between 0 (completely different) and 1 (identical keys).
 * High similarity + user-specific data = broken access control.
 */
export function jsonKeySimilarity(bodyA: string, bodyB: string): number {
  try {
    const objA = JSON.parse(bodyA);
    const objB = JSON.parse(bodyB);
    const keysA = new Set(flattenKeys(objA));
    const keysB = new Set(flattenKeys(objB));
    if (keysA.size === 0 && keysB.size === 0) return 0;
    const intersection = [...keysA].filter((k) => keysB.has(k)).length;
    const union = new Set([...keysA, ...keysB]).size;
    return union === 0 ? 0 : intersection / union;
  } catch {
    // Not valid JSON — fall back to length-based heuristic
    if (bodyA.length === 0 || bodyB.length === 0) return 0;
    const ratio = Math.min(bodyA.length, bodyB.length) / Math.max(bodyA.length, bodyB.length);
    return ratio > 0.8 ? ratio : 0;
  }
}

/** Recursively extract all keys from a JSON object (dot-notation paths) */
function flattenKeys(obj: unknown, prefix = ''): string[] {
  if (obj === null || obj === undefined) return [];
  if (Array.isArray(obj)) {
    if (obj.length === 0) return [prefix];
    // Sample first element only (arrays of objects share structure)
    return flattenKeys(obj[0], `${prefix}[]`);
  }
  if (typeof obj === 'object') {
    const keys: string[] = [];
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${key}` : key;
      keys.push(path);
      keys.push(...flattenKeys(value, path));
    }
    return keys;
  }
  return [prefix];
}

/**
 * Determine if a response likely contains user-specific (non-public) data.
 * Uses field-name heuristics on the response body.
 */
export function hasUserSpecificData(body: string): { isUserData: boolean; indicators: string[] } {
  const indicators: string[] = [];

  if (USER_DATA_RE.test(body)) {
    const match = body.match(USER_DATA_RE);
    if (match) indicators.push(`user-data field: ${match[0].slice(0, 40)}`);
  }
  if (IDENTITY_RE.test(body)) {
    const match = body.match(IDENTITY_RE);
    if (match) indicators.push(`identity field: ${match[0].slice(0, 40)}`);
  }

  // If response is mostly public/generic content with no user fields, skip
  if (indicators.length === 0 && PUBLIC_CONTENT_RE.test(body)) {
    return { isUserData: false, indicators: [] };
  }

  return { isUserData: indicators.length > 0, indicators };
}

export const authDiffCheck: ActiveCheck = {
  name: 'auth-diff',
  category: 'broken-access-control',
  parallel: false, // launches a separate browser, mutates state

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    // ── Gate: requires two auth states ──────────────────────────────────
    if (!config.authStorageState || !config.idorAltAuthState) {
      log.debug('auth-diff: requires --auth + --idor-alt-auth — skipping');
      return findings;
    }

    // ── Collect User A's authenticated API endpoints ────────────────────
    const apiUrls = targets.apiEndpoints.filter((url) => !STATIC_ASSET_RE.test(url));

    if (apiUrls.length === 0) {
      log.debug('auth-diff: no API endpoints to test');
      return findings;
    }

    const limit = config.profile === 'deep' ? 30 : 15;
    const urlsToTest = apiUrls.slice(0, limit);

    log.info(`Auth diff: testing ${urlsToTest.length} endpoints for cross-user access control bypass`);

    // ── Fetch User A baselines ──────────────────────────────────────────
    // We need User A's responses to compare against User B's
    const userAResponses = new Map<string, { status: number; body: string }>();

    for (const url of urlsToTest) {
      const page = await context.newPage();
      try {
        const resp = await page.request.fetch(url, { timeout: config.timeout });
        const status = resp.status();
        const body = await resp.text();
        if (status === 200 && body.length > 50) {
          userAResponses.set(url, { status, body });
        }
      } catch (err) {
        log.debug(`Auth diff User A fetch ${url}: ${(err as Error).message}`);
      } finally {
        await page.close();
      }
      await delay(config.requestDelay);
    }

    if (userAResponses.size === 0) {
      log.info('Auth diff: no 200 responses from User A — nothing to compare');
      return findings;
    }

    log.info(`Auth diff: captured ${userAResponses.size} User A responses, replaying as User B`);

    // ── Create User B context ───────────────────────────────────────────
    const altBrowser = await chromium.launch({ headless: true });
    const altContext = await altBrowser.newContext({
      storageState: config.idorAltAuthState,
    });

    try {
      for (const [url, userAResp] of userAResponses) {
        const page = await altContext.newPage();
        try {
          // Request as User B
          const resp = await page.request.fetch(url, { timeout: config.timeout });
          const status = resp.status();
          const body = await resp.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url,
            responseStatus: status,
            phase: 'active-auth-diff',
          });

          // ── Analysis ────────────────────────────────────────────────
          // 403/401 = proper authorization, skip
          if (status === 401 || status === 403) continue;

          // 404/500 = endpoint not reachable for User B, skip
          if (status >= 400) continue;

          // User B got a 200 — compare with User A's response
          if (status === 200 && body.length > 50) {
            const { isUserData, indicators } = hasUserSpecificData(body);
            const similarity = jsonKeySimilarity(userAResp.body, body);

            // High similarity + user-specific data = broken access control
            const isVulnerable = isUserData && similarity > 0.7;

            // Also flag: identical response bodies (User B gets exact same data)
            const isIdentical = body === userAResp.body && body.length > 100;

            if (isVulnerable || isIdentical) {
              const confidence = isIdentical ? 'high' as const
                : (similarity > 0.9 && indicators.length >= 2) ? 'high' as const
                : 'medium' as const;

              const severity = confidence === 'high' ? 'high' as const : 'medium' as const;

              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity,
                title: `Broken Access Control — User B can access User A's endpoint`,
                description:
                  `Endpoint ${url} returns user-specific data (${body.length} bytes) when accessed ` +
                  `with a different user's credentials. ` +
                  `Response similarity: ${(similarity * 100).toFixed(0)}%. ` +
                  (isIdentical ? 'Responses are byte-identical. ' : '') +
                  `Indicators: ${indicators.join(', ') || 'identical response body'}.`,
                url,
                evidence:
                  `User A status: ${userAResp.status}, body: ${userAResp.body.length} bytes\n` +
                  `User B status: ${status}, body: ${body.length} bytes\n` +
                  `Similarity: ${(similarity * 100).toFixed(0)}%\n` +
                  `User data indicators: ${indicators.join(', ') || 'identical body'}`,
                request: { method: 'GET', url },
                response: { status, bodySnippet: body.slice(0, 500) },
                timestamp: new Date().toISOString(),
                confidence,
                evidencePack: {
                  detectionMethod: 'auth-diff',
                  responseIndicators: indicators,
                  curlCommand: `curl -b "USER_B_COOKIES" "${url}"`,
                },
              });
            }
          }
        } catch (err) {
          log.debug(`Auth diff User B fetch ${url}: ${(err as Error).message}`);
        } finally {
          await page.close();
        }
        await delay(config.requestDelay);
      }
    } finally {
      await altContext.close();
      await altBrowser.close();
    }

    if (findings.length > 0) {
      log.info(`Auth diff: ${findings.length} broken access control finding(s)`);
    } else {
      log.info('Auth diff: all endpoints properly enforce user-level authorization');
    }

    return findings;
  },
};

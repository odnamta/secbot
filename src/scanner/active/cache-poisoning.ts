import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { randomUUID } from 'node:crypto';
import type { RequestLogger } from '../../utils/request-logger.js';
import { log } from '../../utils/logger.js';

const CACHE_HEADERS = ['x-cache', 'cf-cache-status', 'age', 'x-varnish', 'x-cache-hit', 'x-cdn-cache', 'x-proxy-cache'];

const UNKEYED_HEADERS = [
  { name: 'X-Forwarded-Host', value: 'secbot-cache-test.example.com' },
  { name: 'X-Forwarded-Scheme', value: 'nothttps' },
  { name: 'X-Original-URL', value: '/secbot-cache-test' },
  { name: 'X-Rewrite-URL', value: '/secbot-cache-test' },
  { name: 'X-Forwarded-Port', value: '1337' },
  { name: 'X-Host', value: 'secbot-cache-test.example.com' },
];

export function detectCaching(headers: Record<string, string>): boolean {
  const lowerHeaders = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  );
  return CACHE_HEADERS.some(h => h in lowerHeaders);
}

export function isCacheHit(headers: Record<string, string>): boolean {
  const lower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );
  return (lower['x-cache'] === 'hit') ||
         (lower['cf-cache-status'] === 'hit') ||
         (lower['x-cache-hit'] === 'true') ||
         (parseInt(lower['age'] || '0', 10) > 0);
}

export const cachePoisoningCheck: ActiveCheck = {
  name: 'cache-poisoning',
  category: 'cache-poisoning',
  parallel: true,
  async run(_context: BrowserContext, targets: ScanTargets, config: ScanConfig, _requestLogger?: RequestLogger): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const testUrls = [...targets.pages, ...targets.apiEndpoints].slice(0, 10);

    for (const url of testUrls) {
      try {
        // Step 1: Check if page has caching
        const baseResp = await fetch(url, {
          signal: AbortSignal.timeout(config.timeout || 10000),
        });
        const baseHeaders = Object.fromEntries(baseResp.headers);

        if (!detectCaching(baseHeaders)) continue; // no cache = skip

        const baseBody = await baseResp.text();

        // Step 2: Try each unkeyed header
        for (const header of UNKEYED_HEADERS) {
          try {
            // Send request with poisoned header + cache-buster
            const cacheBuster = `cb=${Date.now()}-${randomUUID().slice(0, 8)}`;
            const poisonUrl = url.includes('?') ? `${url}&${cacheBuster}` : `${url}?${cacheBuster}`;

            const poisonResp = await fetch(poisonUrl, {
              headers: { [header.name]: header.value },
              signal: AbortSignal.timeout(config.timeout || 10000),
            });
            const poisonBody = await poisonResp.text();
            const poisonHeaders = Object.fromEntries(poisonResp.headers);

            // Check if the unkeyed header was reflected in the response
            if (poisonBody.includes(header.value) && !baseBody.includes(header.value)) {
              // Step 3: Verify the poisoned response is cached
              // Send clean request to same URL to see if poison was cached
              const verifyResp = await fetch(poisonUrl, {
                signal: AbortSignal.timeout(config.timeout || 10000),
              });
              const verifyBody = await verifyResp.text();
              const verifyHeaders = Object.fromEntries(verifyResp.headers);

              const poisonCached = verifyBody.includes(header.value) && isCacheHit(verifyHeaders);

              findings.push({
                id: randomUUID(),
                category: 'cache-poisoning',
                severity: poisonCached ? 'high' : 'medium',
                title: `Cache poisoning via ${header.name} on ${new URL(url).pathname}`,
                description: poisonCached
                  ? `The ${header.name} header is unkeyed by the cache and its value is reflected in the response. A poisoned response was confirmed to be served from cache to subsequent visitors.`
                  : `The ${header.name} header value is reflected in the response body but was not confirmed in cache. Manual verification recommended.`,
                url,
                evidence: `Header ${header.name}: ${header.value} reflected in response${poisonCached ? ' AND served from cache' : ''}`,
                request: { method: 'GET', url: poisonUrl, headers: { [header.name]: header.value } },
                response: { status: poisonResp.status, headers: poisonHeaders, bodySnippet: poisonBody.slice(0, 500) },
                timestamp: new Date().toISOString(),
                confidence: poisonCached ? 'high' : 'medium',
              });

              break; // Found poisoning on this URL, move to next
            }
          } catch { continue; }
        }
      } catch { continue; }
    }

    // Web Cache Deception (WCD) — test if user-specific pages can be cached
    // by appending static file extensions to dynamic URLs
    const wcdFindings = await testWebCacheDeception(targets, config);
    findings.push(...wcdFindings);

    return findings;
  },
};

// ─── Web Cache Deception ───────────────────────────────────────────────

/** Path suffixes that trick CDNs into caching dynamic pages as static assets */
export const WCD_SUFFIXES = [
  '/nonexistent.css',
  '/nonexistent.js',
  '/nonexistent.png',
  '/nonexistent.svg',
  '/.css',
  '/..%2fnonexistent.css',     // Path traversal normalization
  '%2f.css',                    // Encoded slash
  '%3b.css',                    // Semicolon path param (Tomcat/Spring)
  '/;a.css',                    // Semicolon matrix param
];

/** Indicators that a response contains user-specific content (not a generic page) */
const USER_CONTENT_PATTERNS = [
  /logout/i, /sign.?out/i, /my.?account/i, /profile/i,
  /dashboard/i, /settings/i, /billing/i, /email["':]/i,
  /username["':]/i, /csrf[_-]?token/i, /api[_-]?key/i,
];

function containsUserContent(body: string): boolean {
  return USER_CONTENT_PATTERNS.some(p => p.test(body));
}

async function testWebCacheDeception(
  targets: ScanTargets,
  config: ScanConfig,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Only test pages that might have user-specific content
  // Prefer authenticated pages, account pages, dashboard pages
  const candidatePages = targets.pages.filter(url => {
    const path = new URL(url).pathname.toLowerCase();
    return /\/(account|profile|dashboard|settings|user|me|billing|admin|my)/i.test(path);
  });

  // Also test the home page — many SPAs serve user content on /
  if (targets.pages.length > 0 && candidatePages.length === 0) {
    candidatePages.push(targets.pages[0]);
  }

  const testPages = candidatePages.slice(0, 5);
  if (testPages.length === 0) return findings;

  log.info(`Web Cache Deception: testing ${testPages.length} candidate page(s)...`);

  for (const url of testPages) {
    try {
      // Step 1: Fetch the original page
      const baseResp = await fetch(url, {
        signal: AbortSignal.timeout(config.timeout || 10000),
      });
      const baseBody = await baseResp.text();
      const baseHeaders = Object.fromEntries(baseResp.headers);

      // Only interesting if the page contains user-specific content
      const hasUserContent = containsUserContent(baseBody);

      // Step 2: Try each WCD suffix
      for (const suffix of WCD_SUFFIXES) {
        try {
          const wcdUrl = url.endsWith('/') ? url.slice(0, -1) + suffix : url + suffix;
          const cacheBuster = `wcd=${Date.now()}`;
          const testUrl = wcdUrl.includes('?') ? `${wcdUrl}&${cacheBuster}` : `${wcdUrl}?${cacheBuster}`;

          const wcdResp = await fetch(testUrl, {
            signal: AbortSignal.timeout(config.timeout || 10000),
          });
          const wcdBody = await wcdResp.text();
          const wcdHeaders = Object.fromEntries(wcdResp.headers);
          const status = wcdResp.status;

          // Skip if the appended path resulted in 404/301/302 (CDN/app correctly rejected)
          if (status === 404 || status === 301 || status === 302) continue;

          // Check if the response still contains the original page content
          // (the server ignored the .css suffix and served the dynamic page)
          const bodyMatch = baseBody.length > 100 &&
            wcdBody.length > 100 &&
            wcdBody.includes(baseBody.slice(100, 200));

          if (!bodyMatch) continue;

          // Check if the response was cached (CDN treated it as a static asset)
          const wasCached = detectCaching(wcdHeaders);
          const cacheHit = isCacheHit(wcdHeaders);

          // Verify: re-request without cookies to see if cached content is served
          let confirmedCached = false;
          if (wasCached) {
            try {
              const verifyResp = await fetch(testUrl, {
                signal: AbortSignal.timeout(config.timeout || 10000),
              });
              const verifyBody = await verifyResp.text();
              const verifyHeaders = Object.fromEntries(verifyResp.headers);
              confirmedCached = isCacheHit(verifyHeaders) && verifyBody.includes(baseBody.slice(100, 200));
            } catch { /* verification failed */ }
          }

          // Only report if there's evidence the CDN cached a dynamic response
          if (wasCached || cacheHit || confirmedCached) {
            const severity = confirmedCached && hasUserContent ? 'critical' as const
              : confirmedCached ? 'high' as const
              : hasUserContent ? 'high' as const
              : 'medium' as const;

            findings.push({
              id: randomUUID(),
              category: 'cache-poisoning',
              severity,
              title: `Web Cache Deception via ${suffix} on ${new URL(url).pathname}`,
              description: `Appending "${suffix}" to ${new URL(url).pathname} returns the original dynamic page content, and the response contains cache headers suggesting the CDN treats it as a static asset. ${confirmedCached ? 'A subsequent unauthenticated request confirmed the cached response is served to other users.' : 'Manual verification recommended to confirm cached content is accessible.'} ${hasUserContent ? 'The page contains user-specific content (PII/tokens/session data) which could be stolen by any visitor.' : ''}`,
              url: wcdUrl,
              evidence: `Original: ${url}\nWCD URL: ${wcdUrl}\nHTTP ${status}, Cache: ${JSON.stringify(Object.fromEntries(Object.entries(wcdHeaders).filter(([k]) => CACHE_HEADERS.includes(k.toLowerCase()))))}${confirmedCached ? '\nConfirmed: cached response served on re-request' : ''}`,
              request: { method: 'GET', url: testUrl },
              response: { status, headers: wcdHeaders, bodySnippet: wcdBody.slice(0, 300) },
              timestamp: new Date().toISOString(),
              confidence: confirmedCached ? 'high' : 'medium',
            });

            break; // One WCD finding per URL is enough
          }
        } catch { continue; }
      }
    } catch { continue; }
  }

  return findings;
}

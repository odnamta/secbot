import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { randomUUID } from 'node:crypto';
import type { RequestLogger } from '../../utils/request-logger.js';

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

    return findings;
  },
};

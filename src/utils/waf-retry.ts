import type { BrowserContext, APIResponse } from 'playwright';
import { mutatePayload, pickStrategies } from './payload-mutator.js';
import type { WafDetection } from '../scanner/types.js';
import { log } from './logger.js';

const WAF_BLOCK_PATTERNS = [
  /access denied/i, /forbidden/i, /blocked/i,
  /cloudflare/i, /akamai/i, /incapsula/i,
  /web application firewall/i, /security policy/i,
];

export function isWafBlock(status: number, body: string): boolean {
  if (status !== 403) return false;
  return WAF_BLOCK_PATTERNS.some(p => p.test(body));
}

export interface WafRetryOptions {
  context: BrowserContext;
  url: string;
  payload: string;
  paramName: string;
  method?: 'GET' | 'POST';
  waf?: WafDetection;
  maxRetries?: number; // default 3
  timeout?: number;
}

export interface WafRetryResult {
  response: APIResponse;
  body: string;
  strategy: string; // 'original' or the mutation strategy that worked
  attempts: number;
}

/**
 * Send a payload with WAF-aware retry.
 * If the original request gets WAF-blocked (403 + block pattern),
 * retry with up to maxRetries different encoding strategies.
 */
export async function fetchWithWafRetry(opts: WafRetryOptions): Promise<WafRetryResult> {
  const { context, url, payload, paramName, method = 'GET', waf, maxRetries = 3, timeout = 15000 } = opts;

  const page = await context.newPage();
  try {
    // Try original payload first
    const originalUrl = method === 'GET'
      ? `${url}${url.includes('?') ? '&' : '?'}${paramName}=${encodeURIComponent(payload)}`
      : url;
    const originalBody = method === 'POST' ? `${paramName}=${encodeURIComponent(payload)}` : undefined;

    const resp = await page.request.fetch(originalUrl, {
      method,
      data: originalBody,
      headers: method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : undefined,
      timeout,
    });
    const body = await resp.text();

    if (!isWafBlock(resp.status(), body)) {
      return { response: resp, body, strategy: 'original', attempts: 1 };
    }

    log.debug(`WAF blocked original payload on ${url}, trying mutations...`);

    // Get encoding strategies (skip 'none' — it's equivalent to the original we already tried)
    const strategies = pickStrategies(waf).filter(s => s !== 'none');

    for (let i = 0; i < Math.min(maxRetries, strategies.length); i++) {
      const strategy = strategies[i];
      const mutated = mutatePayload(payload, [strategy])[0] ?? payload;

      const retryUrl = method === 'GET'
        ? `${url}${url.includes('?') ? '&' : '?'}${paramName}=${encodeURIComponent(mutated)}`
        : url;
      const retryBody = method === 'POST' ? `${paramName}=${encodeURIComponent(mutated)}` : undefined;

      try {
        const retryResp = await page.request.fetch(retryUrl, {
          method,
          data: retryBody,
          headers: method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : undefined,
          timeout,
        });
        const retryRespBody = await retryResp.text();

        if (!isWafBlock(retryResp.status(), retryRespBody)) {
          log.info(`WAF bypass: strategy "${strategy}" worked on ${url}`);
          return { response: retryResp, body: retryRespBody, strategy, attempts: i + 2 };
        }
      } catch {
        continue;
      }
    }

    // All retries blocked — return original blocked response
    return { response: resp, body, strategy: 'all-blocked', attempts: maxRetries + 1 };
  } finally {
    await page.close();
  }
}

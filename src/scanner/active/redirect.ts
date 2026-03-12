import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { REDIRECT_PAYLOADS, REDIRECT_CANARY } from '../../config/payloads/redirect.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

/** Regex matching common redirect parameter names */
const REDIRECT_PARAM_NAME_RE =
  /^(url|redirect|next|return|goto|dest|callback|redir|forward|ref|out|continue|target|path|link|returnUrl|redirectUrl|returnTo|return_to|redirect_uri|redirect_url|to|rurl)$/i;

/** Check if a parameter value looks like an external URL (starts with http(s):// or //) */
function isExternalUrl(value: string): boolean {
  if (!value) return false;
  return /^(https?:\/\/|\/\/)/i.test(value.trim());
}

/** Extract the hostname from a URL-like value, or null if not parseable */
function extractHost(value: string): string | null {
  try {
    let normalized = value.trim();
    if (normalized.startsWith('//')) normalized = 'https:' + normalized;
    const parsed = new URL(normalized);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Check if a Location header value would redirect to the canary domain.
 * Must be an absolute URL or protocol-relative URL pointing to the canary.
 * Relative paths (e.g. /\evil.example.com) are NOT external redirects.
 */
function isExternalRedirectToCanary(location: string): boolean {
  if (!location) return false;
  const trimmed = location.trim();
  // Must be absolute or protocol-relative to be an external redirect
  if (!isExternalUrl(trimmed) && !/^[a-z]+:/i.test(trimmed)) return false;
  // Check if it resolves to the canary domain
  const host = extractHost(trimmed);
  if (host && host.includes(REDIRECT_CANARY)) return true;
  // Also check raw string for cases where URL parsing fails but canary is present
  return trimmed.includes(REDIRECT_CANARY);
}

export const redirectCheck: ActiveCheck = {
  name: 'redirect',
  category: 'open-redirect',
  async run(context, targets, config, requestLogger) {
    if (targets.redirectUrls.length === 0) return [];

    log.info(`Testing ${targets.redirectUrls.length} URLs for open redirect...`);
    return testOpenRedirect(context, targets.redirectUrls, config, requestLogger);
  },
};

async function testOpenRedirect(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const targetHost = new URL(config.targetUrl).hostname.toLowerCase();

  for (const originalUrl of urls) {
    const parsedUrl = new URL(originalUrl);
    const redirectParams = Array.from(parsedUrl.searchParams.keys()).filter((k) =>
      REDIRECT_PARAM_NAME_RE.test(k),
    );

    for (const param of redirectParams) {
      const currentValue = parsedUrl.searchParams.get(param) || '';

      // --- Phase 1: Detect existing external URL values ---
      // If the parameter already points to an external domain, test if replacing
      // with our canary domain also works (confirms the redirect is open)
      if (isExternalUrl(currentValue)) {
        const existingHost = extractHost(currentValue);
        if (existingHost && existingHost !== targetHost && existingHost !== 'localhost' && existingHost !== '127.0.0.1') {
          // The parameter already has an external URL — test with our canary
          const found = await testPayloadForParam(
            context, originalUrl, param, REDIRECT_PAYLOADS[0], config, requestLogger,
          );
          if (found) {
            findings.push(found);
            continue; // Skip further payloads for this param, already confirmed
          }
        }
      }

      // --- Phase 2: Standard payload injection (try all bypass techniques) ---
      for (const payload of REDIRECT_PAYLOADS) {
        const found = await testPayloadForParam(
          context, originalUrl, param, payload, config, requestLogger,
        );
        if (found) {
          findings.push(found);
          break; // One finding per param is enough
        }

        await delay(config.requestDelay);
      }

      // Early exit if we already found a redirect for this URL
      if (findings.some((f) => f.url === originalUrl && f.category === 'open-redirect')) break;
    }
  }

  return findings;
}

/**
 * Test a single payload against a single parameter and return a finding if the redirect is confirmed.
 * Checks:
 *   1. HTTP Location header (3xx server-side redirect)
 *   2. Browser navigation (catches JS redirects, meta refresh)
 */
async function testPayloadForParam(
  context: BrowserContext,
  originalUrl: string,
  param: string,
  payload: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const testUrl = new URL(originalUrl);
  testUrl.searchParams.set(param, payload);

  const page = await context.newPage();
  try {
    // First check: use fetch to inspect Location header directly (catches server-side redirects)
    let locationRedirect = false;
    try {
      const fetchResponse = await page.request.fetch(testUrl.href, {
        maxRedirects: 0,
      });
      const locationHeader = fetchResponse.headers()['location'] ?? '';
      if (isExternalRedirectToCanary(locationHeader)) {
        locationRedirect = true;
        return {
          id: randomUUID(),
          category: 'open-redirect',
          severity: 'medium',
          title: `Open Redirect via "${param}" Parameter`,
          description: `The parameter "${param}" allows redirecting users to arbitrary external domains via Location header.`,
          url: originalUrl,
          evidence: `Payload: ${payload}\nLocation: ${locationHeader}`,
          request: { method: 'GET', url: testUrl.href },
          response: { status: fetchResponse.status(), headers: fetchResponse.headers() },
          timestamp: new Date().toISOString(),
          confidence: 'high',
        };
      }
    } catch (err) {
      log.debug(`Redirect fetch check: ${(err as Error).message}`);
    }

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'GET',
      url: testUrl.href,
      phase: 'active-redirect',
    });

    // Second check: follow redirects in browser (catches JS redirects, meta refresh)
    if (!locationRedirect) {
      try {
        await page.goto(testUrl.href, {
          timeout: config.timeout,
          waitUntil: 'domcontentloaded',
        });

        const finalUrl = page.url();
        // Check if the browser navigated to a different host containing our canary domain
        // We check the hostname (not the full URL) to avoid false positives from query params
        const finalHost = extractHost(finalUrl);
        if (finalHost && finalHost.includes(REDIRECT_CANARY)) {
          return {
            id: randomUUID(),
            category: 'open-redirect',
            severity: 'medium',
            title: `Open Redirect via "${param}" Parameter`,
            description: `The parameter "${param}" allows redirecting users to arbitrary external domains.`,
            url: originalUrl,
            evidence: `Payload: ${payload}\nRedirected to: ${finalUrl}`,
            request: { method: 'GET', url: testUrl.href },
            timestamp: new Date().toISOString(),
            confidence: 'high',
          };
        }

        // Third check: meta refresh tags in the page
        const metaRefreshUrl = await page.evaluate(() => {
          const meta = document.querySelector('meta[http-equiv="refresh"]');
          if (!meta) return null;
          const content = meta.getAttribute('content') || '';
          const match = content.match(/url\s*=\s*['"]?(.*?)['"]?$/i);
          return match ? match[1] : null;
        });
        if (metaRefreshUrl && metaRefreshUrl.includes(REDIRECT_CANARY)) {
          return {
            id: randomUUID(),
            category: 'open-redirect',
            severity: 'medium',
            title: `Open Redirect via "${param}" Parameter (Meta Refresh)`,
            description: `The parameter "${param}" allows redirecting users to arbitrary external domains via meta refresh.`,
            url: originalUrl,
            evidence: `Payload: ${payload}\nMeta refresh URL: ${metaRefreshUrl}`,
            request: { method: 'GET', url: testUrl.href },
            timestamp: new Date().toISOString(),
            confidence: 'high',
          };
        }

        // Fourth check: JavaScript-based redirects (window.location in inline scripts)
        const jsRedirectUrl = await page.evaluate(() => {
          const scripts = document.querySelectorAll('script:not([src])');
          for (const script of scripts) {
            const text = script.textContent || '';
            const match = text.match(/(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*['"]([^'"]+)['"]/);
            if (match) return match[1];
          }
          return null;
        });
        if (jsRedirectUrl && jsRedirectUrl.includes(REDIRECT_CANARY)) {
          return {
            id: randomUUID(),
            category: 'open-redirect',
            severity: 'medium',
            title: `Open Redirect via "${param}" Parameter (JavaScript)`,
            description: `The parameter "${param}" allows redirecting users to arbitrary external domains via JavaScript redirect.`,
            url: originalUrl,
            evidence: `Payload: ${payload}\nJS redirect URL: ${jsRedirectUrl}`,
            request: { method: 'GET', url: testUrl.href },
            timestamp: new Date().toISOString(),
            confidence: 'high',
          };
        }
      } catch (err) {
        // Navigation errors (e.g., redirected to unreachable external domain) may indicate success
        const errMsg = (err as Error).message;
        if (errMsg.includes(REDIRECT_CANARY)) {
          return {
            id: randomUUID(),
            category: 'open-redirect',
            severity: 'medium',
            title: `Open Redirect via "${param}" Parameter`,
            description: `The parameter "${param}" allows redirecting users to arbitrary external domains.`,
            url: originalUrl,
            evidence: `Payload: ${payload}\nNavigation error confirms redirect: ${errMsg.slice(0, 200)}`,
            request: { method: 'GET', url: testUrl.href },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          };
        }
        log.debug(`Redirect browser check: ${errMsg}`);
      }
    }
  } catch (err) {
    log.debug(`Redirect test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return null;
}

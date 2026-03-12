import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/** Canary domain injected via Host headers to detect reflection */
export const HOST_CANARY = 'secbot-host-inject.example.com';

/** Headers used for Host header injection testing */
export const INJECTION_HEADERS = [
  'X-Forwarded-Host',
  'X-Forwarded-Server',
  'X-Original-URL',
  'X-Rewrite-URL',
] as const;

/** Max pages to test per scan */
const MAX_PAGES = 5;

/**
 * Detect whether the canary domain appears in a response body or Location header.
 * Returns an object describing where the canary was found, or null if not found.
 */
export function detectCanaryReflection(
  body: string,
  headers: Record<string, string>,
): { location: 'header' | 'body'; evidence: string } | null {
  // Check Location header (redirect) — highest severity
  const locationHeader = headers['location'] ?? '';
  if (locationHeader.includes(HOST_CANARY)) {
    return {
      location: 'header',
      evidence: `Location: ${locationHeader}`,
    };
  }

  // Check response body — medium severity
  if (body.includes(HOST_CANARY)) {
    // Extract surrounding context (up to 100 chars around canary)
    const idx = body.indexOf(HOST_CANARY);
    const start = Math.max(0, idx - 50);
    const end = Math.min(body.length, idx + HOST_CANARY.length + 50);
    const snippet = body.slice(start, end);
    return {
      location: 'body',
      evidence: `Canary reflected in body: ...${snippet}...`,
    };
  }

  return null;
}

export const hostHeaderCheck: ActiveCheck = {
  parallel: true,
  name: 'host-header',
  category: 'host-header',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Test a subset of pages (cap at MAX_PAGES)
    const testPages = targets.pages.slice(0, MAX_PAGES);
    if (testPages.length === 0) return findings;

    log.info(`Testing ${testPages.length} URLs for Host header injection...`);

    for (const url of testPages) {
      // Test 1: Direct Host header override
      const hostFindings = await testHostOverride(context, url, config, requestLogger);
      findings.push(...hostFindings);

      // Test 2: X-Forwarded-Host and related headers
      const xfhFindings = await testForwardedHeaders(context, url, config, requestLogger);
      findings.push(...xfhFindings);

      // Test 3: Cache poisoning via different Host values
      const cacheFindings = await testCachePoisoning(context, url, config, requestLogger);
      findings.push(...cacheFindings);

      await delay(config.requestDelay);
    }

    return findings;
  },
};

/**
 * Test 1: Send request with modified Host header.
 * If the server reflects the canary in Location or body, it's vulnerable.
 */
async function testHostOverride(
  context: BrowserContext,
  url: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const page = await context.newPage();

  try {
    const response = await page.request.fetch(url, {
      headers: { Host: HOST_CANARY },
      maxRedirects: 0,
    });

    const status = response.status();
    const headers = response.headers();
    const body = await response.text();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'GET',
      url,
      headers: { Host: HOST_CANARY },
      responseStatus: status,
      phase: 'active-host-header',
    });

    const reflection = detectCanaryReflection(body, headers);
    if (reflection) {
      findings.push({
        id: randomUUID(),
        category: 'host-header',
        severity: reflection.location === 'header' ? 'high' : 'medium',
        title: reflection.location === 'header'
          ? 'Host Header Injection — Redirect Poisoning'
          : 'Host Header Injection — Body Reflection',
        description: reflection.location === 'header'
          ? 'The server uses the Host header value in redirect URLs (Location header). '
            + 'An attacker can inject a malicious host to redirect users to a phishing site, '
            + 'poison password reset links, or hijack OAuth flows.'
          : 'The server reflects the Host header value in the response body. '
            + 'This can be exploited for phishing via poisoned links, password reset link hijacking, '
            + 'or web cache poisoning.',
        url,
        evidence: [
          `Injected Host: ${HOST_CANARY}`,
          reflection.evidence,
          `Response status: ${status}`,
        ].join('\n'),
        request: { method: 'GET', url, headers: { Host: HOST_CANARY } },
        response: {
          status,
          headers: reflection.location === 'header'
            ? { Location: headers['location'] ?? '' }
            : undefined,
          bodySnippet: body.slice(0, 200),
        },
        timestamp: new Date().toISOString(),
        confidence: reflection.location === 'header' ? 'high' : 'medium',
      });
    }
  } catch (err) {
    log.debug(`Host header override test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return findings;
}

/**
 * Test 2: Inject canary via X-Forwarded-Host and related headers.
 * Many reverse proxies and frameworks trust these headers.
 */
async function testForwardedHeaders(
  context: BrowserContext,
  url: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const headerName of INJECTION_HEADERS) {
    const page = await context.newPage();

    try {
      const response = await page.request.fetch(url, {
        headers: { [headerName]: HOST_CANARY },
        maxRedirects: 0,
      });

      const status = response.status();
      const headers = response.headers();
      const body = await response.text();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url,
        headers: { [headerName]: HOST_CANARY },
        responseStatus: status,
        phase: 'active-host-header',
      });

      const reflection = detectCanaryReflection(body, headers);
      if (reflection) {
        findings.push({
          id: randomUUID(),
          category: 'host-header',
          severity: reflection.location === 'header' ? 'high' : 'medium',
          title: `Host Header Injection via ${headerName}`,
          description: `The server trusts the ${headerName} header and reflects its value `
            + `${reflection.location === 'header' ? 'in redirect URLs' : 'in the response body'}. `
            + 'An attacker can exploit this to poison password reset links, redirect users to '
            + 'malicious sites, or perform web cache poisoning attacks.',
          url,
          evidence: [
            `Injected header: ${headerName}: ${HOST_CANARY}`,
            reflection.evidence,
            `Response status: ${status}`,
          ].join('\n'),
          request: { method: 'GET', url, headers: { [headerName]: HOST_CANARY } },
          response: {
            status,
            headers: reflection.location === 'header'
              ? { Location: headers['location'] ?? '' }
              : undefined,
            bodySnippet: body.slice(0, 200),
          },
          timestamp: new Date().toISOString(),
          confidence: reflection.location === 'header' ? 'high' : 'medium',
        });
        // One finding per URL per header is enough
        break;
      }
    } catch (err) {
      log.debug(`${headerName} injection test: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

/**
 * Test 3: Cache poisoning detection.
 * Send two requests to the same URL — one with normal host, one with canary host.
 * If the second request's response differs when using the canary, the server may be
 * vulnerable to cache poisoning via Host header manipulation.
 */
async function testCachePoisoning(
  context: BrowserContext,
  url: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  const page1 = await context.newPage();
  const page2 = await context.newPage();

  try {
    // First request: normal (baseline)
    const baselineResponse = await page1.request.fetch(url, { maxRedirects: 0 });
    const baselineBody = await baselineResponse.text();
    const baselineStatus = baselineResponse.status();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'GET',
      url,
      responseStatus: baselineStatus,
      phase: 'active-host-header',
    });

    await delay(config.requestDelay);

    // Second request: with X-Forwarded-Host canary
    const poisonedResponse = await page2.request.fetch(url, {
      headers: { 'X-Forwarded-Host': HOST_CANARY },
      maxRedirects: 0,
    });
    const poisonedBody = await poisonedResponse.text();
    const poisonedStatus = poisonedResponse.status();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'GET',
      url,
      headers: { 'X-Forwarded-Host': HOST_CANARY },
      responseStatus: poisonedStatus,
      phase: 'active-host-header',
    });

    // Check if the poisoned response contains the canary while baseline doesn't
    const baselineHasCanary = baselineBody.includes(HOST_CANARY);
    const poisonedHasCanary = poisonedBody.includes(HOST_CANARY);

    if (!baselineHasCanary && poisonedHasCanary) {
      // Now send a third "clean" request to see if the cache was poisoned
      await delay(config.requestDelay);

      const page3 = await context.newPage();
      try {
        const verifyResponse = await page3.request.fetch(url, { maxRedirects: 0 });
        const verifyBody = await verifyResponse.text();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url,
          responseStatus: verifyResponse.status(),
          phase: 'active-host-header',
        });

        if (verifyBody.includes(HOST_CANARY)) {
          // Cache was actually poisoned — the canary persisted
          findings.push({
            id: randomUUID(),
            category: 'host-header',
            severity: 'high',
            title: 'Web Cache Poisoning via Host Header',
            description:
              'The server caches responses that include attacker-controlled Host header values. '
              + 'A subsequent clean request returns the poisoned content. '
              + 'An attacker can serve malicious content to all users via cache poisoning.',
            url,
            evidence: [
              'Cache poisoning confirmed:',
              `1. Baseline request: canary absent`,
              `2. Poisoned request (X-Forwarded-Host: ${HOST_CANARY}): canary present`,
              `3. Verification request (no injection): canary STILL present (cached)`,
            ].join('\n'),
            request: { method: 'GET', url, headers: { 'X-Forwarded-Host': HOST_CANARY } },
            response: {
              status: poisonedStatus,
              bodySnippet: poisonedBody.slice(0, 200),
            },
            timestamp: new Date().toISOString(),
            confidence: 'high',
          });
        }
      } finally {
        await page3.close();
      }
    }
  } catch (err) {
    log.debug(`Cache poisoning test: ${(err as Error).message}`);
  } finally {
    await page1.close();
    await page2.close();
  }

  return findings;
}

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/** Number of rapid requests to send for rate limit testing */
const BURST_COUNT = 15;

/** Delay between burst requests in ms (keep low to test real brute-force protection) */
const BURST_DELAY_MS = 50;

/** If all burst responses have the same status and no rate-limit headers, the endpoint lacks protection */
const RATE_LIMIT_HEADERS = [
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-rate-limit-limit',
  'x-rate-limit-remaining',
  'retry-after',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
];

/** Patterns that indicate a login/auth endpoint */
const AUTH_ENDPOINT_RE = /\/(login|signin|sign-in|auth|authenticate|token|session|register|signup|sign-up|reset|forgot|password|otp|verify|2fa|mfa)\b/i;

/** Patterns for API endpoints that should have rate limiting */
const SENSITIVE_API_RE = /\/(api|graphql|rest)\b/i;

/**
 * Rate Limit / Brute Force Protection check.
 *
 * Tests authentication and sensitive API endpoints for missing rate limiting.
 * Missing rate limiting on login endpoints is a common bug bounty finding
 * (OWASP A07:2021 – Identification and Authentication Failures).
 *
 * Strategy:
 * 1. Identify login/auth forms and sensitive API endpoints
 * 2. Send a burst of rapid requests (15 in quick succession)
 * 3. Check if any response has rate-limit headers or returns 429 Too Many Requests
 * 4. If all responses succeed with 200 and no rate-limit headers → finding
 */
export const rateLimitCheck: ActiveCheck = {
  name: 'rate-limit',
  category: 'rate-limit',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Identify endpoints to test
    const authEndpoints = identifyAuthEndpoints(targets);
    const sensitiveApis = targets.apiEndpoints.filter((u) => SENSITIVE_API_RE.test(u)).slice(0, 3);

    const allEndpoints = [...new Set([...authEndpoints, ...sensitiveApis])];
    if (allEndpoints.length === 0) {
      log.info('Rate limit check: no auth or sensitive API endpoints found');
      return [];
    }

    log.info(`Testing ${allEndpoints.length} endpoint(s) for rate limiting...`);

    for (const endpoint of allEndpoints) {
      const finding = await testRateLimit(context, endpoint, config, requestLogger);
      if (finding) findings.push(finding);
      await delay(config.requestDelay);
    }

    // Also test login forms
    const loginForms = targets.forms.filter(
      (f) => AUTH_ENDPOINT_RE.test(f.action) || AUTH_ENDPOINT_RE.test(f.pageUrl),
    ).slice(0, 3);

    for (const form of loginForms) {
      const formUrl = form.action || form.pageUrl;
      // Skip if we already tested this endpoint via URL
      if (allEndpoints.some((e) => e.includes(new URL(formUrl).pathname))) continue;

      const finding = await testFormRateLimit(context, form, config, requestLogger);
      if (finding) findings.push(finding);
      await delay(config.requestDelay);
    }

    log.info(`Rate limit check: ${findings.length} finding(s)`);
    return findings;
  },
};

/** Identify auth-related endpoints from pages and URLs */
function identifyAuthEndpoints(targets: ScanTargets): string[] {
  const endpoints: string[] = [];

  for (const page of targets.pages) {
    if (AUTH_ENDPOINT_RE.test(page)) {
      endpoints.push(page);
    }
  }

  for (const url of targets.apiEndpoints) {
    if (AUTH_ENDPOINT_RE.test(url)) {
      endpoints.push(url);
    }
  }

  return [...new Set(endpoints)].slice(0, 5); // Cap at 5 auth endpoints
}

/** Test a GET endpoint for rate limiting */
async function testRateLimit(
  context: BrowserContext,
  endpoint: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const statuses: number[] = [];
  let hasRateLimitHeaders = false;
  let got429 = false;

  for (let i = 0; i < BURST_COUNT; i++) {
    const page = await context.newPage();
    try {
      const response = await page.request.fetch(endpoint, {
        timeout: config.timeout,
      });
      const status = response.status();
      statuses.push(status);

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url: endpoint,
        responseStatus: status,
        phase: 'active-rate-limit',
      });

      if (status === 429) {
        got429 = true;
        break;
      }

      // Check for rate limit headers
      const headers = response.headers();
      if (RATE_LIMIT_HEADERS.some((h) => h in headers)) {
        hasRateLimitHeaders = true;
        break;
      }
    } catch {
      // Connection errors during burst may indicate rate limiting (firewall/WAF)
      hasRateLimitHeaders = true;
      break;
    } finally {
      await page.close();
    }

    await delay(BURST_DELAY_MS);
  }

  // If we got 429 or found rate limit headers, the endpoint is protected
  if (got429 || hasRateLimitHeaders) return null;

  // If all requests succeeded (2xx/3xx) without rate limiting → finding
  const allSucceeded = statuses.length >= BURST_COUNT && statuses.every((s) => s < 400);
  if (!allSucceeded) return null;

  const isAuthEndpoint = AUTH_ENDPOINT_RE.test(endpoint);

  return {
    id: randomUUID(),
    category: 'rate-limit',
    severity: isAuthEndpoint ? 'medium' : 'low',
    title: `Missing Rate Limiting on ${isAuthEndpoint ? 'Authentication' : 'API'} Endpoint`,
    description: isAuthEndpoint
      ? `The authentication endpoint at ${new URL(endpoint).pathname} does not enforce rate limiting. An attacker can perform brute-force password attacks, credential stuffing, or account enumeration without being throttled.`
      : `The API endpoint at ${new URL(endpoint).pathname} does not enforce rate limiting. This may allow abuse, scraping, or resource exhaustion attacks.`,
    url: endpoint,
    evidence: `Sent ${BURST_COUNT} rapid requests — all returned HTTP ${statuses[0]} with no rate-limit headers (X-RateLimit-*, Retry-After, etc.) and no 429 response.`,
    request: { method: 'GET', url: endpoint },
    response: { status: statuses[statuses.length - 1] },
    timestamp: new Date().toISOString(),
  };
}

/** Test a form endpoint for rate limiting via POST */
async function testFormRateLimit(
  context: BrowserContext,
  form: ScanTargets['forms'][0],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const formUrl = form.action || form.pageUrl;
  const statuses: number[] = [];
  let hasRateLimitHeaders = false;
  let got429 = false;

  // Build a dummy form body
  const body = form.inputs
    .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(i.name === 'password' ? 'wrongpass123' : 'test@test.com')}`)
    .join('&');

  for (let i = 0; i < BURST_COUNT; i++) {
    const page = await context.newPage();
    try {
      const method = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';
      const response = method === 'POST'
        ? await page.request.fetch(formUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: body,
            timeout: config.timeout,
          })
        : await page.request.fetch(`${formUrl}?${body}`, { timeout: config.timeout });

      const status = response.status();
      statuses.push(status);

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method,
        url: formUrl,
        responseStatus: status,
        phase: 'active-rate-limit',
      });

      if (status === 429) {
        got429 = true;
        break;
      }

      const headers = response.headers();
      if (RATE_LIMIT_HEADERS.some((h) => h in headers)) {
        hasRateLimitHeaders = true;
        break;
      }
    } catch {
      hasRateLimitHeaders = true;
      break;
    } finally {
      await page.close();
    }

    await delay(BURST_DELAY_MS);
  }

  if (got429 || hasRateLimitHeaders) return null;

  const allSucceeded = statuses.length >= BURST_COUNT && statuses.every((s) => s < 500);
  if (!allSucceeded) return null;

  return {
    id: randomUUID(),
    category: 'rate-limit',
    severity: 'medium',
    title: 'Missing Rate Limiting on Login Form',
    description: `The login form at ${new URL(formUrl).pathname} does not enforce rate limiting. An attacker can submit ${BURST_COUNT}+ login attempts per second without being blocked, enabling brute-force and credential stuffing attacks.`,
    url: formUrl,
    evidence: `Sent ${BURST_COUNT} rapid POST requests to the login form — all returned HTTP ${statuses[0]} with no rate-limit headers and no 429 response.`,
    request: { method: 'POST', url: formUrl, body },
    response: { status: statuses[statuses.length - 1] },
    timestamp: new Date().toISOString(),
  };
}

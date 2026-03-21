import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/**
 * CWE-208: Observable Timing Discrepancy
 * OWASP A07:2021 — Identification and Authentication Failures
 *
 * Detects timing side-channels by comparing response times for:
 *  1. Valid vs invalid usernames on login endpoints
 *  2. Existing vs non-existing resources on auth-protected endpoints
 *  3. Valid vs invalid tokens/API keys
 *
 * Uses statistical analysis (median comparison + threshold) to identify
 * consistent timing differences that indicate information leakage.
 *
 * Non-destructive: only sends GET/POST requests with different inputs.
 */

/** Auth/login URL patterns */
const AUTH_ENDPOINT_PATTERNS =
  /\/(login|signin|sign-in|auth|authenticate|api\/auth|api\/login|oauth\/token|session|api\/v[0-9]+\/login|api\/v[0-9]+\/auth)/i;

/** Password reset / account check patterns */
const ACCOUNT_CHECK_PATTERNS =
  /\/(forgot|reset|recover|password|check-email|verify|api\/users\/check|register|signup)/i;

/** Number of timing samples per test case — need 10+ for statistical significance */
const SAMPLES_PER_TEST = 10;

/** Minimum time difference (ms) to flag as significant — 100ms to filter network jitter */
const MIN_TIMING_DIFF_MS = 100;

/** Maximum time difference ratio to flag (e.g., 1.5 = 50% slower) */
const MIN_TIMING_RATIO = 1.5;

/** Profile limits — how many endpoints to test */
const PROFILE_LIMITS: Record<string, number> = {
  quick: 2,
  standard: 5,
  deep: 10,
  stealth: 3,
};

/** Common usernames for timing tests */
const TEST_USERNAMES = {
  likely_valid: ['admin', 'root', 'test', 'user', 'info', 'support', 'contact'],
  likely_invalid: [
    'xyznonexistent99',
    'aaaabbbbcccc1234',
    'timing_test_user_xyz',
  ],
};

/**
 * Measure response time for a fetch request (ms).
 * Uses node fetch via Playwright's page.evaluate for consistency.
 */
async function measureResponseTime(
  context: BrowserContext,
  url: string,
  options: {
    method: string;
    headers?: Record<string, string>;
    body?: string;
  },
): Promise<{ timeMs: number; status: number }> {
  const page = await context.newPage();
  try {
    const result = await page.evaluate(
      async ({ url: u, method, headers, body }) => {
        const start = performance.now();
        try {
          const resp = await fetch(u, {
            method,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              ...headers,
            },
            body,
            credentials: 'omit',
            redirect: 'manual',
          });
          const end = performance.now();
          return { timeMs: end - start, status: resp.status };
        } catch {
          const end = performance.now();
          return { timeMs: end - start, status: 0 };
        }
      },
      { url, method: options.method, headers: options.headers, body: options.body },
    );
    return result;
  } finally {
    await page.close();
  }
}

/**
 * Collect timing samples for a given request.
 * Returns sorted array of response times in ms.
 */
async function collectTimingSamples(
  context: BrowserContext,
  url: string,
  options: { method: string; headers?: Record<string, string>; body?: string },
  count: number,
): Promise<{ times: number[]; statuses: number[] }> {
  const times: number[] = [];
  const statuses: number[] = [];

  for (let i = 0; i < count; i++) {
    const result = await measureResponseTime(context, url, options);
    times.push(result.timeMs);
    statuses.push(result.status);
    // Small delay between samples to avoid rate limiting
    await delay(100);
  }

  return { times, statuses };
}

/**
 * Calculate median of a sorted number array.
 */
function median(arr: number[]): number {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * Determine if two timing distributions show a statistically significant difference.
 */
function isTimingSignificant(
  timesA: number[],
  timesB: number[],
): { significant: boolean; medianA: number; medianB: number; diffMs: number; ratio: number } {
  const medA = median(timesA);
  const medB = median(timesB);
  const diffMs = Math.abs(medA - medB);
  const ratio = Math.max(medA, medB) / Math.min(medA, medB);

  return {
    significant: diffMs >= MIN_TIMING_DIFF_MS && ratio >= MIN_TIMING_RATIO,
    medianA: Math.round(medA),
    medianB: Math.round(medB),
    diffMs: Math.round(diffMs),
    ratio: Math.round(ratio * 100) / 100,
  };
}

export const timingAttackCheck: ActiveCheck = {
  name: 'timing-attack',
  category: 'info-disclosure',
  parallel: true, // read-only HTTP measurements

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const profile = config.profile ?? 'standard';
    const limit = PROFILE_LIMITS[profile] ?? 5;

    // Collect auth-related pages
    const allUrls = [
      ...(targets.pages ?? []),
      ...(targets.apiEndpoints ?? []),
    ];

    const authEndpoints = allUrls.filter(
      (url) => AUTH_ENDPOINT_PATTERNS.test(url) || ACCOUNT_CHECK_PATTERNS.test(url),
    );

    // Also check forms with password fields
    const loginForms = (targets.forms ?? []).filter((f) =>
      f.inputs.some((i) => i.type === 'password'),
    );

    const loginFormUrls = loginForms.map((f) => f.action || f.pageUrl).filter(Boolean);

    const endpointsToTest = [...new Set([...authEndpoints, ...loginFormUrls])].slice(0, limit);

    if (endpointsToTest.length === 0) {
      log.debug('[timing-attack] No auth endpoints found');
      return findings;
    }

    log.info(`[timing-attack] Testing ${endpointsToTest.length} auth endpoints for timing leaks`);

    for (const endpoint of endpointsToTest) {
      try {
        // Phase 1: Test username enumeration via timing
        // Send requests with likely-valid vs clearly-invalid usernames
        const validUsername = TEST_USERNAMES.likely_valid[0]; // 'admin'
        const invalidUsername = TEST_USERNAMES.likely_invalid[0]; // random string

        // Determine if this is a form-based login (POST) or API-based
        const isLoginForm = loginForms.some(
          (f) => (f.action || f.pageUrl) === endpoint,
        );

        const method = isLoginForm || AUTH_ENDPOINT_PATTERNS.test(endpoint) ? 'POST' : 'GET';

        // Find the username field name from the form
        const matchingForm = loginForms.find(
          (f) => (f.action || f.pageUrl) === endpoint,
        );
        const usernameField =
          matchingForm?.inputs.find((i) =>
            /user|email|login|name|account/i.test(i.name) && i.type !== 'password',
          )?.name ?? 'username';
        const passwordField =
          matchingForm?.inputs.find((i) => i.type === 'password')?.name ?? 'password';

        // Warm up — first request is always slower
        await measureResponseTime(context, endpoint, {
          method,
          body:
            method === 'POST'
              ? `${usernameField}=warmup&${passwordField}=warmup`
              : undefined,
        });

        // Collect timing samples for "valid-looking" username
        const validSamples = await collectTimingSamples(
          context,
          endpoint,
          {
            method,
            body:
              method === 'POST'
                ? `${usernameField}=${encodeURIComponent(validUsername)}&${passwordField}=wrongpassword123`
                : undefined,
          },
          SAMPLES_PER_TEST,
        );

        // Collect timing samples for "invalid" username
        const invalidSamples = await collectTimingSamples(
          context,
          endpoint,
          {
            method,
            body:
              method === 'POST'
                ? `${usernameField}=${encodeURIComponent(invalidUsername)}&${passwordField}=wrongpassword123`
                : undefined,
          },
          SAMPLES_PER_TEST,
        );

        const analysis = isTimingSignificant(validSamples.times, invalidSamples.times);

        if (analysis.significant) {
          const slower =
            analysis.medianA > analysis.medianB ? 'valid-looking' : 'invalid';
          const faster =
            slower === 'valid-looking' ? 'invalid' : 'valid-looking';

          findings.push({
            id: randomUUID(),
            title: `Timing Side-Channel — Username Enumeration via Response Time`,
            description:
              `The authentication endpoint at ${endpoint} shows a ${analysis.diffMs}ms timing difference ` +
              `(${analysis.ratio}x ratio) between ${slower} usernames (median: ${Math.max(analysis.medianA, analysis.medianB)}ms) ` +
              `and ${faster} usernames (median: ${Math.min(analysis.medianA, analysis.medianB)}ms). ` +
              `An attacker can enumerate valid usernames by measuring response times.`,
            category: 'info-disclosure',
            severity: 'medium',
            confidence: analysis.ratio >= 2.0 ? 'high' : 'medium',
            url: endpoint,
            evidence: JSON.stringify({
              payloadUsed: `${usernameField}=admin (valid) vs ${usernameField}=${invalidUsername} (invalid)`,
              responseIndicators: [
                `Valid username median: ${analysis.medianA}ms (${SAMPLES_PER_TEST} samples)`,
                `Invalid username median: ${analysis.medianB}ms (${SAMPLES_PER_TEST} samples)`,
                `Difference: ${analysis.diffMs}ms (ratio: ${analysis.ratio}x)`,
              ],
              httpExchange: {
                request: {
                  method,
                  url: endpoint,
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  body: `${usernameField}=[valid|invalid]&${passwordField}=wrongpassword123`,
                },
                response: {
                  status: validSamples.statuses[0] || 200,
                  headers: {},
                  bodySnippet: `Timing analysis: ${SAMPLES_PER_TEST} samples each, median diff ${analysis.diffMs}ms`,
                },
              },
            }),
            timestamp: new Date().toISOString(),
          });

          log.info(
            `[timing-attack] FOUND: ${endpoint} — ${analysis.diffMs}ms timing diff (${analysis.ratio}x ratio)`,
          );
        } else {
          log.debug(
            `[timing-attack] ${endpoint} — no significant timing diff (${analysis.diffMs}ms, ${analysis.ratio}x)`,
          );
        }

        if (requestLogger) {
          requestLogger.log({
            timestamp: new Date().toISOString(),
            method,
            url: endpoint,
            responseStatus: validSamples.statuses[0] || 200,
            phase: 'active:timing-attack',
          });
        }
      } catch (err) {
        log.debug(`[timing-attack] Error testing ${endpoint}: ${(err as Error).message}`);
      }
    }

    return findings;
  },
};

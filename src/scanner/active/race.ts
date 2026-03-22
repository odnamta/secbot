import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/** Number of concurrent requests to send in each race test */
const RACE_CONCURRENCY = 10;

/** Patterns for state-changing endpoints vulnerable to race conditions */
const STATE_CHANGE_RE = /\/(apply|redeem|coupon|discount|transfer|withdraw|deposit|buy|purchase|order|checkout|submit|vote|like|follow|confirm|activate|upgrade|claim|use|consume|assign|book|reserve|enroll|register|subscribe)/i;

/** Patterns for transaction-like form actions */
const TRANSACTION_FORM_RE = /\/(pay|transfer|send|order|checkout|submit|apply|redeem|claim|withdraw|deposit)/i;

// ─── Burst Result Types ───────────────────────────────────────────────

/** A single response captured during a concurrent burst */
export interface BurstResponseEntry {
  status: number;
  body: string;
  timeMs: number;
}

/** Result of a concurrent burst test against a single endpoint */
export interface BurstResult {
  responses: BurstResponseEntry[];
  raceDetected: boolean;
  indicators: string[];
}

// ─── Analysis (exported for testing) ─────────────────────────────────

/**
 * Analyze a set of burst responses for race condition indicators.
 *
 * Indicators checked:
 * 1. Multiple 2xx successes when only one should succeed (double-processing)
 * 2. Status code inconsistency (mix of 2xx and 5xx — fragile concurrency handling)
 * 3. High body variation (inconsistent state across concurrent requests)
 * 4. Duplicate transaction/order IDs across responses
 *
 * Exported so unit tests can exercise the logic without Playwright.
 */
export function analyzeBurstResults(responses: BurstResponseEntry[]): Pick<BurstResult, 'raceDetected' | 'indicators'> {
  const indicators: string[] = [];

  if (responses.length < 2) {
    return { raceDetected: false, indicators };
  }

  const successCount = responses.filter((r) => r.status >= 200 && r.status < 300).length;
  const totalResponses = responses.length;

  // ── Indicator 1: Multiple successes on a state-changing endpoint ──
  // A properly protected endpoint should let at most 1 succeed and reject
  // duplicates with 409 Conflict or 429 Too Many Requests.
  if (successCount > 1) {
    indicators.push(`${successCount}/${totalResponses} requests succeeded (expected at most 1)`);
  }

  // ── Indicator 2: Status code inconsistency ──
  // Some 2xx + some 5xx suggests the server's concurrency handling is
  // fragile — sometimes it catches the race, sometimes it doesn't.
  const has2xx = responses.some((r) => r.status >= 200 && r.status < 300);
  const hasServerError = responses.some((r) => r.status >= 500);
  if (has2xx && hasServerError) {
    const statusCounts = new Map<number, number>();
    for (const r of responses) {
      statusCounts.set(r.status, (statusCounts.get(r.status) ?? 0) + 1);
    }
    const breakdown = [...statusCounts.entries()]
      .map(([code, count]) => `${code}x${count}`)
      .join(', ');
    indicators.push(`Mixed success/error statuses under concurrency (${breakdown})`);
  }

  // ── Indicator 3: High body variation (inconsistent state) ──
  // If concurrent requests return many different bodies, the server state
  // is not stable under concurrency — classic TOCTOU symptom.
  const nonEmptyBodies = responses.map((r) => r.body).filter(Boolean);
  const uniqueBodies = new Set(nonEmptyBodies);
  if (uniqueBodies.size > 2 && totalResponses >= 5) {
    indicators.push(
      `${uniqueBodies.size} different response bodies across ${totalResponses} concurrent requests (inconsistent state)`,
    );
  }

  // ── Indicator 4: Duplicate IDs in responses ──
  // If the server returns the same transaction/order ID in multiple responses,
  // the same resource was processed more than once.
  const allBodiesConcat = responses.map((r) => r.body).join('\n');
  const idPattern = /"(?:id|order_id|transaction_id|txn_id|confirmation_id|reference_id|ref_id|booking_id)":\s*"?([A-Za-z0-9_-]+)"?/g;
  const extractedIds: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = idPattern.exec(allBodiesConcat)) !== null) {
    if (match[1]) extractedIds.push(match[1]);
  }
  if (extractedIds.length > 1) {
    const uniqueIds = new Set(extractedIds);
    if (uniqueIds.size < extractedIds.length) {
      indicators.push(
        `Duplicate IDs in responses: ${extractedIds.length} total, ${uniqueIds.size} unique`,
      );
    }
  }

  return {
    raceDetected: indicators.length > 0,
    indicators,
  };
}

// ─── Concurrent Burst ────────────────────────────────────────────────

/**
 * Fire N concurrent requests to a state-changing endpoint and analyze
 * the responses for race condition indicators.
 *
 * Uses a single Playwright page per request (isolated cookie jars) and
 * fires them all at once via Promise.all to maximize timing overlap.
 */
async function testConcurrentBurst(
  context: BrowserContext,
  url: string,
  method: string,
  body: string | undefined,
  headers: Record<string, string>,
  concurrency: number,
  timeout: number,
  requestLogger?: RequestLogger,
): Promise<BurstResult> {
  const results: BurstResponseEntry[] = [];

  // Fire N requests simultaneously — each on its own page for isolation
  const promises = Array.from({ length: concurrency }, async (_, i) => {
    const page = await context.newPage();
    try {
      const start = Date.now();
      const resp = await page.request.fetch(url, {
        method,
        data: body,
        headers: Object.keys(headers).length > 0 ? headers : undefined,
        timeout,
      });
      const entry: BurstResponseEntry = {
        status: resp.status(),
        body: (await resp.text().catch(() => '')).slice(0, 1000),
        timeMs: Date.now() - start,
      };
      results.push(entry);

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method,
        url,
        responseStatus: entry.status,
        phase: `active-race-burst-${i}`,
      });
    } catch (err) {
      log.debug(`Race burst ${i}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }
  });

  await Promise.allSettled(promises);

  const analysis = analyzeBurstResults(results);

  return {
    responses: results,
    ...analysis,
  };
}

// ─── Check Implementation ─────────────────────────────────────────────

/**
 * Race Condition / TOCTOU (Time-of-Check to Time-of-Use) check.
 *
 * Tests state-changing endpoints for race condition vulnerabilities by sending
 * multiple concurrent requests. Detects:
 * - Double-processing (multiple 2xx when only one should succeed)
 * - Inconsistent state (different response bodies under concurrency)
 * - Duplicate transaction IDs in responses
 * - Mixed success/error status codes (fragile concurrency handling)
 *
 * Common bounty findings:
 * - Double-spend (apply coupon twice, transfer money twice)
 * - Voting/like manipulation
 * - Race-condition privilege escalation
 * - Inventory oversell
 *
 * OWASP: A04:2021 - Insecure Design
 */
export const raceCheck: ActiveCheck = {
  name: 'race',
  category: 'race-condition',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Only run on deep or standard profiles — race tests are noisy
    if (config.profile === 'quick') {
      log.info('Race condition check: skipped (quick profile)');
      return findings;
    }

    // Identify state-changing endpoints
    const raceTargets = identifyRaceTargets(targets);
    if (raceTargets.length === 0) {
      log.info('Race condition check: no state-changing endpoints found');
      return findings;
    }

    const concurrency = config.profile === 'deep' ? 15 : RACE_CONCURRENCY;
    log.info(`Testing ${raceTargets.length} endpoint(s) for race conditions (concurrency=${concurrency})...`);

    for (const target of raceTargets) {
      try {
        const headers: Record<string, string> = {};
        if (target.contentType) {
          headers['Content-Type'] = target.contentType;
        }

        const burst = await testConcurrentBurst(
          context,
          target.url,
          target.method,
          target.body,
          headers,
          concurrency,
          config.timeout,
          requestLogger,
        );

        if (burst.raceDetected) {
          findings.push(burstToFinding(target, burst, concurrency));
        }
      } catch (err) {
        log.debug(`Race check for ${target.url}: ${(err as Error).message}`);
      }
    }

    log.info(`Race condition check: ${findings.length} finding(s)`);
    return findings;
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────

interface RaceTarget {
  url: string;
  method: 'GET' | 'POST';
  body?: string;
  contentType?: string;
  description: string;
}

/**
 * Identify endpoints that are candidates for race condition testing.
 */
function identifyRaceTargets(targets: ScanTargets): RaceTarget[] {
  const results: RaceTarget[] = [];
  const seen = new Set<string>();

  // Check forms — state-changing form submissions
  for (const form of targets.forms) {
    const action = form.action || form.pageUrl;
    if (TRANSACTION_FORM_RE.test(action) && !seen.has(action)) {
      seen.add(action);
      const body = form.inputs
        .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(i.value || 'test')}`)
        .join('&');
      results.push({
        url: action,
        method: form.method.toUpperCase() === 'GET' ? 'GET' : 'POST',
        body,
        contentType: 'application/x-www-form-urlencoded',
        description: `Form submission to ${new URL(action).pathname}`,
      });
    }
  }

  // Check API endpoints for state-changing paths
  for (const url of targets.apiEndpoints) {
    if (STATE_CHANGE_RE.test(url) && !seen.has(url)) {
      seen.add(url);
      results.push({
        url,
        method: 'POST',
        body: JSON.stringify({}),
        contentType: 'application/json',
        description: `API endpoint ${new URL(url).pathname}`,
      });
    }
  }

  // Check regular pages for state-changing paths
  for (const page of targets.pages) {
    if (STATE_CHANGE_RE.test(page) && !seen.has(page)) {
      seen.add(page);
      results.push({
        url: page,
        method: 'GET',
        description: `Page ${new URL(page).pathname}`,
      });
    }
  }

  return results.slice(0, 5); // Cap at 5 targets
}

/**
 * Convert a BurstResult into a RawFinding with structured evidence.
 */
function burstToFinding(
  target: RaceTarget,
  burst: BurstResult,
  concurrency: number,
): RawFinding {
  const successCount = burst.responses.filter((r) => r.status >= 200 && r.status < 300).length;
  const allIdentical = new Set(burst.responses.map((r) => r.body).filter(Boolean)).size <= 1;
  const avgTimeMs = burst.responses.length > 0
    ? Math.round(burst.responses.reduce((sum, r) => sum + r.timeMs, 0) / burst.responses.length)
    : 0;

  // Severity: high if duplicate IDs found (concrete double-processing), medium otherwise
  const hasDuplicateIds = burst.indicators.some((i) => i.includes('Duplicate IDs'));
  const severity = hasDuplicateIds ? 'high' : 'medium';

  // Confidence: high if multiple strong indicators, medium for single indicator
  let confidence: 'high' | 'medium' | 'low';
  if (burst.indicators.length >= 2 || hasDuplicateIds) {
    confidence = 'high';
  } else if (successCount > 1 && allIdentical) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  const pathname = new URL(target.url).pathname;

  return {
    id: randomUUID(),
    category: 'race-condition',
    severity,
    title: `Race Condition on ${target.description}`,
    description: [
      `Sent ${concurrency} concurrent ${target.method} requests to ${pathname}.`,
      ...burst.indicators.map((ind) => `- ${ind}`),
      '',
      'This may allow double-spend, coupon reuse, vote manipulation, or other TOCTOU attacks.',
      'The endpoint should use database-level locks, idempotency keys, or optimistic concurrency control.',
    ].join('\n'),
    url: target.url,
    evidence: [
      `Concurrent requests: ${concurrency}`,
      `Successful responses: ${successCount}/${burst.responses.length}`,
      `Status codes: ${burst.responses.map((r) => r.status).join(', ')}`,
      `Unique response bodies: ${new Set(burst.responses.map((r) => r.body).filter(Boolean)).size}`,
      `Average response time: ${avgTimeMs}ms`,
      allIdentical
        ? 'All responses identical (no concurrency control detected)'
        : 'Responses varied under concurrency',
      '',
      'Race indicators:',
      ...burst.indicators.map((ind) => `  - ${ind}`),
    ].join('\n'),
    request: {
      method: target.method,
      url: target.url,
      body: target.body,
    },
    response: { status: burst.responses[0]?.status ?? 0 },
    timestamp: new Date().toISOString(),
    confidence,
    evidencePack: {
      detectionMethod: 'race-condition-burst',
      responseIndicators: burst.indicators,
    },
  };
}

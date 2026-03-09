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

/**
 * Race Condition / TOCTOU (Time-of-Check to Time-of-Use) check.
 *
 * Tests state-changing endpoints for race condition vulnerabilities by sending
 * multiple concurrent requests. If all requests succeed when only one should,
 * the endpoint lacks proper concurrency control.
 *
 * Common bounty findings:
 * - Double-spend (apply coupon twice, transfer money twice)
 * - Voting/like manipulation
 * - Race-condition privilege escalation
 * - Inventory oversell
 *
 * OWASP: A04:2021 – Insecure Design
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

    log.info(`Testing ${raceTargets.length} endpoint(s) for race conditions...`);

    for (const target of raceTargets) {
      const finding = target.method === 'POST'
        ? await testPostRace(context, target, config, requestLogger)
        : await testGetRace(context, target, config, requestLogger);
      if (finding) findings.push(finding);
    }

    log.info(`Race condition check: ${findings.length} finding(s)`);
    return findings;
  },
};

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
 * Test a POST endpoint for race conditions by sending concurrent requests.
 */
async function testPostRace(
  context: BrowserContext,
  target: RaceTarget,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const statuses: number[] = [];
  const bodies: string[] = [];

  // Send RACE_CONCURRENCY requests simultaneously
  const promises = Array.from({ length: RACE_CONCURRENCY }, async (_, i) => {
    const page = await context.newPage();
    try {
      const response = await page.request.fetch(target.url, {
        method: 'POST',
        headers: target.contentType ? { 'Content-Type': target.contentType } : undefined,
        data: target.body,
        timeout: config.timeout,
      });
      const status = response.status();
      const body = await response.text().catch(() => '');
      statuses.push(status);
      bodies.push(body.slice(0, 500));

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'POST',
        url: target.url,
        responseStatus: status,
        phase: `active-race-${i}`,
      });
    } catch (err) {
      log.debug(`Race test ${i}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }
  });

  await Promise.allSettled(promises);

  return analyzeRaceResults(target, statuses, bodies);
}

/**
 * Test a GET endpoint for race conditions.
 */
async function testGetRace(
  context: BrowserContext,
  target: RaceTarget,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const statuses: number[] = [];
  const bodies: string[] = [];

  const promises = Array.from({ length: RACE_CONCURRENCY }, async (_, i) => {
    const page = await context.newPage();
    try {
      const response = await page.request.fetch(target.url, {
        timeout: config.timeout,
      });
      const status = response.status();
      const body = await response.text().catch(() => '');
      statuses.push(status);
      bodies.push(body.slice(0, 500));

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url: target.url,
        responseStatus: status,
        phase: `active-race-${i}`,
      });
    } catch (err) {
      log.debug(`Race test ${i}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }
  });

  await Promise.allSettled(promises);

  return analyzeRaceResults(target, statuses, bodies);
}

/**
 * Analyze race condition test results.
 * If all concurrent requests succeeded (2xx), the endpoint likely lacks proper
 * concurrency control (no mutex/lock, no idempotency key, no optimistic locking).
 */
function analyzeRaceResults(
  target: RaceTarget,
  statuses: number[],
  bodies: string[],
): RawFinding | null {
  if (statuses.length < RACE_CONCURRENCY / 2) return null; // Too many failures

  const successCount = statuses.filter((s) => s >= 200 && s < 300).length;
  const uniqueBodies = new Set(bodies.filter(Boolean));

  // If ALL concurrent requests succeeded → likely vulnerable
  // A properly protected endpoint would let only one through (or return 409/429 for the rest)
  if (successCount >= RACE_CONCURRENCY - 1) {
    // Additional signal: if all responses are identical, the server processed each independently
    const allIdentical = uniqueBodies.size <= 1;

    return {
      id: randomUUID(),
      category: 'race-condition',
      severity: 'medium',
      title: `Potential Race Condition on ${target.description}`,
      description: `Sent ${RACE_CONCURRENCY} concurrent ${target.method} requests to ${new URL(target.url).pathname} — all ${successCount} returned success (HTTP 2xx).${allIdentical ? ' All responses were identical, suggesting each request was processed independently without concurrency control.' : ''} This may allow double-spend, coupon reuse, vote manipulation, or other TOCTOU attacks. The endpoint should use database-level locks, idempotency keys, or optimistic concurrency control.`,
      url: target.url,
      evidence: [
        `Concurrent requests: ${RACE_CONCURRENCY}`,
        `Successful responses: ${successCount}/${statuses.length}`,
        `Status codes: ${statuses.join(', ')}`,
        `Unique response bodies: ${uniqueBodies.size}`,
        allIdentical ? 'All responses identical (no concurrency control detected)' : 'Responses varied (may have partial protection)',
      ].join('\n'),
      request: {
        method: target.method,
        url: target.url,
        body: target.body,
      },
      response: { status: statuses[0] },
      timestamp: new Date().toISOString(),
    };
  }

  return null;
}

/**
 * HTTP Request Smuggling Check (CWE-444)
 *
 * Tests for HTTP request smuggling via Content-Length / Transfer-Encoding
 * desync between front-end (proxy/CDN/load balancer) and back-end server.
 *
 * Techniques:
 * - CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
 * - TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
 * - TE.TE: Both use Transfer-Encoding but one can be confused via obfuscation
 *
 * Detection: timing-based differential response analysis.
 * We send requests that would cause a timeout on the back-end if the
 * desync exists (the smuggled portion is treated as the start of the
 * next request, which hangs waiting for more data).
 *
 * SAFE: These probes do NOT inject malicious smuggled requests that affect
 * other users. They only cause self-inflicted delays detectable by timing.
 */

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

// ─── Smuggling Probe Definitions ───────────────────────────────────────

interface SmugglingProbe {
  name: string;
  technique: 'CL.TE' | 'TE.CL' | 'TE.TE';
  /** Headers to send */
  headers: Record<string, string>;
  /** Raw body to send */
  body: string;
  /** Expected behavior: if smuggling exists, response takes longer than this (ms) */
  timeoutThreshold: number;
  description: string;
}

/**
 * CL.TE probes: Front-end uses Content-Length, back-end uses Transfer-Encoding.
 * We send a request where CL says the body is short but TE (chunked) says there's
 * more data. If the back-end uses TE, it waits for the final chunk → timeout.
 */
const CL_TE_PROBES: SmugglingProbe[] = [
  {
    name: 'cl-te-basic',
    technique: 'CL.TE',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '4',
      'Transfer-Encoding': 'chunked',
    },
    // CL=4 covers "1\r\n" but TE expects a 0\r\n\r\n terminator
    body: '1\r\nZ\r\nQ',
    timeoutThreshold: 5000,
    description: 'CL.TE basic — front-end reads 4 bytes (CL), back-end parses chunks (TE) and waits for 0-terminator',
  },
  {
    name: 'cl-te-prefix',
    technique: 'CL.TE',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '6',
      'Transfer-Encoding': 'chunked',
    },
    body: '0\r\n\r\nX',
    timeoutThreshold: 5000,
    description: 'CL.TE prefix — CL=6 includes terminator + extra byte; back-end sees complete chunked but leftover X poisons next request',
  },
];

/**
 * TE.CL probes: Front-end uses Transfer-Encoding, back-end uses Content-Length.
 * We send a chunked request with CL shorter than the actual body. Back-end reads
 * only CL bytes, leaving the rest in the buffer → delays or errors.
 */
const TE_CL_PROBES: SmugglingProbe[] = [
  {
    name: 'te-cl-basic',
    technique: 'TE.CL',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '3',
      'Transfer-Encoding': 'chunked',
    },
    // Full chunked body = "8\r\nSMUGGLED\r\n0\r\n\r\n" but CL=3 means back-end reads only "8\r\n"
    body: '8\r\nSMUGGLED\r\n0\r\n\r\n',
    timeoutThreshold: 5000,
    description: 'TE.CL basic — front-end forwards full chunked body, back-end reads only 3 bytes (CL), leftover causes desync',
  },
];

/**
 * TE.TE probes: Both use Transfer-Encoding but one can be confused by obfuscation.
 * We send obfuscated TE headers to see if one side ignores it.
 */
const TE_TE_PROBES: SmugglingProbe[] = [
  {
    name: 'te-te-obfuscated-tab',
    technique: 'TE.TE',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '4',
      'Transfer-Encoding': 'chunked',
      'Transfer-encoding': 'cow',  // Lowercase duplicate — some servers pick first, others last
    },
    body: '1\r\nZ\r\nQ',
    timeoutThreshold: 5000,
    description: 'TE.TE duplicate header — servers may disagree on which Transfer-Encoding value to use',
  },
  {
    name: 'te-te-space-before-colon',
    technique: 'TE.TE',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '4',
      'Transfer-Encoding': ' chunked',  // Leading space — some parsers trim, others reject
    },
    body: '1\r\nZ\r\nQ',
    timeoutThreshold: 5000,
    description: 'TE.TE leading space — front-end may accept "chunked", back-end may reject padded value',
  },
];

const ALL_PROBES = [...CL_TE_PROBES, ...TE_CL_PROBES, ...TE_TE_PROBES];

// ─── Main Check ────────────────────────────────────────────────────────

export const requestSmugglingCheck: ActiveCheck = {
  name: 'request-smuggling',
  category: 'request-smuggling',
  parallel: false,
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Skip in quick mode — smuggling testing requires timing analysis
    if (config.profile === 'quick') return findings;

    // Need pages to test against
    if (targets.pages.length === 0 && targets.apiEndpoints.length === 0) {
      log.info('Request smuggling: no endpoints to test');
      return findings;
    }

    // Test top 2 URLs (standard) or top 5 (deep)
    const urlLimit = config.profile === 'deep' ? 5 : 2;
    const candidateUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])].slice(0, urlLimit);

    // Profile-based probe selection
    const probes = config.profile === 'deep' ? ALL_PROBES : ALL_PROBES.slice(0, 3);

    log.info(`Testing ${candidateUrls.length} URLs for HTTP request smuggling (${probes.length} probes)...`);

    for (const url of candidateUrls) {
      // First, establish a baseline response time
      const baseline = await measureBaselineTime(url, config);
      if (baseline < 0) {
        log.debug(`Request smuggling: could not establish baseline for ${url}`);
        continue;
      }

      for (const probe of probes) {
        const finding = await testSmugglingProbe(url, probe, baseline, config, requestLogger);
        if (finding) {
          findings.push(finding);
          // One finding per URL is enough
          break;
        }
        await delay(config.requestDelay);
      }

      if (findings.length > 0) break; // Critical finding — stop
      await delay(config.requestDelay);
    }

    return findings;
  },
};

// ─── Baseline Measurement ──────────────────────────────────────────────

async function measureBaselineTime(url: string, config: ScanConfig): Promise<number> {
  const times: number[] = [];

  for (let i = 0; i < 3; i++) {
    const start = Date.now();
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'x=1',
        signal: AbortSignal.timeout(config.timeout),
      });
      await resp.text();
      times.push(Date.now() - start);
    } catch {
      return -1; // Can't reach the target
    }
    await delay(50);
  }

  // Return median
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)];
}

// ─── Smuggling Probe Test ──────────────────────────────────────────────

async function testSmugglingProbe(
  url: string,
  probe: SmugglingProbe,
  baselineMs: number,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  // Use raw fetch with a short timeout — if the request takes much longer
  // than baseline, it suggests the back-end is waiting for more data (desync)
  const probeTimeout = Math.max(probe.timeoutThreshold + baselineMs, 10000);
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), probeTimeout);

    const resp = await fetch(url, {
      method: 'POST',
      headers: probe.headers,
      body: probe.body,
      signal: controller.signal,
      // @ts-expect-error -- Node.js specific: disable auto-decompression
      compress: false,
    });

    clearTimeout(timer);
    const elapsed = Date.now() - start;
    await resp.text();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'POST',
      url,
      responseStatus: resp.status,
      phase: 'active-request-smuggling',
    });

    // Significant delay compared to baseline suggests desync
    // The threshold is: elapsed > baseline + probe.timeoutThreshold * 0.8
    // (80% of the expected delay — tighter to reduce FPs from network jitter)
    // Also require minimum 2000ms absolute difference to filter noise
    const delayThreshold = baselineMs + probe.timeoutThreshold * 0.8;
    const absoluteDiff = elapsed - baselineMs;
    if (elapsed > delayThreshold && absoluteDiff > 2000) {
      log.info(`Request smuggling: ${probe.name} — ${elapsed}ms vs baseline ${baselineMs}ms on ${url}`);

      return {
        id: randomUUID(),
        category: 'request-smuggling',
        severity: 'critical',
        title: `HTTP Request Smuggling — ${probe.technique}`,
        description: `The server exhibits timing differences consistent with ${probe.technique} request smuggling. ${probe.description}. This can allow an attacker to bypass security controls, poison the web cache, steal credentials from other users, or achieve request hijacking.`,
        url,
        evidence: [
          `Technique: ${probe.technique} (${probe.name})`,
          `Baseline response time: ${baselineMs}ms`,
          `Probe response time: ${elapsed}ms`,
          `Delay threshold: ${delayThreshold.toFixed(0)}ms`,
          `HTTP status: ${resp.status}`,
        ].join('\n'),
        request: {
          method: 'POST',
          url,
          headers: probe.headers,
          body: probe.body,
        },
        response: {
          status: resp.status,
        },
        timestamp: new Date().toISOString(),
        confidence: elapsed > baselineMs + probe.timeoutThreshold ? 'high' : 'medium',
        evidencePack: {
          payloadUsed: probe.body,
          responseIndicators: [`${elapsed}ms delay (baseline: ${baselineMs}ms)`],

        },
      };
    }

    // Also check for specific error responses that suggest TE processing
    if (resp.status === 400 && probe.technique === 'CL.TE') {
      // 400 on CL.TE probe when baseline was 200 suggests TE is being processed
      // but this alone isn't conclusive — log for analysis
      log.debug(`Request smuggling: ${probe.name} got 400 (possible TE processing) on ${url}`);
    }
  } catch (err) {
    const elapsed = Date.now() - start;
    const errorMsg = (err as Error).message;

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'POST',
      url,
      responseStatus: 0,
      phase: 'active-request-smuggling',
    });

    // Timeout/abort after significant delay = strong indicator
    // Require 80% of threshold + 2000ms absolute minimum to avoid FPs
    if ((errorMsg.includes('abort') || errorMsg.includes('timeout')) && elapsed > baselineMs + probe.timeoutThreshold * 0.8 && elapsed - baselineMs > 2000) {
      log.info(`Request smuggling: ${probe.name} — timeout after ${elapsed}ms (baseline ${baselineMs}ms) on ${url}`);

      return {
        id: randomUUID(),
        category: 'request-smuggling',
        severity: 'critical',
        title: `HTTP Request Smuggling — ${probe.technique} (timeout)`,
        description: `The server timed out on a ${probe.technique} smuggling probe, suggesting the back-end is waiting for additional data due to a CL/TE desync. ${probe.description}.`,
        url,
        evidence: [
          `Technique: ${probe.technique} (${probe.name})`,
          `Baseline response time: ${baselineMs}ms`,
          `Probe timed out after: ${elapsed}ms`,
          `Error: ${errorMsg}`,
        ].join('\n'),
        request: {
          method: 'POST',
          url,
          headers: probe.headers,
          body: probe.body,
        },
        timestamp: new Date().toISOString(),
        confidence: 'medium',
        evidencePack: {
          payloadUsed: probe.body,
          responseIndicators: [`Timeout after ${elapsed}ms (baseline: ${baselineMs}ms)`],

        },
      };
    }

    log.debug(`Request smuggling: ${probe.name} error on ${url}: ${errorMsg}`);
  }

  return null;
}

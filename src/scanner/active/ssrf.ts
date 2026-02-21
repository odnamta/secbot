import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, Severity } from '../types.js';
import { SSRF_PAYLOADS, SSRF_PARAM_PATTERNS, SSRF_INDICATORS, getSSRFPayloads } from '../../config/payloads/ssrf.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

export const ssrfCheck: ActiveCheck = {
  name: 'ssrf',
  category: 'ssrf',
  async run(context, targets, config, requestLogger) {
    // Find URLs with parameters matching SSRF-relevant names
    const ssrfTargets = targets.urlsWithParams.filter((u) => SSRF_PARAM_PATTERNS.test(u));

    if (ssrfTargets.length === 0) return [];

    log.info(`Testing ${ssrfTargets.length} URLs for SSRF...`);
    return testSsrf(context, ssrfTargets, config, requestLogger);
  },
};

/** Determine severity based on payload type */
function getSeverity(payload: string): Severity {
  // Cloud metadata or file:// access = critical
  if (payload.includes('169.254.169.254') || payload.includes('metadata.google') ||
      payload.includes('100.100.100.200') || payload.startsWith('file://')) {
    return 'critical';
  }
  // Internal port scanning = high
  if (/127\.0\.0\.1:\d+/.test(payload)) {
    return 'high';
  }
  // Localhost/loopback access = high
  return 'high';
}

async function testSsrf(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Get base payloads (limited for non-deep profiles)
  const basePayloads = config.profile === 'deep' ? SSRF_PAYLOADS : SSRF_PAYLOADS.slice(0, 4);

  // Get callback payloads if callback URL is configured
  const callbackPayloads = config.callbackUrl
    ? getSSRFPayloads(config.callbackUrl).filter((p) => !SSRF_PAYLOADS.includes(p))
    : [];

  if (callbackPayloads.length > 0) {
    log.info(`Including ${callbackPayloads.length} callback-based SSRF payloads for blind detection`);
  }

  // All payloads: base first, then callback payloads
  const payloadsToTest = [...basePayloads, ...callbackPayloads];

  let callbacksInjected = 0;

  for (const originalUrl of urls) {
    let foundForUrl = false;

    // Parse URL and find SSRF-relevant parameters
    const parsed = new URL(originalUrl);
    const ssrfParams = Array.from(parsed.searchParams.keys()).filter((k) =>
      /^(url|link|src|image|proxy|callback|fetch|load|uri|href|path|file|resource|target|site|page|data)$/i.test(k),
    );

    if (ssrfParams.length === 0) continue;

    // Get baseline response for comparison
    let baselineStatus: number | null = null;
    const baselinePage = await context.newPage();
    try {
      const baselineResponse = await baselinePage.request.fetch(originalUrl);
      baselineStatus = baselineResponse.status();
    } catch {
      // Baseline fetch may fail
    } finally {
      await baselinePage.close();
    }

    for (const param of ssrfParams) {
      if (foundForUrl) break;

      for (const payload of payloadsToTest) {
        const isCallbackPayload = config.callbackUrl && payload.includes(config.callbackUrl.replace(/\/+$/, ''));

        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, payload);

        const page = await context.newPage();
        try {
          const response = await page.request.fetch(testUrl.href);
          const body = await response.text();
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            responseStatus: status,
            phase: isCallbackPayload ? 'active-ssrf-callback' : 'active-ssrf',
          });

          if (isCallbackPayload) {
            // For callback payloads, we just inject and count — verification
            // happens on the user's callback server (Burp Collaborator, interactsh, etc.)
            callbacksInjected++;
            log.debug(`Injected callback SSRF payload: ${payload} into param "${param}" at ${originalUrl}`);
            // Don't break — keep injecting callback payloads even if we found something with base payloads
          } else {
            // Check response body for SSRF indicators
            for (const indicator of SSRF_INDICATORS) {
              if (indicator.test(body)) {
                findings.push({
                  id: randomUUID(),
                  category: 'ssrf',
                  severity: getSeverity(payload),
                  title: `SSRF via "${param}" Parameter`,
                  description: `The parameter "${param}" allows the server to make requests to internal or restricted resources. The response contains evidence of successful internal access.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nIndicator matched: ${indicator.source}\nResponse snippet: ${body.slice(0, 300)}`,
                  request: { method: 'GET', url: testUrl.href },
                  response: { status, bodySnippet: body.slice(0, 200) },
                  timestamp: new Date().toISOString(),
                });
                foundForUrl = true;
                break;
              }
            }

            // Also check: if status differs from baseline, the server may have fetched something
            if (!foundForUrl && baselineStatus !== null && status !== baselineStatus) {
              // Status difference alone is weaker evidence, but still noteworthy
              // Only flag if it's a potentially interesting status change
              if (status === 200 && baselineStatus !== 200) {
                findings.push({
                  id: randomUUID(),
                  category: 'ssrf',
                  severity: getSeverity(payload),
                  title: `Potential SSRF via "${param}" Parameter`,
                  description: `The parameter "${param}" caused a different response status when given an internal URL, suggesting the server attempted to fetch it.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nBaseline status: ${baselineStatus}\nPayload status: ${status}`,
                  request: { method: 'GET', url: testUrl.href },
                  response: { status, bodySnippet: body.slice(0, 200) },
                  timestamp: new Date().toISOString(),
                });
                foundForUrl = true;
              }
            }

            if (foundForUrl) break;
          }
        } catch (err) {
          log.debug(`SSRF test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  if (callbacksInjected > 0) {
    log.info(`Injected ${callbacksInjected} callback URLs for blind SSRF detection. Check your callback server for hits.`);
  }

  return findings;
}

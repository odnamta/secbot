import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, Severity } from '../types.js';
import { SSRF_PAYLOADS, SSRF_PARAM_PATTERNS, SSRF_INDICATORS, getSSRFPayloads } from '../../config/payloads/ssrf.js';
import { generateDnsCanary } from '../oob/dns-canary.js';
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

  // Generate DNS canary payloads for out-of-band detection via DNS resolution.
  // These complement the HTTP callback payloads — even when outbound HTTP is blocked,
  // DNS queries often succeed because they go through the system resolver.
  const dnsCanaryPayloads: string[] = [];
  if (config.callbackUrl) {
    try {
      const callbackDomain = new URL(config.callbackUrl).hostname;
      // Generate several DNS canary subdomains for different SSRF vectors
      const canaryPrefixes = ['ssrf-http', 'ssrf-dns', 'ssrf-redirect', 'ssrf-file'];
      for (const prefix of canaryPrefixes) {
        const canaryId = `${prefix}-${randomUUID().slice(0, 8)}`;
        const canaryDomain = generateDnsCanary(canaryId, callbackDomain);
        // HTTP URL pointing to DNS canary subdomain
        dnsCanaryPayloads.push(`http://${canaryDomain}/`);
        // DNS-only: just the domain (useful for DNS rebinding / resolution-only vectors)
        dnsCanaryPayloads.push(`https://${canaryDomain}/`);
      }
      log.info(`Including ${dnsCanaryPayloads.length} DNS canary payloads for OOB SSRF detection`);
    } catch (err) {
      log.debug(`DNS canary generation failed: ${(err as Error).message}`);
    }
  }

  // All payloads: base first, then callback payloads, then DNS canaries
  const payloadsToTest = [...basePayloads, ...callbackPayloads, ...dnsCanaryPayloads];

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
        const isDnsCanary = dnsCanaryPayloads.includes(payload);
        const isOobPayload = isCallbackPayload || isDnsCanary;

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
            phase: isDnsCanary ? 'active-ssrf-dns-canary' : (isCallbackPayload ? 'active-ssrf-callback' : 'active-ssrf'),
          });

          if (isOobPayload) {
            // For callback/DNS canary payloads, we just inject and count — verification
            // happens on the user's callback server (Burp Collaborator, interactsh, etc.)
            callbacksInjected++;
            log.debug(`Injected ${isDnsCanary ? 'DNS canary' : 'callback'} SSRF payload: ${payload} into param "${param}" at ${originalUrl}`);
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

            // Also check: if status differs from baseline AND body contains SSRF indicators,
            // the server may have fetched the internal resource. Require dual signal to
            // avoid false positives from parameters that merely influence page routing.
            if (!foundForUrl && baselineStatus !== null && status !== baselineStatus) {
              if (status === 200 && baselineStatus !== 200) {
                // Dual signal: status change is necessary but not sufficient —
                // body must also contain an SSRF indicator pattern
                const bodyHasIndicator = SSRF_INDICATORS.some((ind) => ind.test(body));
                if (bodyHasIndicator) {
                  const matchedIndicator = SSRF_INDICATORS.find((ind) => ind.test(body));
                  findings.push({
                    id: randomUUID(),
                    category: 'ssrf',
                    severity: getSeverity(payload),
                    title: `Potential SSRF via "${param}" Parameter`,
                    description: `The parameter "${param}" caused a different response status when given an internal URL, and the response body contains evidence of internal resource access.`,
                    url: originalUrl,
                    evidence: `Payload: ${payload}\nBaseline status: ${baselineStatus}\nPayload status: ${status}\nIndicator matched: ${matchedIndicator?.source ?? 'unknown'}`,
                    request: { method: 'GET', url: testUrl.href },
                    response: { status, bodySnippet: body.slice(0, 200) },
                    timestamp: new Date().toISOString(),
                  });
                  foundForUrl = true;
                }
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

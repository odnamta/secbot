import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { CMDI_PAYLOADS_OUTPUT, CMDI_PAYLOADS_TIMING } from '../../config/payloads/cmdi.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

/** Threshold in ms — if response is this much slower than baseline, flag it */
const CMDI_TIMING_THRESHOLD_MS = 4000;

export const cmdiCheck: ActiveCheck = {
  name: 'cmdi',
  category: 'command-injection',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Test URL parameters
    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for command injection...`);
      const paramFindings = await testCmdiParams(context, targets.urlsWithParams, config, requestLogger);
      findings.push(...paramFindings);
    }

    // Test form inputs
    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for command injection...`);
      const formFindings = await testCmdiForms(context, targets.forms, config, requestLogger);
      findings.push(...formFindings);
    }

    return findings;
  },
};

/**
 * Measure response time using median of 3 requests for reliable timing.
 */
async function measureResponseTime(
  context: BrowserContext,
  url: string,
): Promise<number> {
  const times: number[] = [];
  for (let i = 0; i < 3; i++) {
    const page = await context.newPage();
    try {
      const start = Date.now();
      await page.request.fetch(url);
      times.push(Date.now() - start);
    } catch {
      // Skip failed measurements
    } finally {
      await page.close();
    }
  }
  if (times.length === 0) return -1;
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)]; // median
}

async function testCmdiParams(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const outputPayloads = config.profile === 'deep' ? CMDI_PAYLOADS_OUTPUT : CMDI_PAYLOADS_OUTPUT.slice(0, 2);
  const timingPayloads = config.profile === 'deep' ? CMDI_PAYLOADS_TIMING : CMDI_PAYLOADS_TIMING.slice(0, 2);

  for (const originalUrl of urls) {
    let foundForUrl = false;
    const parsed = new URL(originalUrl);
    const params = Array.from(parsed.searchParams.keys());

    if (params.length === 0) continue;

    // Get baseline response for comparison
    let baselineBody = '';
    const baselinePage = await context.newPage();
    try {
      const baselineResponse = await baselinePage.request.fetch(originalUrl);
      baselineBody = await baselineResponse.text();
    } catch {
      // Baseline fetch may fail
    } finally {
      await baselinePage.close();
    }

    for (const param of params) {
      if (foundForUrl) break;

      // --- Output-based detection ---
      for (const { payload, marker } of outputPayloads) {
        if (foundForUrl) break;

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
            phase: 'active-cmdi',
          });

          // Check if the marker appears in the response but was NOT in the baseline
          if (body.includes(marker) && !baselineBody.includes(marker)) {
            findings.push({
              id: randomUUID(),
              category: 'command-injection',
              severity: 'critical',
              title: `Command Injection via "${param}" Parameter`,
              description: `The parameter "${param}" is vulnerable to OS command injection. The injected command's output marker ("${marker}") appeared in the response. This allows Remote Code Execution (RCE).`,
              url: originalUrl,
              evidence: `Payload: ${payload}\nMarker: ${marker}\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method: 'GET', url: testUrl.href },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
            foundForUrl = true;
            break;
          }
        } catch (err) {
          log.debug(`CMDi output test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }

      // --- Timing-based detection (median-of-3) ---
      if (!foundForUrl && config.profile !== 'quick') {
        const baselineMedian = await measureResponseTime(context, originalUrl);

        if (baselineMedian > 0) {
          for (const { payload } of timingPayloads) {
            if (foundForUrl) break;

            const testUrl = new URL(originalUrl);
            testUrl.searchParams.set(param, payload);

            const payloadMedian = await measureResponseTime(context, testUrl.href);

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              phase: 'active-cmdi-timing',
            });

            if (payloadMedian > 0) {
              const diff = payloadMedian - baselineMedian;
              if (diff > CMDI_TIMING_THRESHOLD_MS) {
                findings.push({
                  id: randomUUID(),
                  category: 'command-injection',
                  severity: 'critical',
                  title: `Command Injection (Time-Based) via "${param}" Parameter`,
                  description: `Time-based command injection detected. The median response was ${Math.round(diff)}ms slower when a sleep payload was injected into "${param}". Baseline median: ${Math.round(baselineMedian)}ms, With payload median: ${payloadMedian}ms. This allows Remote Code Execution (RCE).`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${CMDI_TIMING_THRESHOLD_MS}ms)`,
                  request: { method: 'GET', url: testUrl.href },
                  timestamp: new Date().toISOString(),
                });
                foundForUrl = true;
              }
            }

            await delay(config.requestDelay);
          }
        }
      }
    }
  }

  return findings;
}

async function testCmdiForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const outputPayloads = config.profile === 'deep' ? CMDI_PAYLOADS_OUTPUT : CMDI_PAYLOADS_OUTPUT.slice(0, 2);
  const timingPayloads = config.profile === 'deep' ? CMDI_PAYLOADS_TIMING : CMDI_PAYLOADS_TIMING.slice(0, 2);

  for (const form of forms) {
    let foundForForm = false;
    const textInputs = form.inputs.filter(
      (i) => !i.type || ['text', 'search', 'email', 'url', 'tel', 'hidden', ''].includes(i.type),
    );

    if (textInputs.length === 0) continue;

    const actionUrl = new URL(form.action || form.pageUrl, form.pageUrl).href;

    // Get baseline response
    let baselineBody = '';
    const baselinePage = await context.newPage();
    try {
      const baselineResponse = await baselinePage.request.fetch(actionUrl);
      baselineBody = await baselineResponse.text();
    } catch {
      // Baseline may fail
    } finally {
      await baselinePage.close();
    }

    for (const input of textInputs) {
      if (foundForForm) break;

      // --- Output-based detection ---
      for (const { payload, marker } of outputPayloads) {
        if (foundForForm) break;

        // Build form data
        const formData: Record<string, string> = {};
        for (const inp of form.inputs) {
          formData[inp.name] = inp.value || 'test';
        }
        formData[input.name] = payload;

        const page = await context.newPage();
        try {
          const method = form.method.toUpperCase();
          let response;
          if (method === 'POST') {
            response = await page.request.post(actionUrl, { form: formData });
          } else {
            const getUrl = new URL(actionUrl);
            for (const [k, v] of Object.entries(formData)) {
              getUrl.searchParams.set(k, v);
            }
            response = await page.request.fetch(getUrl.href);
          }

          const body = await response.text();
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method,
            url: actionUrl,
            responseStatus: status,
            phase: 'active-cmdi-form',
          });

          if (body.includes(marker) && !baselineBody.includes(marker)) {
            findings.push({
              id: randomUUID(),
              category: 'command-injection',
              severity: 'critical',
              title: `Command Injection via "${input.name}" Form Input`,
              description: `The form input "${input.name}" on ${form.pageUrl} is vulnerable to OS command injection. The injected command's output marker appeared in the response. This allows Remote Code Execution (RCE).`,
              url: form.pageUrl,
              evidence: `Payload: ${payload}\nMarker: ${marker}\nForm action: ${actionUrl}\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method, url: actionUrl, body: JSON.stringify(formData) },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
            foundForForm = true;
            break;
          }
        } catch (err) {
          log.debug(`CMDi form output test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }

      // --- Timing-based detection for forms (median-of-3) ---
      if (!foundForForm && config.profile !== 'quick') {
        const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';
        const baseFormData = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent('test')}`)
          .join('&');

        // Baseline timing
        let baselineMedian: number;
        if (fetchMethod === 'POST') {
          const times: number[] = [];
          for (let i = 0; i < 3; i++) {
            const page = await context.newPage();
            try {
              const start = Date.now();
              await page.request.fetch(actionUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: baseFormData,
              });
              times.push(Date.now() - start);
            } catch {
              // Skip
            } finally {
              await page.close();
            }
          }
          if (times.length === 0) continue;
          times.sort((a, b) => a - b);
          baselineMedian = times[Math.floor(times.length / 2)];
        } else {
          baselineMedian = await measureResponseTime(context, actionUrl);
        }

        if (baselineMedian > 0) {
          for (const { payload } of timingPayloads) {
            if (foundForForm) break;

            const payloadFormData = textInputs
              .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(payload)}`)
              .join('&');

            let payloadMedian: number;
            if (fetchMethod === 'POST') {
              const times: number[] = [];
              for (let i = 0; i < 3; i++) {
                const page = await context.newPage();
                try {
                  const start = Date.now();
                  await page.request.fetch(actionUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    data: payloadFormData,
                  });
                  times.push(Date.now() - start);
                } catch {
                  // Skip
                } finally {
                  await page.close();
                }
              }
              if (times.length === 0) continue;
              times.sort((a, b) => a - b);
              payloadMedian = times[Math.floor(times.length / 2)];
            } else {
              const getUrl = new URL(actionUrl);
              for (const inp of textInputs) {
                getUrl.searchParams.set(inp.name, payload);
              }
              payloadMedian = await measureResponseTime(context, getUrl.href);
            }

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: fetchMethod,
              url: actionUrl,
              phase: 'active-cmdi-form-timing',
            });

            if (payloadMedian > 0) {
              const diff = payloadMedian - baselineMedian;
              if (diff > CMDI_TIMING_THRESHOLD_MS) {
                findings.push({
                  id: randomUUID(),
                  category: 'command-injection',
                  severity: 'critical',
                  title: `Command Injection (Time-Based) via "${input.name}" Form Input`,
                  description: `Time-based command injection detected in form input "${input.name}" on ${form.pageUrl}. The median response was ${Math.round(diff)}ms slower when a sleep payload was submitted. This allows Remote Code Execution (RCE).`,
                  url: form.pageUrl,
                  evidence: `Payload: ${payload}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${CMDI_TIMING_THRESHOLD_MS}ms)`,
                  request: { method: fetchMethod, url: actionUrl, body: payloadFormData },
                  timestamp: new Date().toISOString(),
                });
                foundForForm = true;
              }
            }

            await delay(config.requestDelay);
          }
        }
      }
    }
  }

  return findings;
}

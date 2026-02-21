import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import {
  SQLI_PAYLOADS,
  SQLI_TIME_PAYLOADS,
  SQL_ERROR_PATTERNS,
  SQLI_BOOLEAN_PAYLOADS,
  SQLI_UNION_ORDER_BY_PROBES,
  NOSQL_PAYLOADS,
  NOSQL_ERROR_PATTERNS,
} from '../../config/payloads/sqli.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

/** Threshold in ms — if response is this much slower than baseline, it's suspicious */
const BLIND_SQLI_THRESHOLD_MS = 1500;

/** Minimum body length difference ratio to flag boolean-based blind SQLi */
const BOOLEAN_BLIND_THRESHOLD = 0.20;

export const sqliCheck: ActiveCheck = {
  name: 'sqli',
  category: 'sqli',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for SQL injection...`);
      findings.push(...(await testSqliOnForms(context, targets.forms, config, requestLogger)));
    }

    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for SQL injection...`);
      findings.push(...(await testSqliOnUrls(context, targets.urlsWithParams, config, requestLogger)));
    }

    return findings;
  },
};

/**
 * Measure response time using median of 3 requests for more reliable timing.
 * Used by time-based blind SQLi detection to reduce false positives from network jitter.
 */
async function measureResponseTime(
  context: BrowserContext,
  url: string,
  options?: { method?: string; headers?: Record<string, string>; data?: string },
): Promise<number> {
  const times: number[] = [];
  for (let i = 0; i < 3; i++) {
    const page = await context.newPage();
    try {
      const start = Date.now();
      if (options?.method && options.method !== 'GET') {
        await page.request.fetch(url, {
          method: options.method,
          headers: options.headers,
          data: options.data,
        });
      } else {
        await page.request.fetch(url);
      }
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

async function testSqliOnForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = config.profile === 'deep' ? SQLI_PAYLOADS : SQLI_PAYLOADS.slice(0, 4);

  for (const form of forms) {
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', 'number', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    // --- Error-based detection ---
    for (const payload of payloads) {
      const page = await context.newPage();

      // Register response handler BEFORE navigation to avoid race condition
      let responseResolve: (() => void) | null = null;
      let responseBody = '';

      page.on('response', async (response) => {
        try {
          const ct = response.headers()['content-type'] ?? '';
          if (ct.includes('text/html') || ct.includes('application/json')) {
            responseBody = await response.text();
            responseResolve?.();
          }
        } catch (err) {
          log.debug(`SQLi response capture: ${(err as Error).message}`);
        }
      });

      try {
        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        for (const input of textInputs) {
          try {
            await page.fill(`[name="${input.name}"]`, payload);
          } catch (err) {
            log.debug(`SQLi fill input: ${(err as Error).message}`);
          }
        }

        // Reset for capturing form submission response
        responseBody = '';
        let responseTimeout: ReturnType<typeof setTimeout> | null = null;
        const submissionResponse = new Promise<void>((resolve) => {
          responseResolve = resolve;
          responseTimeout = setTimeout(resolve, 5000);
        });

        try {
          const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
          if (await submitBtn.count() > 0) {
            await submitBtn.click({ timeout: 5000 });
          } else {
            await page.locator('form').first().evaluate((f) => (f as HTMLFormElement).submit());
          }
          await submissionResponse;
          if (responseTimeout) clearTimeout(responseTimeout);
        } catch (err) {
          log.debug(`SQLi form submit: ${(err as Error).message}`);
          if (responseTimeout) clearTimeout(responseTimeout);
        }

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: form.method,
          url: form.action,
          body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
          phase: 'active-sqli',
        });

        const content = responseBody || (await page.content());

        for (const pattern of SQL_ERROR_PATTERNS) {
          const match = content.match(pattern);
          if (match) {
            findings.push({
              id: randomUUID(),
              category: 'sqli',
              severity: 'critical',
              title: `SQL Injection in Form Input "${textInputs[0].name}"`,
              description: `SQL error message detected when injecting payload into "${textInputs[0].name}". This indicates the input is not properly parameterized.`,
              url: form.pageUrl,
              evidence: `Payload: ${payload}\nSQL error: ${match[0]}`,
              request: {
                method: form.method,
                url: form.action,
                body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
              },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        }
      } catch (err) {
        log.debug(`SQLi form test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);

      if (findings.some((f) => f.category === 'sqli' && f.url === form.pageUrl)) {
        break;
      }
    }

    const hasFormFinding = () => findings.some((f) => f.category === 'sqli' && f.url === form.pageUrl);

    // --- Time-based blind SQLi for forms (improved with median-of-3) ---
    if (config.profile !== 'quick' && !hasFormFinding()) {
      const timePayloads = config.profile === 'deep' ? SQLI_TIME_PAYLOADS : SQLI_TIME_PAYLOADS.slice(0, 1);
      const formBody = textInputs.map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent('test')}`).join('&');
      const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';

      // Establish baseline with median-of-3
      const baselineMedian = await measureResponseTime(context, form.action, {
        method: fetchMethod,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        data: formBody,
      });

      if (baselineMedian > 0) {
        for (const payload of timePayloads) {
          const payloadBody = textInputs
            .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(payload)}`)
            .join('&');

          const payloadMedian = await measureResponseTime(context, form.action, {
            method: fetchMethod,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: payloadBody,
          });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: form.method,
            url: form.action,
            body: payloadBody,
            phase: 'active-sqli-blind',
          });

          if (payloadMedian > 0) {
            const diff = payloadMedian - baselineMedian;
            if (diff > BLIND_SQLI_THRESHOLD_MS) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'high',
                title: `Potential Blind SQL Injection in Form "${textInputs[0].name}"`,
                description: `Time-based blind SQL injection suspected. The median response was ${Math.round(diff)}ms slower when a time-delay payload was submitted via form input "${textInputs[0].name}". Baseline median: ${Math.round(baselineMedian)}ms, With payload median: ${payloadMedian}ms.`,
                url: form.pageUrl,
                evidence: `Payload: ${payload}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                request: {
                  method: form.method,
                  url: form.action,
                  body: payloadBody,
                },
                timestamp: new Date().toISOString(),
              });
              break;
            }
          }

          await delay(config.requestDelay);
        }
      }
    }

    // --- Boolean-based blind SQLi for forms ---
    if (config.profile !== 'quick' && !hasFormFinding()) {
      const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';

      for (const { truePayload, falsePayload } of SQLI_BOOLEAN_PAYLOADS) {
        const trueBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(truePayload)}`)
          .join('&');
        const falseBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(falsePayload)}`)
          .join('&');

        let trueLen = 0;
        let falseLen = 0;

        const truePage = await context.newPage();
        try {
          const resp = await truePage.request.fetch(form.action, {
            method: fetchMethod,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: trueBody,
          });
          trueLen = (await resp.text()).length;
        } catch (err) {
          log.debug(`SQLi boolean true form: ${(err as Error).message}`);
        } finally {
          await truePage.close();
        }

        await delay(config.requestDelay);

        const falsePage = await context.newPage();
        try {
          const resp = await falsePage.request.fetch(form.action, {
            method: fetchMethod,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: falseBody,
          });
          falseLen = (await resp.text()).length;
        } catch (err) {
          log.debug(`SQLi boolean false form: ${(err as Error).message}`);
        } finally {
          await falsePage.close();
        }

        if (trueLen > 0 && falseLen > 0) {
          const maxLen = Math.max(trueLen, falseLen);
          const diff = Math.abs(trueLen - falseLen) / maxLen;
          if (diff > BOOLEAN_BLIND_THRESHOLD) {
            findings.push({
              id: randomUUID(),
              category: 'sqli',
              severity: 'high',
              title: `Potential Boolean-Based Blind SQL Injection in Form "${textInputs[0].name}"`,
              description: `Boolean-based blind SQL injection suspected. The response body length differs significantly between a true condition and a false condition submitted via form input "${textInputs[0].name}".`,
              url: form.pageUrl,
              evidence: `True payload: ${truePayload} (length: ${trueLen})\nFalse payload: ${falsePayload} (length: ${falseLen})\nDifference: ${(diff * 100).toFixed(1)}% (threshold: ${BOOLEAN_BLIND_THRESHOLD * 100}%)`,
              request: {
                method: form.method,
                url: form.action,
                body: trueBody,
              },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        }

        await delay(config.requestDelay);
      }
    }

    // --- NoSQL injection for forms ---
    if (!hasFormFinding()) {
      const nosqlPayloads = config.profile === 'deep' ? NOSQL_PAYLOADS : NOSQL_PAYLOADS.slice(0, 3);
      const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';

      for (const payload of nosqlPayloads) {
        const payloadBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(payload)}`)
          .join('&');

        const page = await context.newPage();
        try {
          const resp = await page.request.fetch(form.action, {
            method: fetchMethod,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: payloadBody,
          });
          const body = await resp.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: form.method,
            url: form.action,
            body: payloadBody,
            responseStatus: resp.status(),
            phase: 'active-nosqli',
          });

          for (const pattern of NOSQL_ERROR_PATTERNS) {
            const match = body.match(pattern);
            if (match) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'high',
                title: `NoSQL Injection in Form Input "${textInputs[0].name}"`,
                description: `NoSQL error message detected when injecting payload into form input "${textInputs[0].name}". This indicates the input may be used in a NoSQL query without proper sanitization.`,
                url: form.pageUrl,
                evidence: `Payload: ${payload}\nNoSQL error: ${match[0]}`,
                request: {
                  method: form.method,
                  url: form.action,
                  body: payloadBody,
                },
                response: { status: resp.status(), bodySnippet: body.slice(0, 300) },
                timestamp: new Date().toISOString(),
              });
              break;
            }
          }
        } catch (err) {
          log.debug(`NoSQL form test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);

        if (hasFormFinding()) break;
      }
    }
  }

  return findings;
}

async function testSqliOnUrls(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const errorPayloads = config.profile === 'deep' ? SQLI_PAYLOADS : SQLI_PAYLOADS.slice(0, 3);
  const timePayloads = config.profile === 'deep' ? SQLI_TIME_PAYLOADS : SQLI_TIME_PAYLOADS.slice(0, 1);

  for (const originalUrl of urls) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(originalUrl);
    } catch (err) {
      log.debug(`SQLi URL parse: ${(err as Error).message}`);
      continue;
    }
    const params = Array.from(parsedUrl.searchParams.keys());
    if (params.length === 0) continue;

    for (const param of params) {
      let foundForParam = false;

      // --- Error-based detection ---
      for (const payload of errorPayloads) {
        if (foundForParam) break;
        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, payload);

        const page = await context.newPage();
        try {
          const response = await page.request.fetch(testUrl.href);
          const body = await response.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            responseStatus: response.status(),
            phase: 'active-sqli',
          });

          for (const pattern of SQL_ERROR_PATTERNS) {
            const match = body.match(pattern);
            if (match) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'critical',
                title: `SQL Injection in URL Parameter "${param}"`,
                description: `SQL error message detected when injecting payload into URL parameter "${param}". This indicates the parameter is directly interpolated into SQL queries.`,
                url: originalUrl,
                evidence: `Payload: ${payload}\nTest URL: ${testUrl.href}\nSQL error: ${match[0]}`,
                request: { method: 'GET', url: testUrl.href },
                response: { status: response.status(), bodySnippet: body.slice(0, 300) },
                timestamp: new Date().toISOString(),
              });
              foundForParam = true;
              break;
            }
          }
        } catch (err) {
          log.debug(`SQLi URL error test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }

      // --- Time-based blind detection (improved with median-of-3) ---
      if (!foundForParam && config.profile !== 'quick') {
        const baselineMedian = await measureResponseTime(context, originalUrl);

        if (baselineMedian > 0) {
          for (const payload of timePayloads) {
            if (foundForParam) break;
            const testUrl = new URL(originalUrl);
            testUrl.searchParams.set(param, payload);

            const payloadMedian = await measureResponseTime(context, testUrl.href);

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              phase: 'active-sqli-blind',
            });

            if (payloadMedian > 0) {
              const diff = payloadMedian - baselineMedian;
              if (diff > BLIND_SQLI_THRESHOLD_MS) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'high',
                  title: `Potential Blind SQL Injection in URL Parameter "${param}"`,
                  description: `Time-based blind SQL injection suspected. The median response was ${Math.round(diff)}ms slower when a time-delay payload was injected into "${param}". Baseline median: ${Math.round(baselineMedian)}ms, With payload median: ${payloadMedian}ms.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                  request: { method: 'GET', url: testUrl.href },
                  timestamp: new Date().toISOString(),
                });
                foundForParam = true;
              }
            }

            await delay(config.requestDelay);
          }
        }
      }

      // --- Boolean-based blind detection ---
      if (!foundForParam && config.profile !== 'quick') {
        for (const { truePayload, falsePayload } of SQLI_BOOLEAN_PAYLOADS) {
          if (foundForParam) break;

          const trueUrl = new URL(originalUrl);
          trueUrl.searchParams.set(param, truePayload);
          const falseUrl = new URL(originalUrl);
          falseUrl.searchParams.set(param, falsePayload);

          let trueLen = 0;
          let falseLen = 0;

          const truePage = await context.newPage();
          try {
            const resp = await truePage.request.fetch(trueUrl.href);
            trueLen = (await resp.text()).length;
          } catch (err) {
            log.debug(`SQLi boolean true URL: ${(err as Error).message}`);
          } finally {
            await truePage.close();
          }

          await delay(config.requestDelay);

          const falsePage = await context.newPage();
          try {
            const resp = await falsePage.request.fetch(falseUrl.href);
            falseLen = (await resp.text()).length;
          } catch (err) {
            log.debug(`SQLi boolean false URL: ${(err as Error).message}`);
          } finally {
            await falsePage.close();
          }

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: trueUrl.href,
            phase: 'active-sqli-boolean',
          });

          if (trueLen > 0 && falseLen > 0) {
            const maxLen = Math.max(trueLen, falseLen);
            const diff = Math.abs(trueLen - falseLen) / maxLen;
            if (diff > BOOLEAN_BLIND_THRESHOLD) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'high',
                title: `Potential Boolean-Based Blind SQL Injection in URL Parameter "${param}"`,
                description: `Boolean-based blind SQL injection suspected. The response body length differs significantly between a true condition (${truePayload}) and a false condition (${falsePayload}) in parameter "${param}".`,
                url: originalUrl,
                evidence: `True payload: ${truePayload} (length: ${trueLen})\nFalse payload: ${falsePayload} (length: ${falseLen})\nDifference: ${(diff * 100).toFixed(1)}% (threshold: ${BOOLEAN_BLIND_THRESHOLD * 100}%)`,
                request: { method: 'GET', url: trueUrl.href },
                timestamp: new Date().toISOString(),
              });
              foundForParam = true;
            }
          }

          await delay(config.requestDelay);
        }
      }

      // --- Union-based detection ---
      if (!foundForParam && config.profile === 'deep') {
        let lastErrorAt = 0;

        // Probe column count with ORDER BY N
        for (let n = 0; n < SQLI_UNION_ORDER_BY_PROBES.length; n++) {
          const probe = SQLI_UNION_ORDER_BY_PROBES[n];
          const testUrl = new URL(originalUrl);
          testUrl.searchParams.set(param, probe);

          const page = await context.newPage();
          try {
            const resp = await page.request.fetch(testUrl.href);
            const body = await resp.text();
            const hasError = SQL_ERROR_PATTERNS.some((p) => p.test(body)) || resp.status() >= 500;

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              responseStatus: resp.status(),
              phase: 'active-sqli-union',
            });

            if (hasError && lastErrorAt === 0) {
              // First probe that errors — column count is n (previous N worked)
              lastErrorAt = n;
              break;
            }
          } catch (err) {
            log.debug(`SQLi union ORDER BY: ${(err as Error).message}`);
            break;
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }

        // If we found where ORDER BY breaks, try UNION SELECT with that column count
        if (lastErrorAt > 0) {
          const columnCount = lastErrorAt; // ORDER BY N+1 failed, so there are N columns
          const nulls = Array.from({ length: columnCount }, () => 'NULL').join(',');
          const unionPayload = `' UNION SELECT ${nulls}--`;
          const testUrl = new URL(originalUrl);
          testUrl.searchParams.set(param, unionPayload);

          const page = await context.newPage();
          try {
            const resp = await page.request.fetch(testUrl.href);
            const body = await resp.text();
            // If no SQL error, the UNION was accepted — vulnerable
            const hasError = SQL_ERROR_PATTERNS.some((p) => p.test(body));
            if (!hasError && resp.status() < 500) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'critical',
                title: `Union-Based SQL Injection in URL Parameter "${param}"`,
                description: `Union-based SQL injection detected. ORDER BY probing determined ${columnCount} columns, and a UNION SELECT with ${columnCount} NULLs was accepted without error.`,
                url: originalUrl,
                evidence: `Payload: ${unionPayload}\nDetected columns: ${columnCount}\nTest URL: ${testUrl.href}`,
                request: { method: 'GET', url: testUrl.href },
                response: { status: resp.status(), bodySnippet: body.slice(0, 300) },
                timestamp: new Date().toISOString(),
              });
              foundForParam = true;
            }
          } catch (err) {
            log.debug(`SQLi union SELECT: ${(err as Error).message}`);
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }
      }

      // --- NoSQL injection detection ---
      if (!foundForParam) {
        const nosqlPayloads = config.profile === 'deep' ? NOSQL_PAYLOADS : NOSQL_PAYLOADS.slice(0, 3);

        for (const payload of nosqlPayloads) {
          if (foundForParam) break;
          const testUrl = new URL(originalUrl);
          testUrl.searchParams.set(param, payload);

          const page = await context.newPage();
          try {
            const response = await page.request.fetch(testUrl.href);
            const body = await response.text();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              responseStatus: response.status(),
              phase: 'active-nosqli',
            });

            for (const pattern of NOSQL_ERROR_PATTERNS) {
              const match = body.match(pattern);
              if (match) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'high',
                  title: `NoSQL Injection in URL Parameter "${param}"`,
                  description: `NoSQL error message detected when injecting payload into URL parameter "${param}". This indicates the parameter may be used in a NoSQL query without proper sanitization.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nTest URL: ${testUrl.href}\nNoSQL error: ${match[0]}`,
                  request: { method: 'GET', url: testUrl.href },
                  response: { status: response.status(), bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                });
                foundForParam = true;
                break;
              }
            }
          } catch (err) {
            log.debug(`NoSQL URL test: ${(err as Error).message}`);
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }
      }
    }
  }

  return findings;
}

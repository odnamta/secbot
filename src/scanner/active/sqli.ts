import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { SQLI_PAYLOADS, SQLI_TIME_PAYLOADS, SQL_ERROR_PATTERNS } from '../../config/payloads/sqli.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

/** Threshold in ms — if response is this much slower than baseline, it's suspicious */
const BLIND_SQLI_THRESHOLD_MS = 1500;

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

    // --- Time-based blind SQLi for forms ---
    if (config.profile !== 'quick' && !findings.some((f) => f.category === 'sqli' && f.url === form.pageUrl)) {
      const timePayloads = config.profile === 'deep' ? SQLI_TIME_PAYLOADS : SQLI_TIME_PAYLOADS.slice(0, 1);

      // Build form body from inputs
      const formBody = textInputs.map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent('test')}`).join('&');

      // Establish baseline with benign POST requests
      const baselineTimes: number[] = [];
      for (let i = 0; i < 2; i++) {
        const page = await context.newPage();
        try {
          const start = Date.now();
          await page.request.fetch(form.action, {
            method: form.method.toUpperCase() === 'GET' ? 'GET' : 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: formBody,
          });
          baselineTimes.push(Date.now() - start);
        } catch (err) {
          log.debug(`SQLi form baseline: ${(err as Error).message}`);
        } finally {
          await page.close();
        }
        await delay(config.requestDelay);
      }

      if (baselineTimes.length > 0) {
        const avgBaseline = baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;

        for (const payload of timePayloads) {
          const payloadBody = textInputs
            .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(payload)}`)
            .join('&');

          const page = await context.newPage();
          try {
            const start = Date.now();
            const response = await page.request.fetch(form.action, {
              method: form.method.toUpperCase() === 'GET' ? 'GET' : 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              data: payloadBody,
            });
            const elapsed = Date.now() - start;

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: form.method,
              url: form.action,
              body: payloadBody,
              responseStatus: response.status(),
              phase: 'active-sqli-blind',
            });

            const diff = elapsed - avgBaseline;
            if (diff > BLIND_SQLI_THRESHOLD_MS) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'high',
                title: `Potential Blind SQL Injection in Form "${textInputs[0].name}"`,
                description: `Time-based blind SQL injection suspected. The response was ${Math.round(diff)}ms slower when a time-delay payload was submitted via form input "${textInputs[0].name}". Baseline: ${Math.round(avgBaseline)}ms, With payload: ${elapsed}ms.`,
                url: form.pageUrl,
                evidence: `Payload: ${payload}\nBaseline: ${Math.round(avgBaseline)}ms\nWith payload: ${elapsed}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                request: {
                  method: form.method,
                  url: form.action,
                  body: payloadBody,
                },
                timestamp: new Date().toISOString(),
              });
              break;
            }
          } catch (err) {
            log.debug(`SQLi blind form test: ${(err as Error).message}`);
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

      // --- Time-based blind detection ---
      if (!foundForParam && config.profile !== 'quick') {
        // Establish baseline response time
        const baselineTimes: number[] = [];
        for (let i = 0; i < 2; i++) {
          const page = await context.newPage();
          try {
            const start = Date.now();
            await page.request.fetch(originalUrl);
            baselineTimes.push(Date.now() - start);
          } catch (err) {
            log.debug(`SQLi URL baseline: ${(err as Error).message}`);
          } finally {
            await page.close();
          }
          await delay(config.requestDelay);
        }

        if (baselineTimes.length === 0) continue;
        const avgBaseline = baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;

        for (const payload of timePayloads) {
          if (foundForParam) break;
          const testUrl = new URL(originalUrl);
          testUrl.searchParams.set(param, payload);

          const page = await context.newPage();
          try {
            const start = Date.now();
            const response = await page.request.fetch(testUrl.href);
            const elapsed = Date.now() - start;

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              responseStatus: response.status(),
              phase: 'active-sqli-blind',
            });

            const diff = elapsed - avgBaseline;
            if (diff > BLIND_SQLI_THRESHOLD_MS) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'high',
                title: `Potential Blind SQL Injection in URL Parameter "${param}"`,
                description: `Time-based blind SQL injection suspected. The response was ${Math.round(diff)}ms slower when a time-delay payload was injected into "${param}". Baseline: ${Math.round(avgBaseline)}ms, With payload: ${elapsed}ms.`,
                url: originalUrl,
                evidence: `Payload: ${payload}\nBaseline: ${Math.round(avgBaseline)}ms\nWith payload: ${elapsed}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                request: { method: 'GET', url: testUrl.href },
                timestamp: new Date().toISOString(),
              });
              foundForParam = true;
            }
          } catch (err) {
            log.debug(`SQLi blind URL test: ${(err as Error).message}`);
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

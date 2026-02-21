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
import { getPolyglotSqli } from '../../utils/polyglot-payloads.js';
import { generateHppVariants } from '../../utils/param-pollution.js';
import { generateBlindSqliPayloads } from '../oob/blind-payloads.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay, measureResponseTime } from '../../utils/shared.js';
import { mutatePayload, pickStrategies, sqlCommentObfuscate } from '../../utils/payload-mutator.js';

/** Threshold in ms — if response is this much slower than baseline, it's suspicious */
const BLIND_SQLI_THRESHOLD_MS = 3000;

/** Minimum body length difference ratio to flag boolean-based blind SQLi */
const BOOLEAN_BLIND_THRESHOLD = 0.35;

/** Select error-based SQLi payloads, appending polyglots when WAF detected or deep profile */
function selectSqliPayloads(config: ScanConfig, maxNonDeep: number): string[] {
  const base = config.profile === 'deep' ? SQLI_PAYLOADS : SQLI_PAYLOADS.slice(0, maxNonDeep);
  const usePolyglots = config.wafDetection?.detected || config.profile === 'deep';
  if (usePolyglots) {
    return [...base, ...getPolyglotSqli()];
  }
  return base;
}

/**
 * Generate WAF-evasion variants of a SQLi payload.
 * Returns array including original + encoded variants + SQL comment obfuscated.
 */
function getSqliWafVariants(payload: string, config: ScanConfig): string[] {
  const strategies = pickStrategies(config.wafDetection);
  const variants = mutatePayload(payload, strategies);
  // Add SQL comment obfuscation variant (breaks up keywords WAFs pattern-match)
  const obfuscated = sqlCommentObfuscate(payload);
  if (obfuscated !== payload && !variants.includes(obfuscated)) {
    variants.push(obfuscated);
  }
  return variants;
}

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

    // Blind SQLi: inject OOB payloads for out-of-band detection
    if (config.callbackUrl) {
      const blindPayloads = generateBlindSqliPayloads(config.callbackUrl);
      log.info(`Injecting ${blindPayloads.length} blind SQLi OOB payloads (callback: ${config.callbackUrl})`);
      findings.push(...(await injectBlindSqli(context, targets, blindPayloads, config, requestLogger)));
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
  const payloads = selectSqliPayloads(config, 4);

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
  const errorPayloads = selectSqliPayloads(config, 3);
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

      // --- Error-based detection (with WAF-evasion variants) ---
      for (const payload of errorPayloads) {
        if (foundForParam) break;

        const variants = getSqliWafVariants(payload, config);
        for (const variant of variants) {
          if (foundForParam) break;
          const testUrl = new URL(originalUrl);
          testUrl.searchParams.set(param, variant);

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
                const isWafBypass = variant !== payload;
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'critical',
                  title: `SQL Injection in URL Parameter "${param}"${isWafBypass ? ' (WAF bypass)' : ''}`,
                  description: `SQL error message detected when injecting payload into URL parameter "${param}". This indicates the parameter is directly interpolated into SQL queries.${isWafBypass ? ' Encoded payload bypassed WAF detection.' : ''}`,
                  url: originalUrl,
                  evidence: `Payload: ${variant}\nOriginal: ${payload}\nTest URL: ${testUrl.href}\nSQL error: ${match[0]}${isWafBypass ? '\nWAF bypass: yes' : ''}`,
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

        // HPP bypass: when WAF detected, duplicate the parameter to bypass
        // WAFs that only inspect the first (or last) occurrence
        if (!foundForParam && config.wafDetection?.detected) {
          const hppUrls = generateHppVariants(originalUrl, param, payload);
          for (const hppUrl of hppUrls) {
            if (foundForParam) break;

            const page = await context.newPage();
            try {
              const response = await page.request.fetch(hppUrl);
              const body = await response.text();

              requestLogger?.log({
                timestamp: new Date().toISOString(),
                method: 'GET',
                url: hppUrl,
                responseStatus: response.status(),
                phase: 'active-sqli-hpp',
              });

              for (const pattern of SQL_ERROR_PATTERNS) {
                const match = body.match(pattern);
                if (match) {
                  findings.push({
                    id: randomUUID(),
                    category: 'sqli',
                    severity: 'critical',
                    title: `SQL Injection in URL Parameter "${param}" (HPP bypass)`,
                    description: `SQL error message detected when injecting payload into URL parameter "${param}" via HTTP Parameter Pollution. WAF was bypassed by duplicating the parameter.`,
                    url: originalUrl,
                    evidence: `Payload: ${payload}\nHPP URL: ${hppUrl}\nSQL error: ${match[0]}\nWAF bypass: HPP`,
                    request: { method: 'GET', url: hppUrl },
                    response: { status: response.status(), bodySnippet: body.slice(0, 300) },
                    timestamp: new Date().toISOString(),
                  });
                  foundForParam = true;
                  break;
                }
              }
            } catch (err) {
              log.debug(`SQLi HPP test: ${(err as Error).message}`);
            } finally {
              await page.close();
            }

            await delay(config.requestDelay);
          }
        }
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

/**
 * Inject blind SQLi payloads (OOB: DNS exfiltration, outbound HTTP, etc.)
 * into forms and URL parameters. These payloads use database-specific features
 * (LOAD_FILE, UTL_HTTP, xp_cmdshell, dblink, COPY TO PROGRAM) to make the
 * database server connect to the callback URL, confirming exploitation.
 *
 * Detection happens out-of-band on the user's callback server.
 */
async function injectBlindSqli(
  context: BrowserContext,
  targets: ScanTargets,
  blindPayloads: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  let injectedCount = 0;

  // Inject into forms
  for (const form of targets.forms) {
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', 'number', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const payload of blindPayloads) {
      const page = await context.newPage();
      try {
        const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';
        const payloadBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(payload)}`)
          .join('&');

        await page.request.fetch(form.action, {
          method: fetchMethod,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          data: payloadBody,
        });

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: form.method,
          url: form.action,
          body: payloadBody,
          phase: 'active-sqli-blind-oob',
        });

        injectedCount++;
      } catch (err) {
        log.debug(`Blind SQLi form inject: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  // Inject into URL parameters
  for (const originalUrl of targets.urlsWithParams) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(originalUrl);
    } catch {
      continue;
    }
    const params = Array.from(parsedUrl.searchParams.keys());

    for (const param of params) {
      for (const payload of blindPayloads) {
        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, payload);

        const page = await context.newPage();
        try {
          await page.request.fetch(testUrl.href);

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            phase: 'active-sqli-blind-oob',
          });

          injectedCount++;
        } catch (err) {
          log.debug(`Blind SQLi URL inject: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  if (injectedCount > 0) {
    log.info(`Injected ${injectedCount} blind SQLi OOB payloads. Check your callback server for hits.`);
  }

  // Blind SQLi findings are detected out-of-band — no immediate findings to return
  return [];
}

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import {
  SQLI_PAYLOADS,
  SQLI_TIME_PAYLOADS,
  SQL_ERROR_PATTERNS,
  SQLI_BOOLEAN_PAYLOADS,
  SQLI_UNION_ORDER_BY_PROBES,
  SQLI_STACKED_PAYLOADS,
  NOSQL_PAYLOADS,
  NOSQL_ERROR_PATTERNS,
  NOSQL_TIMING_PAYLOADS,
  NOSQL_JSON_PAYLOADS,
} from '../../config/payloads/sqli.js';
import type { TimedSqliPayload, StackedSqliPayload } from '../../config/payloads/sqli.js';
import type { DatabaseType } from '../../utils/payload-context.js';
import { getPolyglotSqli } from '../../utils/polyglot-payloads.js';
import { generateHppVariants } from '../../utils/param-pollution.js';
import { generateBlindSqliPayloads } from '../oob/blind-payloads.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay, measureResponseTime, INFRA_PARAM_RE } from '../../utils/shared.js';
import { mutatePayload, pickStrategies, sqlCommentObfuscate, sqlCaseRandomize } from '../../utils/payload-mutator.js';
import { isWafBlock } from '../../utils/waf-retry.js';

/** Threshold in ms — if response is this much slower than baseline, it's suspicious.
 *  With SLEEP(5) payloads and median-of-3 reducing jitter, 2500ms gives
 *  sufficient margin while catching genuine delays on slower networks. */
const BLIND_SQLI_THRESHOLD_MS = 2500;

/** Minimum body length difference ratio to flag boolean-based blind SQLi.
 *  Adaptive: large HTML pages use lower threshold (15%) since even a 15% shift
 *  on a 20KB response is significant. Small JSON uses 35%. */
const BOOLEAN_BLIND_THRESHOLD = 0.35;
const BOOLEAN_BLIND_THRESHOLD_LARGE = 0.15;
const LARGE_RESPONSE_BYTES = 10000;

/** Maximum variance allowed within same-condition requests (TRUE-TRUE or FALSE-FALSE).
 *  If same-condition responses vary more than this, the page is inherently dynamic
 *  and boolean-blind detection is unreliable — skip this parameter. */
const BOOLEAN_CONSISTENCY_THRESHOLD = 0.30;

/** Reorder timed SQLi payloads: matching DB types first, then the rest */
export function prioritizeTimedPayloads(databases: DatabaseType[]): TimedSqliPayload[] {
  const dbSet: Set<string> = new Set(databases.filter((d) => d !== 'unknown'));
  if (dbSet.size === 0) return [...SQLI_TIME_PAYLOADS];

  const prioritized = SQLI_TIME_PAYLOADS.filter((p) => dbSet.has(p.dbType));
  const rest = SQLI_TIME_PAYLOADS.filter((p) => !dbSet.has(p.dbType));
  log.debug(`SQLi payload context: prioritizing ${prioritized.length} ${[...dbSet].join('/')} payloads`);
  return [...prioritized, ...rest];
}

/** Get timed payloads, optionally prioritized by payload context */
function getTimedPayloads(config: ScanConfig): TimedSqliPayload[] {
  const all = config.payloadContext
    ? prioritizeTimedPayloads(config.payloadContext.databases)
    : [...SQLI_TIME_PAYLOADS];
  return config.profile === 'deep' ? all : all.slice(0, 1);
}

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
  const strategies = pickStrategies(config.wafDetection, config.payloadStats);
  const variants = mutatePayload(payload, strategies);
  // Add SQL comment obfuscation variant (breaks up keywords WAFs pattern-match)
  const obfuscated = sqlCommentObfuscate(payload);
  if (obfuscated !== payload && !variants.includes(obfuscated)) {
    variants.push(obfuscated);
  }
  // Add SQL case randomization variant (bypasses case-sensitive WAF rules)
  const caseRandomized = sqlCaseRandomize(payload);
  if (caseRandomized !== payload && !variants.includes(caseRandomized)) {
    variants.push(caseRandomized);
  }
  return variants;
}

/**
 * Fetch a URL/form and return the response body length.
 * Returns 0 on failure.
 */
async function fetchBodyLength(
  context: BrowserContext,
  url: string,
  options?: { method?: string; headers?: Record<string, string>; data?: string },
): Promise<number> {
  const page = await context.newPage();
  try {
    const resp = options?.method && options.method !== 'GET'
      ? await page.request.fetch(url, {
          method: options.method,
          headers: options.headers,
          data: options.data,
        })
      : await page.request.fetch(url);
    return (await resp.text()).length;
  } catch {
    return 0;
  } finally {
    await page.close();
  }
}

/**
 * Multi-round boolean-blind confirmation.
 * Sends each condition twice to verify consistency, then compares TRUE vs FALSE.
 * Returns null if the page is too dynamic (same-condition variance > threshold),
 * or the difference ratio if confirmed.
 */
async function confirmBooleanBlind(
  context: BrowserContext,
  trueFetcher: () => Promise<number>,
  falseFetcher: () => Promise<number>,
  requestDelay: number,
): Promise<{ diff: number; trueLen: number; falseLen: number; trueLen2: number; falseLen2: number; effectiveThreshold: number } | null> {
  // Round 1: TRUE condition
  const trueLen1 = await trueFetcher();
  await delay(requestDelay);

  // Round 2: TRUE condition (verify consistency)
  const trueLen2 = await trueFetcher();
  await delay(requestDelay);

  // Check TRUE-TRUE consistency
  if (trueLen1 > 0 && trueLen2 > 0) {
    const trueMax = Math.max(trueLen1, trueLen2);
    const trueVariance = Math.abs(trueLen1 - trueLen2) / trueMax;
    if (trueVariance > BOOLEAN_CONSISTENCY_THRESHOLD) {
      log.debug(`Boolean-blind: TRUE-TRUE variance ${(trueVariance * 100).toFixed(1)}% exceeds ${BOOLEAN_CONSISTENCY_THRESHOLD * 100}% — page is dynamic, skipping`);
      return null;
    }
  }

  // Round 1: FALSE condition
  const falseLen1 = await falseFetcher();
  await delay(requestDelay);

  // Round 2: FALSE condition (verify consistency)
  const falseLen2 = await falseFetcher();
  await delay(requestDelay);

  // Check FALSE-FALSE consistency
  if (falseLen1 > 0 && falseLen2 > 0) {
    const falseMax = Math.max(falseLen1, falseLen2);
    const falseVariance = Math.abs(falseLen1 - falseLen2) / falseMax;
    if (falseVariance > BOOLEAN_CONSISTENCY_THRESHOLD) {
      log.debug(`Boolean-blind: FALSE-FALSE variance ${(falseVariance * 100).toFixed(1)}% exceeds ${BOOLEAN_CONSISTENCY_THRESHOLD * 100}% — page is dynamic, skipping`);
      return null;
    }
  }

  // Use averages for the final comparison
  const trueAvg = (trueLen1 + trueLen2) / 2;
  const falseAvg = (falseLen1 + falseLen2) / 2;

  if (trueAvg === 0 || falseAvg === 0) return null;

  const maxLen = Math.max(trueAvg, falseAvg);
  const diff = Math.abs(trueAvg - falseAvg) / maxLen;

  // Adaptive threshold: large HTML pages need a lower threshold
  const effectiveThreshold = maxLen > LARGE_RESPONSE_BYTES ? BOOLEAN_BLIND_THRESHOLD_LARGE : BOOLEAN_BLIND_THRESHOLD;
  log.debug(`Boolean-blind: trueAvg=${Math.round(trueAvg)} falseAvg=${Math.round(falseAvg)} diff=${(diff * 100).toFixed(1)}% threshold=${(effectiveThreshold * 100).toFixed(0)}%`);

  return { diff, trueLen: trueLen1, falseLen: falseLen1, trueLen2, falseLen2, effectiveThreshold };
}

/** Destructive action path segments — skip these to avoid data loss */
const DESTRUCTIVE_PATH_RE = /\b(delete|remove|destroy|drop|truncate|reset|purge|wipe)\b/i;

export const sqliCheck: ActiveCheck = {
  name: 'sqli',
  category: 'sqli',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for SQL injection...`);
      findings.push(...(await testSqliOnForms(context, targets.forms, config, requestLogger)));
    }

    // POST form SQLi — test forms with POST method via direct HTTP requests
    const postForms = targets.forms.filter((f) => f.method.toUpperCase() === 'POST');
    if (postForms.length > 0) {
      log.info(`Testing ${postForms.length} POST forms for SQL injection (direct POST)...`);
      findings.push(...(await testPostFormSqli(context, postForms, config, requestLogger)));
    }

    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for SQL injection...`);
      findings.push(...(await testSqliOnUrls(context, targets.urlsWithParams, config, requestLogger)));
    }

    // JSON API SQLi — test API endpoints with JSON body payloads
    if (targets.apiEndpoints.length > 0) {
      log.info(`Testing ${targets.apiEndpoints.length} API endpoints for JSON body SQL injection...`);
      findings.push(...(await testJsonApiSqli(context, targets.apiEndpoints, config, requestLogger)));
    }

    // NoSQL JSON body injection — test API endpoints with MongoDB operator payloads
    if (targets.apiEndpoints.length > 0) {
      log.info(`Testing ${targets.apiEndpoints.length} API endpoints for NoSQL JSON body injection...`);
      findings.push(...(await testNoSqlJsonApi(context, targets.apiEndpoints, config, requestLogger)));
    }

    // Stacked query SQLi — test for multi-statement execution (RCE potential)
    if (config.profile !== 'quick' && targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for stacked query SQL injection...`);
      findings.push(...(await testStackedQuerySqli(context, targets.urlsWithParams, config, requestLogger)));
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
            const inputLocator = page.locator(`[name="${input.name}"]`);
            const isVisible = await inputLocator.isVisible({ timeout: 1000 }).catch(() => false);
            if (!isVisible) {
              log.debug(`SQLi skipping hidden input: ${input.name}`);
              continue;
            }
            await inputLocator.fill(payload, { timeout: 5000 });
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
              confidence: 'high',
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
              evidencePack: { detectionMethod: 'error-pattern' },
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
      const timePayloads = getTimedPayloads(config);
      const formBody = textInputs.map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent('test')}`).join('&');
      const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';

      // Establish baseline with median-of-3
      const baselineMedian = await measureResponseTime(context, form.action, {
        method: fetchMethod,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        data: formBody,
      });

      if (baselineMedian > 0) {
        for (const { payload } of timePayloads) {
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
                confidence: 'medium',
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
                evidencePack: { detectionMethod: 'error-pattern' },
              });
              break;
            }
          }

          await delay(config.requestDelay);
        }
      }
    }

    // --- Boolean-based blind SQLi for forms (multi-round confirmation) ---
    if (config.profile !== 'quick' && !hasFormFinding()) {
      const fetchMethod = form.method.toUpperCase() === 'GET' ? 'GET' : 'POST';
      const fetchOpts = {
        method: fetchMethod,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      };

      for (const { truePayload, falsePayload } of SQLI_BOOLEAN_PAYLOADS) {
        const trueBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(truePayload)}`)
          .join('&');
        const falseBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(falsePayload)}`)
          .join('&');

        const result = await confirmBooleanBlind(
          context,
          () => fetchBodyLength(context, form.action, { ...fetchOpts, data: trueBody }),
          () => fetchBodyLength(context, form.action, { ...fetchOpts, data: falseBody }),
          config.requestDelay,
        );

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: form.method,
          url: form.action,
          body: trueBody,
          phase: 'active-sqli-boolean',
        });

        if (result && result.diff > result.effectiveThreshold) {
          findings.push({
            id: randomUUID(),
            category: 'sqli',
            severity: 'high',
            confidence: 'medium',
            title: `Potential Boolean-Based Blind SQL Injection in Form "${textInputs[0].name}"`,
            description: `Boolean-based blind SQL injection suspected. Multi-round confirmation: TRUE responses consistent, FALSE responses consistent, and the difference between TRUE vs FALSE exceeds threshold. Submitted via form input "${textInputs[0].name}".`,
            url: form.pageUrl,
            evidence: `True payload: ${truePayload} (lengths: ${result.trueLen}, ${result.trueLen2})\nFalse payload: ${falsePayload} (lengths: ${result.falseLen}, ${result.falseLen2})\nDifference: ${(result.diff * 100).toFixed(1)}% (threshold: ${BOOLEAN_BLIND_THRESHOLD * 100}%)`,
            request: {
              method: form.method,
              url: form.action,
              body: trueBody,
            },
            timestamp: new Date().toISOString(),
            evidencePack: { detectionMethod: 'error-pattern' },
          });
          break;
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
                confidence: 'low',
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
                evidencePack: { detectionMethod: 'nosql-injection' },
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
  const timePayloads = getTimedPayloads(config);

  for (const originalUrl of urls) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(originalUrl);
    } catch (err) {
      log.debug(`SQLi URL parse: ${(err as Error).message}`);
      continue;
    }
    const params = Array.from(parsedUrl.searchParams.keys())
      .filter(p => !INFRA_PARAM_RE.test(p));
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
            let response = await page.request.fetch(testUrl.href);
            let body = await response.text();
            let usedVariant = variant;

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              responseStatus: response.status(),
              phase: 'active-sqli',
            });

            // WAF adaptive retry: if the response is WAF-blocked, try mutated payloads
            if (isWafBlock(response.status(), body) && config.wafDetection?.detected) {
              const retryStrategies = pickStrategies(config.wafDetection, config.payloadStats).filter(s => s !== 'none');
              for (const strategy of retryStrategies.slice(0, 2)) {
                const mutated = mutatePayload(payload, [strategy])[0];
                if (!mutated || mutated === variant) continue;
                const retryUrl = new URL(originalUrl);
                retryUrl.searchParams.set(param, mutated);
                try {
                  const retryResp = await page.request.fetch(retryUrl.href, { timeout: config.timeout });
                  const retryBody = await retryResp.text();
                  if (!isWafBlock(retryResp.status(), retryBody)) {
                    response = retryResp;
                    body = retryBody;
                    usedVariant = mutated;
                    testUrl.searchParams.set(param, mutated);
                    log.info(`WAF bypass: ${strategy} worked for SQLi on ${originalUrl}`);
                    break;
                  }
                } catch { continue; }
              }
            }

            for (const pattern of SQL_ERROR_PATTERNS) {
              const match = body.match(pattern);
              if (match) {
                const isWafBypass = usedVariant !== payload;
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'critical',
                  confidence: 'high',
                  title: `SQL Injection in URL Parameter "${param}"${isWafBypass ? ' (WAF bypass)' : ''}`,
                  description: `SQL error message detected when injecting payload into URL parameter "${param}". This indicates the parameter is directly interpolated into SQL queries.${isWafBypass ? ' Encoded payload bypassed WAF detection.' : ''}`,
                  url: originalUrl,
                  evidence: `Payload: ${usedVariant}\nOriginal: ${payload}\nTest URL: ${testUrl.href}\nSQL error: ${match[0]}${isWafBypass ? '\nWAF bypass: yes' : ''}`,
                  request: { method: 'GET', url: testUrl.href },
                  response: { status: response.status(), bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'error-pattern' },
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
                    confidence: 'high',
                    title: `SQL Injection in URL Parameter "${param}" (HPP bypass)`,
                    description: `SQL error message detected when injecting payload into URL parameter "${param}" via HTTP Parameter Pollution. WAF was bypassed by duplicating the parameter.`,
                    url: originalUrl,
                    evidence: `Payload: ${payload}\nHPP URL: ${hppUrl}\nSQL error: ${match[0]}\nWAF bypass: HPP`,
                    request: { method: 'GET', url: hppUrl },
                    response: { status: response.status(), bodySnippet: body.slice(0, 300) },
                    timestamp: new Date().toISOString(),
                    evidencePack: { detectionMethod: 'error-pattern' },
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
          for (const { payload } of timePayloads) {
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
              log.debug(`SQLi blind: param="${param}" baseline=${Math.round(baselineMedian)}ms payload=${Math.round(payloadMedian)}ms diff=${Math.round(diff)}ms threshold=${BLIND_SQLI_THRESHOLD_MS}ms`);
              if (diff > BLIND_SQLI_THRESHOLD_MS) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'high',
                  confidence: 'medium',
                  title: `Potential Blind SQL Injection in URL Parameter "${param}"`,
                  description: `Time-based blind SQL injection suspected. The median response was ${Math.round(diff)}ms slower when a time-delay payload was injected into "${param}". Baseline median: ${Math.round(baselineMedian)}ms, With payload median: ${payloadMedian}ms.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                  request: { method: 'GET', url: testUrl.href },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'error-pattern' },
                });
                foundForParam = true;
              }
            }

            await delay(config.requestDelay);
          }
        }
      }

      // --- Boolean-based blind detection (multi-round confirmation) ---
      if (!foundForParam && config.profile !== 'quick') {
        for (const { truePayload, falsePayload } of SQLI_BOOLEAN_PAYLOADS) {
          if (foundForParam) break;

          const trueUrl = new URL(originalUrl);
          trueUrl.searchParams.set(param, truePayload);
          const falseUrl = new URL(originalUrl);
          falseUrl.searchParams.set(param, falsePayload);

          const result = await confirmBooleanBlind(
            context,
            () => fetchBodyLength(context, trueUrl.href),
            () => fetchBodyLength(context, falseUrl.href),
            config.requestDelay,
          );

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: trueUrl.href,
            phase: 'active-sqli-boolean',
          });

          if (result && result.diff > result.effectiveThreshold) {
            findings.push({
              id: randomUUID(),
              category: 'sqli',
              severity: 'high',
              confidence: 'medium',
              title: `Potential Boolean-Based Blind SQL Injection in URL Parameter "${param}"`,
              description: `Boolean-based blind SQL injection suspected. Multi-round confirmation: TRUE responses consistent, FALSE responses consistent, and the difference between TRUE (${truePayload}) vs FALSE (${falsePayload}) exceeds threshold in parameter "${param}".`,
              url: originalUrl,
              evidence: `True payload: ${truePayload} (lengths: ${result.trueLen}, ${result.trueLen2})\nFalse payload: ${falsePayload} (lengths: ${result.falseLen}, ${result.falseLen2})\nDifference: ${(result.diff * 100).toFixed(1)}% (threshold: ${BOOLEAN_BLIND_THRESHOLD * 100}%)`,
              request: { method: 'GET', url: trueUrl.href },
              timestamp: new Date().toISOString(),
              evidencePack: { detectionMethod: 'error-pattern' },
            });
            foundForParam = true;
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
                confidence: 'high',
                title: `Union-Based SQL Injection in URL Parameter "${param}"`,
                description: `Union-based SQL injection detected. ORDER BY probing determined ${columnCount} columns, and a UNION SELECT with ${columnCount} NULLs was accepted without error.`,
                url: originalUrl,
                evidence: `Payload: ${unionPayload}\nDetected columns: ${columnCount}\nTest URL: ${testUrl.href}`,
                request: { method: 'GET', url: testUrl.href },
                response: { status: resp.status(), bodySnippet: body.slice(0, 300) },
                timestamp: new Date().toISOString(),
                evidencePack: { detectionMethod: 'error-pattern' },
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
                  confidence: 'low',
                  title: `NoSQL Injection in URL Parameter "${param}"`,
                  description: `NoSQL error message detected when injecting payload into URL parameter "${param}". This indicates the parameter may be used in a NoSQL query without proper sanitization.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nTest URL: ${testUrl.href}\nNoSQL error: ${match[0]}`,
                  request: { method: 'GET', url: testUrl.href },
                  response: { status: response.status(), bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'nosql-injection' },
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

      // --- NoSQL timing-based blind ($where JavaScript sleep) ---
      if (!foundForParam && config.profile !== 'quick') {
        const baselineMedian = await measureResponseTime(context, originalUrl);
        if (baselineMedian > 0) {
          for (const { payload } of NOSQL_TIMING_PAYLOADS) {
            if (foundForParam) break;
            const testUrl = new URL(originalUrl);
            testUrl.searchParams.set(param, payload);
            const payloadMedian = await measureResponseTime(context, testUrl.href);
            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              phase: 'active-nosqli-timing',
            });
            if (payloadMedian > 0) {
              const diff = payloadMedian - baselineMedian;
              if (diff > BLIND_SQLI_THRESHOLD_MS) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'critical',
                  confidence: 'medium',
                  title: `NoSQL Injection (Time-Based) via "${param}" Parameter`,
                  description: `Time-based NoSQL injection detected using $where JavaScript sleep. The median response was ${Math.round(diff)}ms slower when a sleep payload was injected into "${param}". This indicates server-side JavaScript evaluation in a MongoDB $where clause.`,
                  url: originalUrl,
                  evidence: `Payload: ${payload}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms`,
                  request: { method: 'GET', url: testUrl.href },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'time-based-blind' },
                });
                foundForParam = true;
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

/**
 * Test POST form fields for SQL injection via direct HTTP POST requests.
 * For each form input, injects SQLi payloads while filling other fields with benign data.
 * Covers error-based and time-based blind detection.
 */
async function testPostFormSqli(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = selectSqliPayloads(config, 4);

  for (const form of forms) {
    // Skip destructive-looking endpoints
    if (DESTRUCTIVE_PATH_RE.test(form.action)) {
      log.debug(`Skipping destructive POST form: ${form.action}`);
      continue;
    }

    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', 'number', 'hidden', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    let foundForForm = false;

    // --- Error-based detection via direct POST ---
    for (const input of textInputs) {
      if (foundForForm) break;

      for (const payload of payloads) {
        if (foundForForm) break;

        // Build form body: inject payload into target input, benign data for others
        const bodyParams = textInputs.map((i) => {
          const val = i.name === input.name ? payload : (i.value || 'test');
          return `${encodeURIComponent(i.name)}=${encodeURIComponent(val)}`;
        }).join('&');

        const page = await context.newPage();
        try {
          const resp = await page.request.fetch(form.action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: bodyParams,
          });
          const body = await resp.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'POST',
            url: form.action,
            body: bodyParams,
            responseStatus: resp.status(),
            phase: 'active-sqli-post-form',
          });

          for (const pattern of SQL_ERROR_PATTERNS) {
            const match = body.match(pattern);
            if (match) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'critical',
                confidence: 'medium',
                title: `SQL Injection in POST Form Field "${input.name}"`,
                description: `SQL error message detected when injecting payload into POST form field "${input.name}" at ${form.action}. This indicates the input is directly interpolated into SQL queries.`,
                url: form.pageUrl,
                evidence: `Payload: ${payload}\nField: ${input.name}\nSQL error: ${match[0]}`,
                request: {
                  method: 'POST',
                  url: form.action,
                  body: bodyParams,
                },
                response: { status: resp.status(), bodySnippet: body.slice(0, 300) },
                timestamp: new Date().toISOString(),
                evidencePack: { detectionMethod: 'error-pattern' },
              });
              foundForForm = true;
              break;
            }
          }
        } catch (err) {
          log.debug(`SQLi POST form test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    // --- Time-based blind detection for POST forms ---
    if (!foundForForm && config.profile !== 'quick') {
      const timePayloads = getTimedPayloads(config);

      for (const input of textInputs) {
        if (foundForForm) break;

        // Baseline with benign data
        const baselineBody = textInputs
          .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(i.value || 'test')}`)
          .join('&');

        const baselineMedian = await measureResponseTime(context, form.action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          data: baselineBody,
        });

        if (baselineMedian <= 0) continue;

        for (const { payload } of timePayloads) {
          if (foundForForm) break;

          const payloadBody = textInputs.map((i) => {
            const val = i.name === input.name ? payload : (i.value || 'test');
            return `${encodeURIComponent(i.name)}=${encodeURIComponent(val)}`;
          }).join('&');

          const payloadMedian = await measureResponseTime(context, form.action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: payloadBody,
          });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'POST',
            url: form.action,
            body: payloadBody,
            phase: 'active-sqli-post-form-blind',
          });

          if (payloadMedian > 0) {
            const diff = payloadMedian - baselineMedian;
            if (diff > BLIND_SQLI_THRESHOLD_MS) {
              findings.push({
                id: randomUUID(),
                category: 'sqli',
                severity: 'high',
                confidence: 'medium',
                title: `Potential Blind SQL Injection in POST Form Field "${input.name}"`,
                description: `Time-based blind SQL injection suspected in POST form field "${input.name}" at ${form.action}. The median response was ${Math.round(diff)}ms slower when a time-delay payload was submitted.`,
                url: form.pageUrl,
                evidence: `Payload: ${payload}\nField: ${input.name}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                request: {
                  method: 'POST',
                  url: form.action,
                  body: payloadBody,
                },
                timestamp: new Date().toISOString(),
                evidencePack: { detectionMethod: 'error-pattern' },
              });
              foundForForm = true;
            }
          }

          await delay(config.requestDelay);
        }
      }
    }
  }

  return findings;
}

/**
 * Test JSON API endpoints for SQL injection via POST/PUT/PATCH with JSON body.
 * Probes each endpoint by sending JSON bodies with SQLi payloads in string values.
 * Covers error-based and time-based blind detection.
 */
async function testJsonApiSqli(
  context: BrowserContext,
  apiEndpoints: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = selectSqliPayloads(config, 3);
  const timePayloads = getTimedPayloads(config);

  // Common JSON field names to probe — these are typical injection points
  const probeFields = ['query', 'search', 'q', 'filter', 'name', 'username', 'email', 'id', 'value', 'input', 'data', 'text', 'keyword', 'term', 'param'];

  for (const endpoint of apiEndpoints) {
    // Skip destructive-looking endpoints
    if (DESTRUCTIVE_PATH_RE.test(endpoint)) {
      log.debug(`Skipping destructive API endpoint: ${endpoint}`);
      continue;
    }

    let foundForEndpoint = false;

    // Try POST, PUT, PATCH methods
    const methods = ['POST', 'PUT', 'PATCH'];

    for (const method of methods) {
      if (foundForEndpoint) break;

      // First, try a probe request to see if the endpoint accepts JSON
      const probePage = await context.newPage();
      let acceptsJson = false;
      try {
        const probeBody = JSON.stringify({ query: 'test' });
        const resp = await probePage.request.fetch(endpoint, {
          method,
          headers: { 'Content-Type': 'application/json' },
          data: probeBody,
        });
        // Consider it a JSON-accepting endpoint if it doesn't return 404/405
        acceptsJson = resp.status() < 400 || resp.status() === 500;
      } catch {
        // If the request fails entirely, skip this method
      } finally {
        await probePage.close();
      }

      if (!acceptsJson) continue;

      // --- Error-based detection ---
      for (const fieldName of probeFields) {
        if (foundForEndpoint) break;

        for (const payload of payloads) {
          if (foundForEndpoint) break;

          const jsonBody = JSON.stringify({ [fieldName]: payload });

          const page = await context.newPage();
          try {
            const resp = await page.request.fetch(endpoint, {
              method,
              headers: { 'Content-Type': 'application/json' },
              data: jsonBody,
            });
            const body = await resp.text();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method,
              url: endpoint,
              body: jsonBody,
              responseStatus: resp.status(),
              phase: 'active-sqli-json-api',
            });

            for (const pattern of SQL_ERROR_PATTERNS) {
              const match = body.match(pattern);
              if (match) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'critical',
                  confidence: 'medium',
                  title: `SQL Injection in JSON API Field "${fieldName}" (${method})`,
                  description: `SQL error message detected when injecting payload into JSON body field "${fieldName}" via ${method} ${endpoint}. This indicates the field value is directly interpolated into SQL queries.`,
                  url: endpoint,
                  evidence: `Payload: ${payload}\nField: ${fieldName}\nMethod: ${method}\nSQL error: ${match[0]}`,
                  request: {
                    method,
                    url: endpoint,
                    headers: { 'Content-Type': 'application/json' },
                    body: jsonBody,
                  },
                  response: { status: resp.status(), bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'error-pattern' },
                });
                foundForEndpoint = true;
                break;
              }
            }
          } catch (err) {
            log.debug(`SQLi JSON API test: ${(err as Error).message}`);
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }
      }

      // --- Time-based blind detection for JSON API ---
      if (!foundForEndpoint && config.profile !== 'quick') {
        for (const fieldName of probeFields.slice(0, 5)) {
          if (foundForEndpoint) break;

          const baselineBody = JSON.stringify({ [fieldName]: 'test' });
          const baselineMedian = await measureResponseTime(context, endpoint, {
            method,
            headers: { 'Content-Type': 'application/json' },
            data: baselineBody,
          });

          if (baselineMedian <= 0) continue;

          for (const { payload } of timePayloads) {
            if (foundForEndpoint) break;

            const jsonBody = JSON.stringify({ [fieldName]: payload });
            const payloadMedian = await measureResponseTime(context, endpoint, {
              method,
              headers: { 'Content-Type': 'application/json' },
              data: jsonBody,
            });

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method,
              url: endpoint,
              body: jsonBody,
              phase: 'active-sqli-json-api-blind',
            });

            if (payloadMedian > 0) {
              const diff = payloadMedian - baselineMedian;
              if (diff > BLIND_SQLI_THRESHOLD_MS) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'high',
                  confidence: 'medium',
                  title: `Potential Blind SQL Injection in JSON API Field "${fieldName}" (${method})`,
                  description: `Time-based blind SQL injection suspected in JSON body field "${fieldName}" via ${method} ${endpoint}. The median response was ${Math.round(diff)}ms slower when a time-delay payload was submitted.`,
                  url: endpoint,
                  evidence: `Payload: ${payload}\nField: ${fieldName}\nMethod: ${method}\nBaseline median: ${Math.round(baselineMedian)}ms\nWith payload median: ${payloadMedian}ms\nDifference: ${Math.round(diff)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
                  request: {
                    method,
                    url: endpoint,
                    headers: { 'Content-Type': 'application/json' },
                    body: jsonBody,
                  },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'error-pattern' },
                });
                foundForEndpoint = true;
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

/**
 * Test JSON API endpoints for NoSQL injection via MongoDB operator payloads.
 * Modern Express/Mongoose/Fastify apps deserialize JSON bodies directly into
 * MongoDB queries. If { "username": { "$ne": null } } bypasses auth, the
 * query is injectable.
 */
async function testNoSqlJsonApi(
  context: BrowserContext,
  apiEndpoints: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = config.profile === 'deep' ? NOSQL_JSON_PAYLOADS : NOSQL_JSON_PAYLOADS.slice(0, 4);

  // Fields commonly used in MongoDB queries (auth, search, filters)
  const probeFields = ['username', 'email', 'password', 'user', 'login', 'query', 'search', 'filter', 'name', 'id'];

  for (const endpoint of apiEndpoints) {
    if (DESTRUCTIVE_PATH_RE.test(endpoint)) {
      log.debug(`Skipping destructive API endpoint for NoSQL: ${endpoint}`);
      continue;
    }

    let foundForEndpoint = false;

    // Try POST first (most common for auth/search APIs), then PUT
    const methods = ['POST', 'PUT'];

    for (const method of methods) {
      if (foundForEndpoint) break;

      // Probe if endpoint accepts JSON
      const probePage = await context.newPage();
      let acceptsJson = false;
      let baselineBody = '';
      let baselineStatus = 0;
      try {
        const probeBody = JSON.stringify({ username: 'test', password: 'test' });
        const resp = await probePage.request.fetch(endpoint, {
          method,
          headers: { 'Content-Type': 'application/json' },
          data: probeBody,
        });
        baselineStatus = resp.status();
        baselineBody = await resp.text();
        acceptsJson = baselineStatus < 400 || baselineStatus === 500;
      } catch {
        // skip
      } finally {
        await probePage.close();
      }

      if (!acceptsJson) continue;

      for (const fieldName of probeFields) {
        if (foundForEndpoint) break;

        for (const nosqlPayload of payloads) {
          if (foundForEndpoint) break;

          // Build JSON body with operator value replacing the field's string
          const bodyObj: Record<string, unknown> = {};
          // Add a normal field to make the request look realistic
          if (fieldName !== 'password') bodyObj.password = 'test';
          if (fieldName !== 'username') bodyObj.username = 'test';
          // Inject the operator payload as the field value
          bodyObj[fieldName] = JSON.parse(nosqlPayload.valueJson);
          const jsonBody = JSON.stringify(bodyObj);

          const page = await context.newPage();
          try {
            const resp = await page.request.fetch(endpoint, {
              method,
              headers: { 'Content-Type': 'application/json' },
              data: jsonBody,
            });
            const body = await resp.text();
            const status = resp.status();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method,
              url: endpoint,
              responseStatus: status,
              body: jsonBody,
              phase: 'active-nosqli-json',
            });

            // Detection 1: MongoDB error pattern in response
            for (const pattern of NOSQL_ERROR_PATTERNS) {
              const match = body.match(pattern);
              if (match) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'high',
                  confidence: 'medium',
                  title: `NoSQL Injection in JSON API Field "${fieldName}" (${method})`,
                  description: `MongoDB error detected when injecting operator payload into JSON body field "${fieldName}" via ${method} ${endpoint}. Technique: ${nosqlPayload.description}. This indicates the field value is used in a MongoDB query without sanitization.`,
                  url: endpoint,
                  evidence: `Technique: ${nosqlPayload.technique}\nPayload: ${jsonBody}\nNoSQL error: ${match[0]}`,
                  request: { method, url: endpoint, body: jsonBody },
                  response: { status, bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'nosql-injection' },
                });
                foundForEndpoint = true;
                break;
              }
            }

            // Detection 2: Auth bypass — baseline returned 401/403 but operator payload returns 200
            if (!foundForEndpoint && (baselineStatus === 401 || baselineStatus === 403) && status === 200 && body.length > 50) {
              // Check it's not just an error page with 200
              const looksLikeData = body.includes('"') || body.includes('{') || body.includes('token') || body.includes('session');
              if (looksLikeData) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'critical',
                  confidence: 'high',
                  title: `NoSQL Authentication Bypass in JSON API (${method} ${new URL(endpoint).pathname})`,
                  description: `Authentication bypass via MongoDB operator injection. Normal credentials return ${baselineStatus}, but injecting ${nosqlPayload.technique} into "${fieldName}" returns ${status} with data. This allows login without valid credentials.`,
                  url: endpoint,
                  evidence: `Technique: ${nosqlPayload.technique}\nBaseline status: ${baselineStatus}\nBypass status: ${status}\nPayload: ${jsonBody}\nResponse snippet: ${body.slice(0, 200)}`,
                  request: { method, url: endpoint, body: jsonBody },
                  response: { status, bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'nosql-injection' },
                });
                foundForEndpoint = true;
              }
            }

            // Detection 3: Response significantly different from baseline (data leak)
            if (!foundForEndpoint && status === 200 && baselineStatus === 200) {
              // If response is much larger, operator might have matched more documents
              const sizeDiff = body.length - baselineBody.length;
              if (sizeDiff > 500 && body.length > 100) {
                findings.push({
                  id: randomUUID(),
                  category: 'sqli',
                  severity: 'high',
                  confidence: 'low',
                  title: `Potential NoSQL Data Leak in JSON API Field "${fieldName}" (${method})`,
                  description: `Injecting ${nosqlPayload.technique} into "${fieldName}" returned significantly more data (${body.length} bytes vs baseline ${baselineBody.length} bytes). The MongoDB operator may have matched additional documents, leaking data.`,
                  url: endpoint,
                  evidence: `Technique: ${nosqlPayload.technique}\nBaseline response: ${baselineBody.length} bytes\nPayload response: ${body.length} bytes\nDifference: +${sizeDiff} bytes`,
                  request: { method, url: endpoint, body: jsonBody },
                  response: { status, bodySnippet: body.slice(0, 300) },
                  timestamp: new Date().toISOString(),
                  evidencePack: { detectionMethod: 'nosql-injection' },
                });
                foundForEndpoint = true;
              }
            }
          } catch (err) {
            log.debug(`NoSQL JSON API test: ${(err as Error).message}`);
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
 * Test for stacked (multi-statement) SQL injection via URL parameters.
 * Stacked queries are critical for MSSQL/PostgreSQL where they enable RCE
 * (e.g., xp_cmdshell on MSSQL, COPY TO on PostgreSQL).
 *
 * Detection: uses timing-based verification (same as blind SQLi but with
 * semicolon-separated statements instead of inline expressions).
 */
async function testStackedQuerySqli(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Select payloads based on detected DB type
  const dbTypes = config.payloadContext?.databases ?? [];
  const dbSet = new Set<string>(dbTypes.filter((d: string) => d !== 'unknown'));

  let payloads: StackedSqliPayload[];
  if (dbSet.size > 0) {
    const matched = SQLI_STACKED_PAYLOADS.filter((p) => p.dbType === 'generic' || dbSet.has(p.dbType));
    const rest = SQLI_STACKED_PAYLOADS.filter((p) => p.dbType !== 'generic' && !dbSet.has(p.dbType));
    payloads = [...matched, ...rest];
    log.debug(`Stacked SQLi: prioritizing ${matched.length} ${[...dbSet].join('/')} + generic payloads`);
  } else {
    payloads = [...SQLI_STACKED_PAYLOADS];
  }

  if (config.profile !== 'deep') {
    payloads = payloads.slice(0, 3);
  }

  const urlLimit = config.profile === 'deep' ? urls.length : Math.min(urls.length, 2);

  for (const originalUrl of urls.slice(0, urlLimit)) {
    const parsed = new URL(originalUrl);
    const params = Array.from(parsed.searchParams.keys()).filter((k) => !INFRA_PARAM_RE.test(k));
    if (params.length === 0) continue;

    // Measure baseline response time (median of 3)
    const baselineTimes: number[] = [];
    for (let i = 0; i < 3; i++) {
      const t = await measureResponseTime(context, originalUrl);
      if (t > 0) baselineTimes.push(t);
      await delay(50);
    }
    if (baselineTimes.length < 2) continue;
    baselineTimes.sort((a, b) => a - b);
    const baselineMedian = baselineTimes[Math.floor(baselineTimes.length / 2)];

    let foundForUrl = false;
    const paramLimit = config.profile === 'deep' ? 3 : 1;

    for (const param of params.slice(0, paramLimit)) {
      if (foundForUrl) break;

      for (const stackedPayload of payloads) {
        if (foundForUrl) break;

        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, stackedPayload.payload);

        // Measure with payload (median of 3)
        const payloadTimes: number[] = [];
        for (let i = 0; i < 3; i++) {
          const t = await measureResponseTime(context, testUrl.href);
          if (t > 0) payloadTimes.push(t);
          await delay(50);
        }
        if (payloadTimes.length < 2) continue;
        payloadTimes.sort((a, b) => a - b);
        const payloadMedian = payloadTimes[Math.floor(payloadTimes.length / 2)];

        const timeDiff = payloadMedian - baselineMedian;

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: testUrl.href,
          responseStatus: 0,
          phase: 'active-sqli-stacked',
        });

        if (timeDiff > BLIND_SQLI_THRESHOLD_MS) {
          findings.push({
            id: randomUUID(),
            category: 'sqli',
            severity: 'critical',
            title: `Stacked Query SQL Injection via "${param}" (${stackedPayload.dbType})`,
            description: `The parameter "${param}" is vulnerable to stacked (multi-statement) SQL injection. The server executed a second SQL statement after a semicolon delimiter, confirmed by a ${(timeDiff / 1000).toFixed(1)}s timing delay. Stacked queries enable data exfiltration, data modification, and potentially remote code execution (e.g., xp_cmdshell on MSSQL, COPY TO on PostgreSQL). Technique: ${stackedPayload.technique}.`,
            url: originalUrl,
            evidence: `Payload: ${stackedPayload.payload}\nDB type: ${stackedPayload.dbType}\nTechnique: ${stackedPayload.technique}\nBaseline median: ${baselineMedian.toFixed(0)}ms\nPayload median: ${payloadMedian.toFixed(0)}ms\nTime difference: ${timeDiff.toFixed(0)}ms (threshold: ${BLIND_SQLI_THRESHOLD_MS}ms)`,
            request: { method: 'GET', url: testUrl.href },
            response: { status: 0, bodySnippet: '' },
            timestamp: new Date().toISOString(),
            confidence: 'high',
            evidencePack: { detectionMethod: 'time-based-blind' },
          });
          foundForUrl = true;
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

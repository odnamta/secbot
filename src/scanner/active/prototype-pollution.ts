import { randomUUID } from 'node:crypto';
import type { BrowserContext, Page } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay, INFRA_PARAM_RE } from '../../utils/shared.js';

// ─── Payload Definitions ────────────────────────────────────────────

/**
 * Query-string prototype pollution payloads.
 * These inject __proto__, constructor.prototype, or constructor keys
 * into URL query parameters and JSON bodies.
 */
export const PP_QUERY_PAYLOADS = [
  // __proto__ — classic prototype pollution via query string parsers (qs, query-string)
  { key: '__proto__[secbot_pp]', value: 'polluted', technique: '__proto__-bracket' },
  { key: '__proto__.secbot_pp', value: 'polluted', technique: '__proto__-dot' },
  // constructor.prototype — bypasses __proto__ blocklists
  { key: 'constructor[prototype][secbot_pp]', value: 'polluted', technique: 'constructor-prototype-bracket' },
  { key: 'constructor.prototype.secbot_pp', value: 'polluted', technique: 'constructor-prototype-dot' },
  // Nested __proto__ — double-nested for deep merge libs (lodash.merge, jQuery.extend)
  { key: 'a[__proto__][secbot_pp]', value: 'polluted', technique: 'nested-proto-bracket' },
  // Array-form — some parsers treat numeric keys differently
  { key: '__proto__[0]', value: 'polluted', technique: 'proto-array-index' },
];

/**
 * JSON body prototype pollution payloads for API endpoints.
 * These exploit deep-merge / Object.assign vulnerabilities in server-side JS.
 */
/**
 * JSON body prototype pollution payloads — stored as raw JSON strings
 * to avoid TypeScript issues with __proto__ keys on object literals.
 */
export const PP_JSON_PAYLOADS = [
  {
    bodyJson: '{"__proto__":{"secbot_pp":"polluted"}}',
    technique: 'json-proto',
    description: '__proto__ key in JSON body — exploits deep merge (lodash.merge, jQuery.extend)',
  },
  {
    bodyJson: '{"constructor":{"prototype":{"secbot_pp":"polluted"}}}',
    technique: 'json-constructor-prototype',
    description: 'constructor.prototype in JSON body — bypasses __proto__ filters',
  },
];

/**
 * Client-side (DOM) prototype pollution payloads injected via URL fragment or query.
 * These target client-side JS that parses URL parameters into objects.
 */
export const PP_CLIENT_PAYLOADS = [
  // Query string — parsed by client-side JS (URLSearchParams, custom parsers)
  '__proto__[secbot_pp]=polluted',
  'constructor[prototype][secbot_pp]=polluted',
  // URL hash/fragment — parsed by SPA routers and client-side libs
  '#__proto__[secbot_pp]=polluted',
  '#constructor[prototype][secbot_pp]=polluted',
];

/** Canary property we inject — if it appears on Object.prototype, pollution succeeded */
export const PP_CANARY = 'secbot_pp';

/**
 * Detection patterns in server responses that indicate prototype pollution worked.
 * If our canary value appears in a response where it shouldn't, the server merged it.
 */
export const PP_RESPONSE_INDICATORS = [
  /secbot_pp/,
  /"polluted"/,
];

// ─── Detection Helpers ──────────────────────────────────────────────

/**
 * Check if a server response contains evidence of prototype pollution.
 * Looks for our canary value reflected in response body or unexpected 500 errors
 * that may indicate Object.prototype was modified.
 */
export function detectServerPollution(
  body: string,
  status: number,
  baselineStatus: number,
): { polluted: boolean; evidence: string } {
  // Direct reflection: our canary value appears in response
  if (body.includes(PP_CANARY) && body.includes('polluted')) {
    return { polluted: true, evidence: `Canary value "${PP_CANARY}":"polluted" reflected in response body` };
  }

  // Server crash: baseline was 200 but now 500 after pollution
  if (baselineStatus >= 200 && baselineStatus < 400 && status >= 500) {
    return { polluted: true, evidence: `Server error ${status} after prototype pollution (baseline was ${baselineStatus}) — possible Object.prototype modification` };
  }

  return { polluted: false, evidence: '' };
}

/**
 * Check client-side prototype pollution via Playwright page evaluation.
 * Returns true if Object.prototype has our canary property.
 */
export async function detectClientPollution(page: Page): Promise<boolean> {
  try {
    return await page.evaluate((canary: string) => {
      // Check if our canary leaked onto Object.prototype
      return (({} as Record<string, unknown>)[canary] !== undefined);
    }, PP_CANARY);
  } catch {
    return false;
  }
}

// ─── Main Check ─────────────────────────────────────────────────────

export const prototypePollutionCheck: ActiveCheck = {
  name: 'prototype-pollution',
  category: 'prototype-pollution',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Server-side PP: test URL params and API endpoints
    if (targets.urlsWithParams.length > 0 || targets.apiEndpoints.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs + ${targets.apiEndpoints.length} APIs for prototype pollution...`);

      const serverFindings = await testServerSidePP(context, targets, config, requestLogger);
      findings.push(...serverFindings);
    }

    // Client-side PP: test pages via Playwright
    if (targets.pages.length > 0 && config.profile !== 'quick') {
      const clientFindings = await testClientSidePP(context, targets, config, requestLogger);
      findings.push(...clientFindings);
    }

    return findings;
  },
};

// ─── Server-Side Testing ────────────────────────────────────────────

async function testServerSidePP(
  context: BrowserContext,
  targets: { urlsWithParams: string[]; apiEndpoints: string[] },
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Test URL query parameters
  const maxUrls = config.profile === 'deep' ? targets.urlsWithParams.length : Math.min(5, targets.urlsWithParams.length);
  for (let i = 0; i < maxUrls; i++) {
    const url = targets.urlsWithParams[i];
    const urlFindings = await testUrlQueryPP(context, url, config, requestLogger);
    findings.push(...urlFindings);
    if (findings.length > 0) break; // One confirmed finding is enough
    await delay(config.requestDelay);
  }

  // Test JSON API endpoints
  if (findings.length === 0) {
    const maxApis = config.profile === 'deep' ? targets.apiEndpoints.length : Math.min(5, targets.apiEndpoints.length);
    for (let i = 0; i < maxApis; i++) {
      const url = targets.apiEndpoints[i];
      const apiFindings = await testJsonBodyPP(context, url, config, requestLogger);
      findings.push(...apiFindings);
      if (findings.length > 0) break;
      await delay(config.requestDelay);
    }
  }

  return findings;
}

async function testUrlQueryPP(
  context: BrowserContext,
  originalUrl: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Get baseline response
  let baselineStatus = 200;
  const baselinePage = await context.newPage();
  try {
    const baselineResp = await baselinePage.request.fetch(originalUrl, { maxRedirects: 3 });
    baselineStatus = baselineResp.status();
  } catch {
    // baseline may fail
  } finally {
    await baselinePage.close();
  }

  const payloads = config.profile === 'deep' ? PP_QUERY_PAYLOADS : PP_QUERY_PAYLOADS.slice(0, 4);

  for (const pp of payloads) {
    const page = await context.newPage();
    try {
      const testUrl = new URL(originalUrl);
      testUrl.searchParams.set(pp.key, pp.value);
      const resp = await page.request.fetch(testUrl.href, { maxRedirects: 3 });
      const status = resp.status();
      const body = await resp.text();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url: testUrl.href,
        responseStatus: status,
        phase: 'active-prototype-pollution',
      });

      const result = detectServerPollution(body, status, baselineStatus);

      if (result.polluted) {
        findings.push({
          id: randomUUID(),
          category: 'prototype-pollution',
          severity: status >= 500 ? 'high' : 'critical',
          title: `Server-Side Prototype Pollution via Query Parameter (${pp.technique})`,
          description: `The application is vulnerable to prototype pollution via the "${pp.key}" query parameter. ` +
            `The server-side query string parser (e.g., qs, query-string) or deep merge function (e.g., lodash.merge) ` +
            `allows injection of properties onto Object.prototype. ` +
            `This can lead to denial of service, authentication bypass, or remote code execution depending on the application logic.`,
          url: originalUrl,
          evidence: [
            `Technique: ${pp.technique}`,
            `Payload: ${pp.key}=${pp.value}`,
            `Detection: ${result.evidence}`,
            `Response status: ${status}`,
          ].join('\n'),
          request: { method: 'GET', url: testUrl.href },
          response: {
            status,
            bodySnippet: body.slice(0, 300),
          },
          timestamp: new Date().toISOString(),
          confidence: body.includes(PP_CANARY) ? 'high' : 'medium',
        });
        break;
      }
    } catch (err) {
      log.debug(`PP query test: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

async function testJsonBodyPP(
  context: BrowserContext,
  apiUrl: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Get baseline
  let baselineStatus = 200;
  const baselinePage = await context.newPage();
  try {
    const resp = await baselinePage.request.fetch(apiUrl, { maxRedirects: 3 });
    baselineStatus = resp.status();
  } catch {
    // baseline may fail
  } finally {
    await baselinePage.close();
  }

  for (const pp of PP_JSON_PAYLOADS) {
    // Try both POST and PUT (common API methods)
    for (const method of ['POST', 'PUT'] as const) {
      const page = await context.newPage();
      try {
        const resp = await page.request.fetch(apiUrl, {
          method,
          headers: { 'Content-Type': 'application/json' },
          data: pp.bodyJson,
          maxRedirects: 3,
        });
        const status = resp.status();
        const body = await resp.text();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method,
          url: apiUrl,
          responseStatus: status,
          phase: 'active-prototype-pollution',
        });

        const result = detectServerPollution(body, status, baselineStatus);

        if (result.polluted) {
          findings.push({
            id: randomUUID(),
            category: 'prototype-pollution',
            severity: status >= 500 ? 'high' : 'critical',
            title: `Server-Side Prototype Pollution via JSON Body (${pp.technique})`,
            description: `The API endpoint is vulnerable to prototype pollution via JSON body. ` +
              `${pp.description}. ` +
              `This can lead to denial of service, property injection, authentication bypass, or remote code execution.`,
            url: apiUrl,
            evidence: [
              `Technique: ${pp.technique}`,
              `Method: ${method}`,
              `Payload: ${pp.bodyJson}`,
              `Detection: ${result.evidence}`,
              `Response status: ${status}`,
            ].join('\n'),
            request: {
              method,
              url: apiUrl,
              headers: { 'Content-Type': 'application/json' },
              body: pp.bodyJson,
            },
            response: {
              status,
              bodySnippet: body.slice(0, 300),
            },
            timestamp: new Date().toISOString(),
            confidence: body.includes(PP_CANARY) ? 'high' : 'medium',
          });
          break;
        }
      } catch (err) {
        log.debug(`PP JSON test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }

    if (findings.length > 0) break;
  }

  return findings;
}

// ─── Client-Side Testing ────────────────────────────────────────────

async function testClientSidePP(
  context: BrowserContext,
  targets: { pages: string[] },
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  const maxPages = config.profile === 'deep' ? Math.min(10, targets.pages.length) : Math.min(3, targets.pages.length);

  for (let i = 0; i < maxPages; i++) {
    const pageUrl = targets.pages[i];
    const page = await context.newPage();
    try {
      // Navigate to the page first (establish baseline)
      await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });

      // Check if baseline already has our canary (false positive guard)
      const baselinePolluted = await detectClientPollution(page);
      if (baselinePolluted) {
        log.debug(`PP client: baseline already has canary on ${pageUrl} — skipping`);
        continue;
      }

      // Test each client-side payload
      for (const ppPayload of PP_CLIENT_PAYLOADS) {
        const testPage = await context.newPage();
        try {
          const separator = ppPayload.startsWith('#') ? '' : (pageUrl.includes('?') ? '&' : '?');
          const testUrl = ppPayload.startsWith('#')
            ? pageUrl.split('#')[0] + ppPayload
            : pageUrl + separator + ppPayload;

          await testPage.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl,
            responseStatus: 200,
            phase: 'active-prototype-pollution-client',
          });

          // Wait for client-side JS to execute
          await delay(500);

          const polluted = await detectClientPollution(testPage);

          if (polluted) {
            const isFragment = ppPayload.startsWith('#');
            findings.push({
              id: randomUUID(),
              category: 'prototype-pollution',
              severity: 'high',
              title: `Client-Side Prototype Pollution via ${isFragment ? 'URL Fragment' : 'Query Parameter'}`,
              description: `The page is vulnerable to client-side prototype pollution. ` +
                `Injecting ${isFragment ? 'fragment parameters' : 'query parameters'} with __proto__ or constructor.prototype keys ` +
                `modifies Object.prototype in the browser. ` +
                `This can lead to DOM XSS, authentication bypass, or property injection ` +
                `depending on how the application uses object properties.`,
              url: pageUrl,
              evidence: [
                `Payload: ${ppPayload}`,
                `Detection: Object.prototype.${PP_CANARY} === "polluted" after page load`,
                `Vector: ${isFragment ? 'URL fragment (hash)' : 'URL query parameter'}`,
              ].join('\n'),
              request: { method: 'GET', url: testUrl },
              response: { status: 200 },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
            break; // One finding per page
          }
        } catch (err) {
          log.debug(`PP client test: ${(err as Error).message}`);
        } finally {
          await testPage.close();
        }

        await delay(config.requestDelay);
      }
    } catch (err) {
      log.debug(`PP client page: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    if (findings.length > 0) break;
  }

  return findings;
}

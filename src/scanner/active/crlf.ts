import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

/** Sentinel header name and value used in CRLF injection payloads */
export const CRLF_SENTINEL_HEADER = 'Injected-Header';
export const CRLF_SENTINEL_VALUE = 'secbot-test';

/** Parameter names commonly used for redirect destinations — prime CRLF targets */
export const REDIRECT_PARAM_NAMES = [
  'url', 'redirect', 'next', 'return', 'goto', 'dest',
  'callback', 'location', 'path', 'redir', 'forward',
  'returnUrl', 'redirectUrl', 'returnTo', 'return_to',
  'redirect_uri', 'redirect_url',
];

const REDIRECT_PARAM_RE = new RegExp(
  `^(${REDIRECT_PARAM_NAMES.join('|')})$`,
  'i',
);

/** CRLF injection payloads — ordered from most to least common */
export const CRLF_PAYLOADS = [
  {
    name: 'url-encoded-crlf',
    payload: `%0d%0a${CRLF_SENTINEL_HEADER}:${CRLF_SENTINEL_VALUE}`,
    description: 'URL-encoded \\r\\n header injection',
  },
  {
    name: 'url-encoded-lf-only',
    payload: `%0a${CRLF_SENTINEL_HEADER}:${CRLF_SENTINEL_VALUE}`,
    description: 'URL-encoded \\n only (some servers accept LF without CR)',
  },
  {
    name: 'response-splitting',
    payload: `%0d%0a%0d%0a<script>alert(1)</script>`,
    description: 'Full HTTP response splitting — inject body after double CRLF',
  },
  {
    name: 'literal-crlf',
    payload: `\r\n${CRLF_SENTINEL_HEADER}:${CRLF_SENTINEL_VALUE}`,
    description: 'Literal \\r\\n (in case server decodes differently)',
  },
];

/**
 * Check whether a response contains the injected sentinel header.
 * Returns true if the `Injected-Header` header is present with the expected value.
 */
export function detectInjectedHeader(
  responseHeaders: Record<string, string>,
): boolean {
  // Headers are case-insensitive — normalize to lowercase for comparison
  for (const [name, value] of Object.entries(responseHeaders)) {
    if (
      name.toLowerCase() === CRLF_SENTINEL_HEADER.toLowerCase() &&
      value.trim() === CRLF_SENTINEL_VALUE
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Check whether the response body contains evidence of HTTP response splitting.
 * If the double-CRLF payload worked, the injected script tag will appear in the body.
 */
export function detectResponseSplitting(body: string): boolean {
  return body.includes('<script>alert(1)</script>');
}

/**
 * Generate CRLF test URLs for a given original URL and parameter name.
 */
export function generateCrlfTestUrls(
  originalUrl: string,
  param: string,
): { url: string; payload: typeof CRLF_PAYLOADS[number] }[] {
  const results: { url: string; payload: typeof CRLF_PAYLOADS[number] }[] = [];

  for (const crlfPayload of CRLF_PAYLOADS) {
    const testUrl = new URL(originalUrl);
    // Prepend the original parameter value (if any) before the CRLF payload
    const originalValue = testUrl.searchParams.get(param) || '';
    testUrl.searchParams.set(param, originalValue + crlfPayload.payload);
    results.push({ url: testUrl.href, payload: crlfPayload });
  }

  return results;
}

export const crlfCheck: ActiveCheck = {
  name: 'crlf',
  category: 'crlf-injection',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    if (targets.urlsWithParams.length === 0) return findings;

    log.info(`Testing ${targets.urlsWithParams.length} URLs for CRLF injection...`);
    const paramFindings = await testCrlfParams(
      context,
      targets.urlsWithParams,
      config,
      requestLogger,
    );
    findings.push(...paramFindings);

    return findings;
  },
};

async function testCrlfParams(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const originalUrl of urls) {
    let foundForUrl = false;
    const parsed = new URL(originalUrl);
    const params = Array.from(parsed.searchParams.keys());

    if (params.length === 0) continue;

    // Prioritize redirect-like parameter names (common CRLF injection vectors)
    const sortedParams = [...params].sort((a, b) => {
      const aIsRedirect = REDIRECT_PARAM_RE.test(a) ? 0 : 1;
      const bIsRedirect = REDIRECT_PARAM_RE.test(b) ? 0 : 1;
      return aIsRedirect - bIsRedirect;
    });

    for (const param of sortedParams) {
      if (foundForUrl) break;

      const testCases = generateCrlfTestUrls(originalUrl, param);

      for (const { url: testUrlHref, payload: crlfPayload } of testCases) {
        if (foundForUrl) break;

        const page = await context.newPage();
        try {
          const response = await page.request.fetch(testUrlHref, {
            maxRedirects: 0,
          });
          const status = response.status();
          const headers = response.headers();
          const body = await response.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrlHref,
            responseStatus: status,
            phase: 'active-crlf',
          });

          const headerInjected = detectInjectedHeader(headers);
          const responseSplit = crlfPayload.name === 'response-splitting'
            && detectResponseSplitting(body);

          if (headerInjected || responseSplit) {
            const isRedirectParam = REDIRECT_PARAM_RE.test(param);
            const injectionType = responseSplit
              ? 'HTTP Response Splitting'
              : 'CRLF Header Injection';

            findings.push({
              id: randomUUID(),
              category: 'crlf-injection',
              severity: 'high',
              title: `${injectionType} via "${param}" Parameter${isRedirectParam ? ' (Redirect Parameter)' : ''}`,
              description: `The parameter "${param}" is vulnerable to CRLF injection. ` +
                `An attacker can inject arbitrary HTTP headers${responseSplit ? ' and body content' : ''} ` +
                `by injecting carriage return / line feed characters. ` +
                `This can lead to XSS, cache poisoning, and session fixation.`,
              url: originalUrl,
              evidence: [
                `Payload: ${crlfPayload.payload}`,
                `Technique: ${crlfPayload.description}`,
                headerInjected
                  ? `Injected header found: ${CRLF_SENTINEL_HEADER}: ${CRLF_SENTINEL_VALUE}`
                  : `Response splitting detected: script tag injected into body`,
                `Response status: ${status}`,
              ].join('\n'),
              request: { method: 'GET', url: testUrlHref },
              response: {
                status,
                headers: headerInjected
                  ? { [CRLF_SENTINEL_HEADER]: headers[CRLF_SENTINEL_HEADER.toLowerCase()] || CRLF_SENTINEL_VALUE }
                  : undefined,
                bodySnippet: body.slice(0, 200),
              },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
            foundForUrl = true;
          }
        } catch (err) {
          log.debug(`CRLF test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

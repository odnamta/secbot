import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { XSS_PAYLOADS, type XSSPayload } from '../../config/payloads/xss.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';
import { mutatePayload, pickStrategies, caseRandomize } from '../../utils/payload-mutator.js';

/**
 * Dangerous HTML contexts — safe to match against both markers and full payloads.
 * These contexts mean executable XSS even if only a marker string appears.
 */
const DANGEROUS_CONTEXTS_ALWAYS = [
  // Inside <script> tags
  /<script[^>]*>[^]*?PAYLOAD[^]*?<\/script>/i,
  // Inside event handlers
  /on\w+\s*=\s*["'][^"']*PAYLOAD/i,
  // Inside href/src with javascript:
  /(?:href|src|action)\s*=\s*["']?\s*javascript:[^"']*PAYLOAD/i,
  // Unquoted attribute value
  /=\s*PAYLOAD/,
];

/**
 * Body-context pattern — only safe to match against full payloads, NOT markers.
 * A marker like "secbot-xss-1" appearing in text content is NOT dangerous by itself.
 */
const DANGEROUS_CONTEXTS_PAYLOAD_ONLY = [
  // Raw in HTML body (full payload with tags appearing unencoded)
  />[^<]*PAYLOAD/,
];

/** Sink-monitoring init script for DOM XSS detection */
const DOM_XSS_INIT_SCRIPT = `
  window.__secbot_dom_xss = [];

  // Monkey-patch document.write
  const origWrite = document.write.bind(document);
  document.write = function(s) {
    window.__secbot_dom_xss.push({ sink: 'document.write', value: String(s) });
    return origWrite(s);
  };

  // Monkey-patch document.writeln
  const origWriteln = document.writeln.bind(document);
  document.writeln = function(s) {
    window.__secbot_dom_xss.push({ sink: 'document.writeln', value: String(s) });
    return origWriteln(s);
  };

  // Monkey-patch eval
  const origEval = window.eval;
  window.eval = function(s) {
    window.__secbot_dom_xss.push({ sink: 'eval', value: String(s) });
    return origEval.call(window, s);
  };

  // Monkey-patch setTimeout with string arg
  const origSetTimeout = window.setTimeout;
  window.setTimeout = function(fn, ...args) {
    if (typeof fn === 'string') {
      window.__secbot_dom_xss.push({ sink: 'setTimeout', value: fn });
    }
    return origSetTimeout.call(window, fn, ...args);
  };

  // Monkey-patch setInterval with string arg
  const origSetInterval = window.setInterval;
  window.setInterval = function(fn, ...args) {
    if (typeof fn === 'string') {
      window.__secbot_dom_xss.push({ sink: 'setInterval', value: fn });
    }
    return origSetInterval.call(window, fn, ...args);
  };

  // Monitor innerHTML assignments via MutationObserver
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const el = node;
          if (el.innerHTML) {
            window.__secbot_dom_xss.push({ sink: 'innerHTML', value: el.innerHTML });
          }
        }
      }
    }
  });
  observer.observe(document.documentElement || document.body || document, {
    childList: true,
    subtree: true,
  });
`;

export const xssCheck: ActiveCheck = {
  name: 'xss',
  category: 'xss',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for XSS...`);
      const formFindings = await testXssOnForms(context, targets.forms, config, requestLogger);
      findings.push(...formFindings);
    }

    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for reflected XSS...`);
      findings.push(...(await testXssOnUrls(context, targets.urlsWithParams, config, requestLogger)));
    }

    // DOM XSS detection on crawled pages
    if (targets.pages.length > 0) {
      log.info(`Testing ${targets.pages.length} pages for DOM XSS...`);
      findings.push(...(await testDomXss(context, targets.pages, config, requestLogger)));
    }

    // Stored XSS detection: re-visit pages to check for previously injected markers
    if (targets.forms.length > 0 && targets.pages.length > 0) {
      log.info('Checking for stored XSS...');
      findings.push(...(await testStoredXss(context, targets.pages, config)));
    }

    return findings;
  },
};

/**
 * Check if nearby content has HTML-encoded versions of the marker,
 * indicating the app IS encoding output (safe, not XSS).
 */
function isHtmlEncoded(content: string, marker: string): boolean {
  const idx = content.indexOf(marker);
  if (idx === -1) return false;

  const windowStart = Math.max(0, idx - 100);
  const windowEnd = Math.min(content.length, idx + marker.length + 100);
  const window = content.slice(windowStart, windowEnd);

  return /&lt;|&gt;|&quot;|&#x27;|&#39;|&amp;/.test(window);
}

/**
 * Check if a payload is reflected in a dangerous (unencoded, executable) context.
 * Returns the context description if dangerous, null if safely encoded.
 */
function checkDangerousReflection(content: string, payload: string, marker: string): string | null {
  // Check full payload first (higher signal)
  if (content.includes(payload)) {
    for (const pattern of [...DANGEROUS_CONTEXTS_ALWAYS, ...DANGEROUS_CONTEXTS_PAYLOAD_ONLY]) {
      const contextPattern = new RegExp(pattern.source.replace('PAYLOAD', escapeRegex(payload)), pattern.flags);
      if (contextPattern.test(content)) {
        return `Unencoded reflection in dangerous context`;
      }
    }

    // If the raw HTML tag payload appears as-is, it's dangerous
    if (payload.includes('<') && content.includes(payload)) {
      return `Raw HTML tag reflected without encoding`;
    }
  }

  // Check marker — only against ALWAYS contexts, and skip if HTML-encoded
  if (marker && content.includes(marker)) {
    if (isHtmlEncoded(content, marker)) {
      return null; // App encodes output — marker in text is safe
    }

    for (const pattern of DANGEROUS_CONTEXTS_ALWAYS) {
      const contextPattern = new RegExp(pattern.source.replace('PAYLOAD', escapeRegex(marker)), pattern.flags);
      if (contextPattern.test(content)) {
        return `Unencoded reflection in dangerous context`;
      }
    }
  }

  return null;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Select payloads based on scan profile, excluding DOM-type payloads for non-DOM checks */
function selectPayloads(config: ScanConfig, maxQuick: number): XSSPayload[] {
  const nonDomPayloads = XSS_PAYLOADS.filter(p => p.type !== 'dom');
  return config.profile === 'deep' ? nonDomPayloads : nonDomPayloads.slice(0, maxQuick);
}

/**
 * Generate WAF-evasion variants of an XSS payload.
 * Returns array of payload strings (original + encoded variants + case-randomized).
 * The marker stays the same since the server will decode the payload.
 */
function getWafVariants(payload: string, config: ScanConfig): string[] {
  const strategies = pickStrategies(config.wafDetection);
  const variants = mutatePayload(payload, strategies);
  // Also add case-randomized variant for HTML tag payloads
  if (payload.includes('<')) {
    const cased = caseRandomize(payload);
    if (cased !== payload) variants.push(cased);
  }
  return variants;
}

async function testXssOnForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = selectPayloads(config, 5);

  for (let formIdx = 0; formIdx < forms.length; formIdx++) {
    const form = forms[formIdx];
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const xssPayload of payloads) {
      const page = await context.newPage();
      try {
        // Register response handler BEFORE navigation
        let responseResolve: (() => void) | null = null;
        let responseBody = '';

        page.on('response', async (response) => {
          try {
            const ct = response.headers()['content-type'] ?? '';
            if (ct.includes('text/html')) {
              responseBody = await response.text();
              responseResolve?.();
            }
          } catch (err) {
            log.debug(`XSS response capture: ${(err as Error).message}`);
          }
        });

        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        // Target the specific form by index, not always .first()
        const formLocator = page.locator('form').nth(formIdx);
        const formExists = await formLocator.count() > 0;

        // Fill inputs within the target form
        for (const input of textInputs) {
          try {
            if (formExists) {
              await formLocator.locator(`[name="${input.name}"]`).fill(xssPayload.payload);
            } else {
              await page.fill(`[name="${input.name}"]`, xssPayload.payload);
            }
          } catch (err) {
            log.debug(`XSS fill input: ${(err as Error).message}`);
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
          if (formExists) {
            const submitBtn = formLocator.locator('button[type="submit"], input[type="submit"]').first();
            if (await submitBtn.count() > 0) {
              await submitBtn.click({ timeout: 5000 });
            } else {
              await formLocator.evaluate((f) => (f as HTMLFormElement).submit());
            }
          } else {
            const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
            if (await submitBtn.count() > 0) {
              await submitBtn.click({ timeout: 5000 });
            }
          }
          await submissionResponse;
          if (responseTimeout) clearTimeout(responseTimeout);
        } catch (err) {
          log.debug(`XSS form submit: ${(err as Error).message}`);
          if (responseTimeout) clearTimeout(responseTimeout);
        }

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: form.method,
          url: form.action,
          body: textInputs.map((i) => `${i.name}=${xssPayload.payload}`).join('&'),
          phase: 'active-xss',
        });

        const content = responseBody || (await page.content());
        const dangerousContext = checkDangerousReflection(content, xssPayload.payload, xssPayload.marker);

        if (dangerousContext) {
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `Reflected XSS in Form Input "${textInputs[0].name}"`,
            description: `The form input "${textInputs[0].name}" reflects XSS payload (${xssPayload.type}) in a dangerous context without proper encoding. ${dangerousContext}.`,
            url: form.pageUrl,
            evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\n${dangerousContext}`,
            request: {
              method: form.method,
              url: form.action,
              body: textInputs.map((i) => `${i.name}=${xssPayload.payload}`).join('&'),
            },
            timestamp: new Date().toISOString(),
          });
          break;
        }
      } catch (err) {
        log.debug(`XSS form test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

async function testXssOnUrls(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = selectPayloads(config, 3);

  for (const originalUrl of urls) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(originalUrl);
    } catch (err) {
      log.debug(`XSS URL parse: ${(err as Error).message}`);
      continue;
    }
    const params = Array.from(parsedUrl.searchParams.keys());

    for (const param of params) {
      let foundForParam = false;
      for (const xssPayload of payloads) {
        if (foundForParam) break;

        // Get WAF-evasion variants (includes original)
        const variants = getWafVariants(xssPayload.payload, config);

        for (const variant of variants) {
          if (foundForParam) break;
          const testUrl = new URL(originalUrl);
          testUrl.searchParams.set(param, variant);

          const page = await context.newPage();
          try {
            await page.goto(testUrl.href, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: testUrl.href,
              phase: 'active-xss',
            });

            const content = await page.content();
            // Check for both the variant and original payload reflection
            const dangerousContext = checkDangerousReflection(content, variant, xssPayload.marker)
              || (variant !== xssPayload.payload ? checkDangerousReflection(content, xssPayload.payload, xssPayload.marker) : null);

            if (dangerousContext) {
              const isWafBypass = variant !== xssPayload.payload;
              findings.push({
                id: randomUUID(),
                category: 'xss',
                severity: 'high',
                title: `Reflected XSS in URL Parameter "${param}"${isWafBypass ? ' (WAF bypass)' : ''}`,
                description: `The URL parameter "${param}" reflects XSS payload (${xssPayload.type}) in a dangerous context without proper encoding. ${dangerousContext}.${isWafBypass ? ' Payload was encoded to bypass WAF detection.' : ''}`,
                url: originalUrl,
                evidence: `Payload: ${variant}\nOriginal: ${xssPayload.payload}\nType: ${xssPayload.type}\nTest URL: ${testUrl.href}\n${dangerousContext}${isWafBypass ? '\nWAF bypass: yes' : ''}`,
                request: { method: 'GET', url: testUrl.href },
                timestamp: new Date().toISOString(),
              });
              foundForParam = true;
            }
          } catch (err) {
            log.debug(`XSS URL test: ${(err as Error).message}`);
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
 * DOM XSS detection: inject payloads via URL fragment and monitor dangerous sinks.
 * Uses page.addInitScript to monkey-patch document.write, eval, innerHTML, etc.
 */
async function testDomXss(
  context: BrowserContext,
  pageUrls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const domPayloads = XSS_PAYLOADS.filter(p => p.type === 'dom');

  if (domPayloads.length === 0) return findings;

  // Limit pages in non-deep mode
  const pagesToTest = config.profile === 'deep' ? pageUrls : pageUrls.slice(0, 3);

  for (const pageUrl of pagesToTest) {
    for (const xssPayload of domPayloads) {
      const page = await context.newPage();
      try {
        // Install sink monitors before navigation
        await page.addInitScript(DOM_XSS_INIT_SCRIPT);

        // Navigate with payload in URL fragment
        const fragmentPayload = xssPayload.payload.startsWith('#')
          ? xssPayload.payload.slice(1)
          : xssPayload.payload;
        const testUrl = `${pageUrl.split('#')[0]}#${fragmentPayload}`;

        await page.goto(testUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });
        // Allow time for DOM-based scripts to execute
        await delay(500);

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: testUrl,
          phase: 'active-xss-dom',
        });

        // Check if any sink received a value containing our marker
        const sinkHits = await page.evaluate((marker: string) => {
          const hits = (window as any).__secbot_dom_xss || [];
          return hits.filter((h: { sink: string; value: string }) =>
            h.value.includes(marker)
          );
        }, xssPayload.marker);

        if (sinkHits.length > 0) {
          const sinkNames = sinkHits.map((h: { sink: string }) => h.sink).join(', ');
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `DOM XSS via URL Fragment`,
            description: `Payload injected via URL fragment reaches dangerous DOM sink(s): ${sinkNames}. This indicates a DOM-based XSS vulnerability.`,
            url: pageUrl,
            evidence: `Payload: ${xssPayload.payload}\nSinks: ${sinkNames}\nTest URL: ${pageUrl}#${fragmentPayload}`,
            request: { method: 'GET', url: `${pageUrl}#${fragmentPayload}` },
            timestamp: new Date().toISOString(),
          });
          break; // One finding per page is enough
        }
      } catch (err) {
        log.debug(`DOM XSS test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

/**
 * Basic stored XSS detection: after form payloads were injected,
 * re-visit a subset of crawled pages and check if any markers appear.
 * If a marker from a form submission shows up on a different page, flag as stored XSS.
 */
async function testStoredXss(
  context: BrowserContext,
  pageUrls: string[],
  config: ScanConfig,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const markers = XSS_PAYLOADS.map(p => p.marker);

  // Only check a subset of pages (max 5) to avoid excessive requests
  const pagesToCheck = pageUrls.slice(0, 5);

  for (const pageUrl of pagesToCheck) {
    const page = await context.newPage();
    try {
      await page.goto(pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });
      const content = await page.content();

      for (const marker of markers) {
        if (content.includes(marker)) {
          // Found a marker on a page — check if it's in a dangerous context
          const xssPayload = XSS_PAYLOADS.find(p => p.marker === marker);
          if (!xssPayload) continue;

          // Verify it's not just HTML-encoded text
          if (isHtmlEncoded(content, marker)) continue;

          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'critical',
            title: `Potential Stored XSS`,
            description: `Marker "${marker}" from a previously injected XSS payload was found on page ${pageUrl}. This may indicate stored XSS where user input is persisted and rendered without encoding.`,
            url: pageUrl,
            evidence: `Marker found: ${marker}\nOriginal payload: ${xssPayload.payload}\nType: ${xssPayload.type}`,
            request: { method: 'GET', url: pageUrl },
            timestamp: new Date().toISOString(),
          });
          break; // One stored XSS finding per page is enough
        }
      }
    } catch (err) {
      log.debug(`Stored XSS check: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

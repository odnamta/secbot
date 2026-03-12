import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { XSS_PAYLOADS, MUTATION_XSS_PAYLOADS, CSP_BYPASS_PAYLOADS, type XSSPayload } from '../../config/payloads/xss.js';
import { getPolyglotXss } from '../../utils/polyglot-payloads.js';
import { generateHppVariants } from '../../utils/param-pollution.js';
import { generateBlindXssPayloads } from '../oob/blind-payloads.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';
import { mutatePayload, pickStrategies, caseRandomize } from '../../utils/payload-mutator.js';
import { detectFramework, waitForHydration } from '../discovery/framework-detector.js';

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

/** Destructive action indicators — skip forms that look like they delete or cancel things */
const DESTRUCTIVE_ACTION_RE = /\b(delete|remove|cancel|destroy|drop|reset|purge|wipe|terminate)\b/i;

/** Search-like query parameter names — common across SPAs and traditional web apps */
export const SEARCH_PARAM_RE = /^(q|query|search|s|keyword|term|text|find|filter|k|key|name|input)$/i;

/**
 * XSS payloads optimized for SPA rendering contexts (Angular [innerHTML], React
 * dangerouslySetInnerHTML, Vue v-html). These payloads avoid <script> tags which
 * don't execute when injected via innerHTML and instead use event handlers that
 * fire immediately on render.
 */
function getSpaSearchPayloads(): XSSPayload[] {
  return [
    // ── Safe HTML probe — detects innerHTML usage (survives Angular/React sanitizers) ──
    // If <b>marker</b> renders as bold text (marker appears as text content of a <b> element),
    // it proves the app uses innerHTML/[innerHTML]/dangerouslySetInnerHTML without full escaping.
    { payload: '<b class="secbot-probe">secbot-spa-xss-probe</b>', marker: 'secbot-spa-xss-probe', type: 'reflected' },
    // ── Actual XSS payloads ──
    // iframe — works with Angular [innerHTML] bypass
    { payload: '<iframe src="javascript:alert(\'secbot-spa-xss-0\')"></iframe>', marker: 'secbot-spa-xss-0', type: 'reflected' },
    // img onerror — fires immediately
    { payload: '<img src=x onerror="alert(\'secbot-spa-xss-1\')">', marker: 'secbot-spa-xss-1', type: 'event-handler' },
    // svg onload — fires on render
    { payload: '<svg onload="alert(\'secbot-spa-xss-2\')">', marker: 'secbot-spa-xss-2', type: 'event-handler' },
    // basic script (may not execute via innerHTML but still detected if reflected)
    { payload: '<script>alert("secbot-spa-xss-3")</script>', marker: 'secbot-spa-xss-3', type: 'reflected' },
    // embed + object tags
    { payload: '<embed src="javascript:alert(\'secbot-spa-xss-4\')">', marker: 'secbot-spa-xss-4', type: 'reflected' },
    // details/summary auto-open
    { payload: '<details open ontoggle="alert(\'secbot-spa-xss-5\')"><summary>x</summary></details>', marker: 'secbot-spa-xss-5', type: 'event-handler' },
  ];
}

/** Check if payload context recommends prioritizing DOM XSS over reflected */
export function shouldPrioritizeDomXss(config: ScanConfig): boolean {
  return config.payloadContext?.preferDomXss === true;
}

export const xssCheck: ActiveCheck = {
  name: 'xss',
  category: 'xss',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];
    const domFirst = shouldPrioritizeDomXss(config);

    if (domFirst) {
      log.info('Payload context: SPA detected — prioritizing DOM XSS');
    }

    // --- DOM XSS phases (run first when SPA detected) ---
    const runDomPhases = async () => {
      if (targets.pages.length > 0) {
        log.info(`Testing ${targets.pages.length} pages for DOM XSS...`);
        findings.push(...(await testDomXss(context, targets.pages, config, requestLogger)));
      }

      const searchUrls = collectSearchUrls(targets, config);
      if (searchUrls.length > 0) {
        log.info(`Testing ${searchUrls.length} search URLs for SPA DOM XSS...`);
        findings.push(...(await testSearchParamXss(context, searchUrls, config, requestLogger)));
      }
    };

    // --- Reflected XSS phases ---
    const runReflectedPhases = async () => {
      if (targets.forms.length > 0) {
        log.info(`Testing ${targets.forms.length} forms for XSS...`);
        findings.push(...(await testXssOnForms(context, targets.forms, config, requestLogger)));
      }

      const postForms = targets.forms.filter(f => f.method === 'POST');
      if (postForms.length > 0) {
        log.info(`Testing ${postForms.length} POST forms for body parameter XSS...`);
        findings.push(...(await testPostFormXss(context, postForms, config, requestLogger)));
      }

      if (targets.urlsWithParams.length > 0) {
        log.info(`Testing ${targets.urlsWithParams.length} URLs for reflected XSS...`);
        findings.push(...(await testXssOnUrls(context, targets.urlsWithParams, config, requestLogger)));
      }

      if (targets.apiEndpoints.length > 0) {
        log.info(`Testing ${targets.apiEndpoints.length} API endpoints for JSON XSS...`);
        findings.push(...(await testJsonApiXss(context, targets.apiEndpoints, config, requestLogger)));
      }
    };

    // Execute in priority order based on payload context
    if (domFirst) {
      await runDomPhases();
      await runReflectedPhases();
    } else {
      await runReflectedPhases();
      await runDomPhases();
    }

    // Stored XSS detection: re-visit pages to check for previously injected markers
    if (targets.forms.length > 0 && targets.pages.length > 0) {
      log.info('Checking for stored XSS...');
      findings.push(...(await testStoredXss(context, targets.pages, config)));
    }

    // Blind XSS: inject callback payloads for out-of-band detection
    if (config.callbackUrl) {
      const blindPayloads = generateBlindXssPayloads(config.callbackUrl);
      log.info(`Injecting ${blindPayloads.length} blind XSS payloads (callback: ${config.callbackUrl})`);
      findings.push(...(await injectBlindXss(context, targets, blindPayloads, config, requestLogger)));
    }

    // Mutation XSS: test parser-confusion payloads when profile is 'deep'
    // or when AI focus areas mention mutation/mxss testing
    const runMutationXss = config.profile === 'deep' ||
      config.aiFocusAreas?.some(a => /mutation|mxss/i.test(a));

    if (runMutationXss && targets.pages.length > 0) {
      log.info(`Testing mutation XSS payloads (${MUTATION_XSS_PAYLOADS.length} payloads)...`);
      findings.push(...(await testMutationXss(context, targets.pages, config, requestLogger)));
    }

    // CSP bypass: test CSP-evasion payloads when CSP was detected or deep profile
    const hasCsp = await detectCsp(context, config.targetUrl, config);
    const runCspBypass = hasCsp ||
      config.aiFocusAreas?.some(a => /csp|content.security.policy/i.test(a));

    if (runCspBypass && (targets.urlsWithParams.length > 0 || targets.forms.length > 0)) {
      log.info(`Testing CSP bypass payloads (${CSP_BYPASS_PAYLOADS.length} payloads, CSP detected: ${hasCsp})...`);
      findings.push(...(await testCspBypassXss(context, targets, config, requestLogger)));
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

/** Select payloads based on scan profile, excluding DOM-type payloads for non-DOM checks.
 *  Appends polyglot XSS payloads when WAF is detected or profile is 'deep'. */
function selectPayloads(config: ScanConfig, maxQuick: number): XSSPayload[] {
  const nonDomPayloads = XSS_PAYLOADS.filter(p => p.type !== 'dom');
  const base = config.profile === 'deep' ? nonDomPayloads : nonDomPayloads.slice(0, maxQuick);

  // Append polyglot payloads when WAF detected or deep profile —
  // polyglots work across multiple contexts and can bypass WAF patterns
  const usePolyglots = config.wafDetection?.detected || config.profile === 'deep';
  if (usePolyglots) {
    const polyglots = getPolyglotXss();
    const polyglotPayloads: XSSPayload[] = polyglots.map((payload, i) => ({
      payload,
      marker: `secbot-polyglot-xss-${i}`,
      type: 'reflected' as const,
    }));
    return [...base, ...polyglotPayloads];
  }

  return base;
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
            confidence: 'medium',
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

/**
 * POST form body XSS: submit XSS payloads directly via HTTP POST (fetch API)
 * rather than filling browser forms. Tests each text input individually while
 * filling other fields with benign data.
 */
async function testPostFormXss(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = selectPayloads(config, 5);

  for (const form of forms) {
    // Skip forms with destructive-looking actions
    if (DESTRUCTIVE_ACTION_RE.test(form.action)) {
      log.debug(`Skipping destructive form action: ${form.action}`);
      continue;
    }

    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', 'hidden', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const input of textInputs) {
      let foundForInput = false;
      for (const xssPayload of payloads) {
        if (foundForInput) break;

        const page = await context.newPage();
        try {
          // Build form data: inject payload into this input, benign data for others
          const formData: Record<string, string> = {};
          for (const other of textInputs) {
            formData[other.name] = other.name === input.name
              ? xssPayload.payload
              : (other.value || 'test');
          }

          // Resolve the action URL relative to the page URL
          let actionUrl: string;
          try {
            actionUrl = new URL(form.action, form.pageUrl).href;
          } catch {
            actionUrl = form.action;
          }

          // Submit via fetch API with URL-encoded body
          const urlEncodedBody = Object.entries(formData)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');

          const response = await page.request.fetch(actionUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            data: urlEncodedBody,
          });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'POST',
            url: actionUrl,
            body: urlEncodedBody,
            phase: 'active-xss-post-form',
          });

          const contentType = response.headers()['content-type'] ?? '';
          if (!contentType.includes('text/html')) {
            continue; // Only check HTML responses for reflected XSS
          }

          const content = await response.text();
          const dangerousContext = checkDangerousReflection(content, xssPayload.payload, xssPayload.marker);

          if (dangerousContext) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `Reflected XSS in POST Body Parameter "${input.name}"`,
              description: `The POST body parameter "${input.name}" reflects XSS payload (${xssPayload.type}) in the response without proper encoding. ${dangerousContext}. This is exploitable via a crafted form that auto-submits via JavaScript.`,
              url: form.pageUrl,
              evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\nParameter: ${input.name}\nMethod: POST\nAction: ${actionUrl}\n${dangerousContext}`,
              confidence: 'medium',
              request: {
                method: 'POST',
                url: actionUrl,
                body: urlEncodedBody,
              },
              timestamp: new Date().toISOString(),
            });
            foundForInput = true;
          }
        } catch (err) {
          log.debug(`POST form XSS test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

/**
 * JSON API XSS: inject XSS payloads into JSON string values sent to API endpoints.
 * Tests for reflected XSS where the API echoes back unencoded payloads in JSON responses
 * that could be rendered in HTML context (stored XSS via API pattern).
 *
 * Only flags findings where:
 * 1. The raw payload appears in the JSON response unencoded, AND
 * 2. The payload contains HTML-significant characters (< > " ') that would be
 *    dangerous if the JSON value is rendered in HTML without encoding
 */
async function testJsonApiXss(
  context: BrowserContext,
  apiEndpoints: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = selectPayloads(config, 3);

  // Limit endpoints in non-deep mode
  const endpointsToTest = config.profile === 'deep' ? apiEndpoints : apiEndpoints.slice(0, 5);

  for (const endpoint of endpointsToTest) {
    // Skip destructive-looking endpoints
    if (DESTRUCTIVE_ACTION_RE.test(endpoint)) {
      log.debug(`Skipping destructive API endpoint: ${endpoint}`);
      continue;
    }

    for (const xssPayload of payloads) {
      // Only test payloads with HTML-significant characters
      if (!xssPayload.payload.includes('<') && !xssPayload.payload.includes('>') && !xssPayload.payload.includes('"')) {
        continue;
      }

      const page = await context.newPage();
      try {
        // Try POST with JSON body containing the payload in common field names
        const testBody = JSON.stringify({
          name: xssPayload.payload,
          text: xssPayload.payload,
          comment: xssPayload.payload,
          message: xssPayload.payload,
          title: xssPayload.payload,
          description: xssPayload.payload,
          author: xssPayload.payload,
          displayName: xssPayload.payload,
          bio: xssPayload.payload,
          content: xssPayload.payload,
          value: xssPayload.payload,
          query: xssPayload.payload,
        });

        // Try POST first
        let response = await page.request.fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          data: testBody,
        }).catch(() => null);

        // If POST returns 404/405, try PUT
        if (response && (response.status() === 404 || response.status() === 405)) {
          response = await page.request.fetch(endpoint, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            data: testBody,
          }).catch(() => null);
        }

        if (!response) continue;

        const status = response.status();
        // Skip server errors and not-found responses
        if (status >= 500 || status === 404 || status === 405) continue;

        const contentType = response.headers()['content-type'] ?? '';
        const responseText = await response.text();

        const method = 'POST';
        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method,
          url: endpoint,
          headers: { 'Content-Type': 'application/json' },
          body: testBody,
          phase: 'active-xss-json-api',
        });

        // Check 1: Does the JSON response contain the raw payload?
        if (contentType.includes('application/json') && responseText.includes(xssPayload.marker)) {
          // The API echoes back the payload in JSON. This is potentially dangerous
          // if the JSON values are rendered client-side without encoding.
          // Check if the raw HTML characters are preserved (not encoded)
          const hasRawHtml = responseText.includes(xssPayload.payload) &&
            (xssPayload.payload.includes('<') || xssPayload.payload.includes('>'));

          if (hasRawHtml) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'medium', // Medium because exploitation requires client-side rendering
              title: `Potential Stored XSS via JSON API`,
              description: `The API endpoint echoes back XSS payload (${xssPayload.type}) in JSON response without encoding HTML characters. If this data is rendered client-side via innerHTML or similar, it leads to stored XSS.`,
              url: endpoint,
              evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\nAPI Response (snippet): ${responseText.slice(0, 500)}`,
              request: {
                method,
                url: endpoint,
                headers: { 'Content-Type': 'application/json' },
                body: testBody,
              },
              response: {
                status,
                headers: { 'content-type': contentType },
                bodySnippet: responseText.slice(0, 500),
              },
              timestamp: new Date().toISOString(),
              confidence: 'medium',
            });
            break; // One finding per endpoint is enough
          }
        }

        // Check 2: Does the response render the payload in HTML context?
        // (Some APIs return HTML for certain requests)
        if (contentType.includes('text/html')) {
          const dangerousContext = checkDangerousReflection(responseText, xssPayload.payload, xssPayload.marker);
          if (dangerousContext) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `Reflected XSS in API Endpoint`,
              description: `The API endpoint reflects XSS payload (${xssPayload.type}) in HTML response without proper encoding. ${dangerousContext}.`,
              url: endpoint,
              evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\n${dangerousContext}`,
              request: {
                method,
                url: endpoint,
                headers: { 'Content-Type': 'application/json' },
                body: testBody,
              },
              timestamp: new Date().toISOString(),
              confidence: 'medium',
            });
            break;
          }
        }
      } catch (err) {
        log.debug(`JSON API XSS test: ${(err as Error).message}`);
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
                confidence: 'medium',
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

        // HPP bypass: when WAF detected, duplicate the parameter to bypass
        // WAFs that only inspect the first (or last) occurrence
        if (!foundForParam && config.wafDetection?.detected) {
          const hppUrls = generateHppVariants(originalUrl, param, xssPayload.payload);
          for (const hppUrl of hppUrls) {
            if (foundForParam) break;

            const page = await context.newPage();
            try {
              await page.goto(hppUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

              requestLogger?.log({
                timestamp: new Date().toISOString(),
                method: 'GET',
                url: hppUrl,
                phase: 'active-xss-hpp',
              });

              const content = await page.content();
              const dangerousContext = checkDangerousReflection(content, xssPayload.payload, xssPayload.marker);

              if (dangerousContext) {
                findings.push({
                  id: randomUUID(),
                  category: 'xss',
                  severity: 'high',
                  title: `Reflected XSS in URL Parameter "${param}" (HPP bypass)`,
                  description: `The URL parameter "${param}" reflects XSS payload (${xssPayload.type}) via HTTP Parameter Pollution. ${dangerousContext}. WAF was bypassed by duplicating the parameter.`,
                  url: originalUrl,
                  evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\nHPP URL: ${hppUrl}\n${dangerousContext}\nWAF bypass: HPP`,
                  request: { method: 'GET', url: hppUrl },
                  timestamp: new Date().toISOString(),
                  confidence: 'medium',
                });
                foundForParam = true;
              }
            } catch (err) {
              log.debug(`XSS HPP test: ${(err as Error).message}`);
            } finally {
              await page.close();
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
            confidence: 'medium',
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
 * Collect URLs that have search-like query parameters.
 * These are candidates for SPA search XSS testing, where the query is reflected
 * in the client-rendered DOM (e.g., Angular [innerHTML], React dangerouslySetInnerHTML).
 *
 * Exported for testing.
 */
export function collectSearchUrls(targets: ScanTargets, config?: ScanConfig): Array<{ url: string; param: string }> {
  const results: Array<{ url: string; param: string }> = [];
  const seen = new Set<string>();

  for (const url of targets.urlsWithParams) {
    try {
      const parsed = new URL(url);
      for (const [key] of parsed.searchParams) {
        if (SEARCH_PARAM_RE.test(key)) {
          const dedupeKey = `${parsed.origin}${parsed.pathname}:${key}`;
          if (!seen.has(dedupeKey)) {
            seen.add(dedupeKey);
            results.push({ url, param: key });
          }
        }
      }
    } catch {
      continue;
    }
  }

  // Also scan pages for search-like paths (e.g., /search, /#!/search, /#/search)
  for (const pageUrl of targets.pages) {
    try {
      const parsed = new URL(pageUrl);
      // Check both pathname and hash fragment for search routes (SPA hash-based routing)
      const isSearchPath = /\/(search|find|query|results|browse)\b/i.test(parsed.pathname);
      const isSearchHash = /\/(search|find|query|results|browse)\b/i.test(parsed.hash);
      if (isSearchPath || isSearchHash) {
        // If this page doesn't already have a search param, add it with 'q'
        const dedupeKey = `${pageUrl}:q`;
        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);
          // For hash-based routes, append ?q= to the hash fragment
          if (isSearchHash && !isSearchPath) {
            const hashUrl = parsed.hash.includes('?')
              ? `${pageUrl}&q=test`
              : `${pageUrl}?q=test`;
            results.push({ url: hashUrl, param: 'q' });
          } else {
            const withParam = new URL(pageUrl);
            withParam.searchParams.set('q', 'test');
            results.push({ url: withParam.href, param: 'q' });
          }
        }
      }
    } catch {
      continue;
    }
  }

  // When a SPA framework is detected, generate hash-based search route candidates.
  // Many SPAs (especially Angular) use hash routing: /rest/products/search?q= → /#/search?q=
  if (config?.detectedFramework) {
    const baseUrl = targets.pages[0] ? new URL(targets.pages[0]).origin : null;
    if (baseUrl) {
      // Infer hash routes from API search endpoints
      for (const r of [...results]) {
        try {
          const parsed = new URL(r.url);
          if (/\/(api|rest)\//i.test(parsed.pathname)) {
            // Extract the search-related path segment: /rest/products/search → search
            const match = parsed.pathname.match(/\/(search|find|query|results|browse)(?:[/?]|$)/i);
            if (match) {
              const hashRoute = `${baseUrl}/#/${match[1].toLowerCase()}`;
              const dedupeKey = `${hashRoute}:${r.param}`;
              if (!seen.has(dedupeKey)) {
                seen.add(dedupeKey);
                results.push({ url: `${hashRoute}?${r.param}=test`, param: r.param });
              }
            }
          }
        } catch { continue; }
      }
    }
  }

  // Filter out REST API endpoints for SPA DOM XSS testing — they return JSON, not rendered pages.
  // Keep only endpoints that are likely SPA pages (no /api/ or /rest/ path).
  const spaResults = results.filter(r => {
    try {
      const parsed = new URL(r.url);
      return !/\/(api|rest)\//i.test(parsed.pathname);
    } catch { return true; }
  });

  // If filtering removed everything, keep originals as fallback
  return spaResults.length > 0 ? spaResults : results;
}

/**
 * SPA Search Parameter XSS: Test for DOM XSS in SPA-rendered search results.
 *
 * Unlike testXssOnUrls which only checks the server response HTML, this function:
 * 1. Detects the SPA framework (Angular, React, Vue, etc.)
 * 2. Navigates to the search URL with XSS payload as the search parameter
 * 3. Waits for the SPA to render the results (framework-aware hydration)
 * 4. Checks the client-rendered DOM for unencoded XSS payloads
 *
 * This catches XSS in Angular [innerHTML], React dangerouslySetInnerHTML, Vue v-html,
 * and similar client-side rendering patterns where the server response is JSON but the
 * client renders the payload unsafely.
 *
 * Exported for testing.
 */
export async function testSearchParamXss(
  context: BrowserContext,
  searchUrls: Array<{ url: string; param: string }>,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const spaPayloads = getSpaSearchPayloads();

  // Limit URLs in non-deep mode
  const urlsToTest = config.profile === 'deep' ? searchUrls : searchUrls.slice(0, 5);

  for (const { url, param } of urlsToTest) {
    let foundForParam = false;

    for (const xssPayload of spaPayloads) {
      if (foundForParam) break;

      const page = await context.newPage();
      try {
        // Install DOM XSS sink monitors before navigation
        await page.addInitScript(DOM_XSS_INIT_SCRIPT);

        // Build the test URL with XSS payload in the search parameter.
        // For hash-based SPA routes (e.g., /#/search?q=test), inject into the hash fragment.
        const testUrl = new URL(url);
        const isHashRoute = testUrl.hash.includes('?');
        if (isHashRoute) {
          // Parse params inside hash fragment: /#/search?q=test → /#/search?q=<payload>
          const hashParts = testUrl.hash.split('?');
          const hashParams = new URLSearchParams(hashParts[1] || '');
          hashParams.set(param, xssPayload.payload);
          testUrl.hash = `${hashParts[0]}?${hashParams.toString()}`;
        } else {
          testUrl.searchParams.set(param, xssPayload.payload);
        }

        // Capture the initial HTTP response body for comparison later.
        // We use this to distinguish server-side reflection (caught by testXssOnUrls)
        // from client-side rendering (the unique value of this SPA check).
        let serverResponseBody = '';
        const responseCapture = (response: { url: () => string; headers: () => Record<string, string>; text: () => Promise<string> }) => {
          try {
            const ct = response.headers()['content-type'] ?? '';
            if (ct.includes('text/html') && response.url() === testUrl.href) {
              response.text().then(text => { serverResponseBody = text; }).catch(() => {});
            }
          } catch { /* ignore */ }
        };
        page.on('response', responseCapture);

        // Navigate and wait for initial load
        await page.goto(testUrl.href, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        // Brief settle before detection — Angular/React may not have markers ready immediately
        await delay(300);

        // Use pre-detected framework from crawl phase (avoids re-detection on fresh pages).
        // Fall back to live detection if not available.
        let framework = config.detectedFramework ?? await detectFramework(page);

        // If detection fails, wait for full load and retry — some SPAs bootstrap late
        if (!framework) {
          try {
            await page.waitForLoadState('load', { timeout: 3000 });
          } catch { /* timeout OK */ }
          framework = await detectFramework(page);
        }

        await waitForHydration(page, framework);

        // Additional wait for API responses to render — SPAs often fetch data and render async
        // Wait for network to be idle (no pending requests for 500ms)
        try {
          await page.waitForLoadState('networkidle', { timeout: 5000 });
        } catch {
          // Timeout is OK — some SPAs have long-polling or websockets
        }

        // Extra settling time for client-side rendering
        await delay(500);

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: testUrl.href,
          phase: 'active-xss-spa-search',
        });

        // ── Check 1: Client-rendered DOM content analysis ──
        // Get the fully rendered DOM (after Angular/React/Vue rendering)
        const renderedContent = await page.content();

        // Check if the payload appears unencoded in the rendered DOM
        const dangerousContext = checkDangerousReflection(renderedContent, xssPayload.payload, xssPayload.marker);

        if (dangerousContext) {
          // Only flag this as a SPA finding if the payload was NOT already in the
          // server response HTML. If the server reflects the payload directly,
          // testXssOnUrls already catches it — we don't want duplicates.
          const payloadInServerResponse = serverResponseBody.includes(xssPayload.payload);

          if (!payloadInServerResponse) {
            const isSpaRendered = framework !== null;

            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `DOM XSS in Search Parameter "${param}"${isSpaRendered ? ` (${framework!.name} SPA)` : ''}`,
              description: `The search parameter "${param}" is reflected in the ${isSpaRendered ? 'client-rendered' : ''} DOM without proper encoding. ${dangerousContext}.${isSpaRendered ? ` The ${framework!.name} application renders user input unsafely (e.g., via [innerHTML] binding or similar).` : ''} The payload was injected client-side (not in the server response), indicating a DOM-based XSS.`,
              url,
              evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\nParameter: ${param}\nTest URL: ${testUrl.href}\nFramework: ${framework?.name ?? 'none detected'}\n${dangerousContext}`,
              request: { method: 'GET', url: testUrl.href },
              timestamp: new Date().toISOString(),
              confidence: 'medium',
            });
            foundForParam = true;
            continue;
          }
        }

        // ── Check 2: Sink monitoring ──
        // Check if any DOM sink (innerHTML, document.write, eval, etc.)
        // received a value containing the FULL PAYLOAD (not just marker).
        // The marker alone is not sufficient because it's a plain alphanumeric
        // string that appears even when HTML tags are properly encoded.
        const sinkHits = await page.evaluate((payload: string) => {
          const hits = (window as unknown as Record<string, unknown>).__secbot_dom_xss as Array<{ sink: string; value: string }> || [];
          return hits.filter((h) => h.value.includes(payload));
        }, xssPayload.payload);

        if (sinkHits.length > 0) {
          const sinkNames = sinkHits.map((h: { sink: string }) => h.sink).join(', ');
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `DOM XSS in Search Parameter "${param}" via ${sinkNames}`,
            description: `The search parameter "${param}" reaches dangerous DOM sink(s): ${sinkNames}. The payload flows from the search API response into the client-side DOM without proper sanitization.${framework ? ` Framework: ${framework.name}.` : ''}`,
            url,
            evidence: `Payload: ${xssPayload.payload}\nSinks: ${sinkNames}\nParameter: ${param}\nTest URL: ${testUrl.href}\nFramework: ${framework?.name ?? 'none detected'}`,
            request: { method: 'GET', url: testUrl.href },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          });
          foundForParam = true;
          continue;
        }

        // ── Check 3: Evaluate DOM for marker presence in element content ──
        // This catches cases where the marker appears in text content or attributes
        // even if the full payload is sanitized but the marker string leaks through
        const markerInDom = await page.evaluate((marker: string) => {
          // Check text content of all elements
          const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_ELEMENT,
            null,
          );
          const results: Array<{ tag: string; attribute?: string; content: string }> = [];
          let node: Node | null;
          while ((node = walker.nextNode())) {
            const el = node as Element;
            // Check innerHTML for unencoded payload markers
            if (el.innerHTML?.includes(marker)) {
              // Verify it's not just in a text node (safely encoded)
              // Look for the marker inside HTML tags or attributes
              const inner = el.innerHTML;
              const idx = inner.indexOf(marker);
              if (idx !== -1) {
                // Check surrounding context: is it inside a tag?
                const before = inner.slice(Math.max(0, idx - 50), idx);
                const after = inner.slice(idx, idx + marker.length + 50);
                // If we find < before and > after without encoding, it's in a tag context
                if (before.includes('<') && !before.includes('&lt;')) {
                  results.push({
                    tag: el.tagName.toLowerCase(),
                    content: inner.slice(Math.max(0, idx - 100), idx + marker.length + 100),
                  });
                }
              }
            }
            // Check dangerous attributes
            for (const attr of ['src', 'href', 'action', 'data']) {
              const val = el.getAttribute(attr);
              if (val?.includes(marker)) {
                results.push({
                  tag: el.tagName.toLowerCase(),
                  attribute: attr,
                  content: val,
                });
              }
            }
          }
          return results;
        }, xssPayload.marker);

        if (markerInDom.length > 0) {
          const contexts = markerInDom.map((m) =>
            m.attribute ? `${m.tag}[${m.attribute}]` : `${m.tag}.innerHTML`,
          ).join(', ');

          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `DOM XSS in Search Parameter "${param}"${framework ? ` (${framework.name} SPA)` : ''}`,
            description: `The search parameter "${param}" is rendered unsafely in the DOM context(s): ${contexts}. The XSS payload marker appears within HTML tags in the rendered DOM, indicating the application does not properly sanitize user input before rendering.${framework ? ` Framework: ${framework.name}.` : ''}`,
            url,
            evidence: `Payload: ${xssPayload.payload}\nParameter: ${param}\nDOM contexts: ${contexts}\nTest URL: ${testUrl.href}\nFramework: ${framework?.name ?? 'none detected'}\nDOM snippet: ${markerInDom[0].content.slice(0, 200)}`,
            request: { method: 'GET', url: testUrl.href },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          });
          foundForParam = true;
        }
      } catch (err) {
        log.debug(`SPA search XSS test: ${(err as Error).message}`);
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
            confidence: 'medium',
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

/**
 * Inject blind XSS payloads into forms and URL parameters.
 * These payloads phone home to the callback URL — actual detection happens
 * on the user's callback server (Burp Collaborator, interactsh, etc.).
 * We don't expect a reflected response; we just inject and log.
 */
async function injectBlindXss(
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
      (i) => ['text', 'search', 'email', 'url', 'tel', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const payload of blindPayloads) {
      const page = await context.newPage();
      try {
        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        for (const input of textInputs) {
          try {
            await page.fill(`[name="${input.name}"]`, payload);
          } catch (err) {
            log.debug(`Blind XSS fill: ${(err as Error).message}`);
          }
        }

        try {
          const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
          if (await submitBtn.count() > 0) {
            await submitBtn.click({ timeout: 5000 });
          } else {
            await page.locator('form').first().evaluate((f) => (f as HTMLFormElement).submit());
          }
          // Brief wait for submission to complete
          await delay(1000);
        } catch (err) {
          log.debug(`Blind XSS submit: ${(err as Error).message}`);
        }

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: form.method,
          url: form.action,
          body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
          phase: 'active-xss-blind',
        });

        injectedCount++;
      } catch (err) {
        log.debug(`Blind XSS form inject: ${(err as Error).message}`);
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
          await page.goto(testUrl.href, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            phase: 'active-xss-blind',
          });

          injectedCount++;
        } catch (err) {
          log.debug(`Blind XSS URL inject: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  if (injectedCount > 0) {
    log.info(`Injected ${injectedCount} blind XSS callback payloads. Check your callback server for hits.`);
  }

  // Blind XSS findings are detected out-of-band — no immediate findings to return
  return [];
}

/**
 * Detect whether the target URL sends a Content-Security-Policy header.
 * Makes a single lightweight GET request and inspects response headers.
 * Returns false on any error to avoid blocking the scan.
 */
async function detectCsp(
  context: BrowserContext,
  targetUrl: string,
  config: ScanConfig,
): Promise<boolean> {
  const page = await context.newPage();
  try {
    const response = await page.request.fetch(targetUrl, {
      method: 'GET',
      headers: { Accept: 'text/html' },
    }).catch(() => null);

    if (!response) return false;

    const headers = response.headers();
    return 'content-security-policy' in headers ||
      'content-security-policy-report-only' in headers;
  } catch (err) {
    log.debug(`CSP detection: ${(err as Error).message}`);
    return false;
  } finally {
    await page.close();
  }
}

/**
 * Mutation XSS: test payloads that exploit browser parser quirks to bypass sanitizers.
 * Uses the same injection+detection pattern as testDomXss (URL fragment + sink monitoring).
 * Only runs when profile is 'deep' or AI focus areas mention mutation/mxss.
 */
async function testMutationXss(
  context: BrowserContext,
  pageUrls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Limit pages in non-deep mode
  const pagesToTest = config.profile === 'deep' ? pageUrls : pageUrls.slice(0, 3);

  for (const pageUrl of pagesToTest) {
    for (const xssPayload of MUTATION_XSS_PAYLOADS) {
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
        await delay(500);

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: testUrl,
          phase: 'active-xss-mutation',
        });

        // Check if any sink received a value containing our marker
        const sinkHits = await page.evaluate((marker: string) => {
          const hits = (window as any).__secbot_dom_xss || [];
          return hits.filter((h: { sink: string; value: string }) =>
            h.value.includes(marker),
          );
        }, xssPayload.marker);

        if (sinkHits.length > 0) {
          const sinkNames = sinkHits.map((h: { sink: string }) => h.sink).join(', ');
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `Mutation XSS via URL Fragment`,
            description: `Mutation XSS payload (${xssPayload.type}) injected via URL fragment reaches dangerous DOM sink(s): ${sinkNames}. This payload exploits browser parser quirks to bypass sanitizers such as DOMPurify.`,
            url: pageUrl,
            evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\nSinks: ${sinkNames}\nTest URL: ${pageUrl}#${fragmentPayload}`,
            request: { method: 'GET', url: `${pageUrl}#${fragmentPayload}` },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          });
          break; // One finding per page is enough
        }

        // Also check rendered page content for unencoded payload reflection
        const content = await page.content();
        const dangerousContext = checkDangerousReflection(content, xssPayload.payload, xssPayload.marker);

        if (dangerousContext) {
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `Mutation XSS Payload Reflected`,
            description: `Mutation XSS payload (${xssPayload.type}) appears unencoded in rendered page content. ${dangerousContext}. This payload exploits browser parser quirks that may bypass sanitizers.`,
            url: pageUrl,
            evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\n${dangerousContext}\nTest URL: ${pageUrl}#${fragmentPayload}`,
            request: { method: 'GET', url: `${pageUrl}#${fragmentPayload}` },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          });
          break;
        }
      } catch (err) {
        log.debug(`Mutation XSS test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

/**
 * CSP bypass XSS: test payloads designed to circumvent Content-Security-Policy.
 * Injects into URL parameters and form fields, checking for unencoded reflection.
 * Only runs when a CSP header is detected on the target.
 */
async function testCspBypassXss(
  context: BrowserContext,
  targets: ScanTargets,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Test URL parameters
  const urlsToTest = config.profile === 'deep'
    ? targets.urlsWithParams
    : targets.urlsWithParams.slice(0, 3);

  for (const originalUrl of urlsToTest) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(originalUrl);
    } catch {
      continue;
    }

    const params = Array.from(parsedUrl.searchParams.keys());
    let foundForUrl = false;

    for (const param of params) {
      if (foundForUrl) break;

      for (const xssPayload of CSP_BYPASS_PAYLOADS) {
        if (foundForUrl) break;

        // Skip template-type payloads for URL reflection — they require server-side
        // template evaluation and are better tested by the SSTI check
        if (xssPayload.type === 'template') continue;

        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, xssPayload.payload);

        const page = await context.newPage();
        try {
          await page.goto(testUrl.href, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            phase: 'active-xss-csp-bypass',
          });

          const content = await page.content();
          const dangerousContext = checkDangerousReflection(content, xssPayload.payload, xssPayload.marker);

          if (dangerousContext) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `CSP Bypass XSS in URL Parameter "${param}"`,
              description: `Despite a Content-Security-Policy being present, the XSS payload (${xssPayload.type}) is reflected in a dangerous context. ${dangerousContext}. The payload is designed to bypass common CSP configurations.`,
              url: originalUrl,
              evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\nParameter: ${param}\nTest URL: ${testUrl.href}\n${dangerousContext}`,
              request: { method: 'GET', url: testUrl.href },
              timestamp: new Date().toISOString(),
              confidence: 'low',
            });
            foundForUrl = true;
          }
        } catch (err) {
          log.debug(`CSP bypass XSS test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  // Test form fields (limit to 2 forms in non-deep mode)
  const formsToTest = config.profile === 'deep'
    ? targets.forms
    : targets.forms.slice(0, 2);

  for (const form of formsToTest) {
    if (DESTRUCTIVE_ACTION_RE.test(form.action)) continue;

    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const xssPayload of CSP_BYPASS_PAYLOADS) {
      const page = await context.newPage();
      try {
        let responseBody = '';
        page.on('response', async (response) => {
          try {
            const ct = response.headers()['content-type'] ?? '';
            if (ct.includes('text/html')) {
              responseBody = await response.text();
            }
          } catch { /* ignore */ }
        });

        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        for (const input of textInputs) {
          try {
            await page.fill(`[name="${input.name}"]`, xssPayload.payload);
          } catch (err) {
            log.debug(`CSP bypass form fill: ${(err as Error).message}`);
          }
        }

        responseBody = '';
        try {
          const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
          if (await submitBtn.count() > 0) {
            await submitBtn.click({ timeout: 5000 });
            await delay(2000);
          }
        } catch (err) {
          log.debug(`CSP bypass form submit: ${(err as Error).message}`);
        }

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: form.method,
          url: form.action,
          body: textInputs.map((i) => `${i.name}=${xssPayload.payload}`).join('&'),
          phase: 'active-xss-csp-bypass',
        });

        const content = responseBody || (await page.content());
        const dangerousContext = checkDangerousReflection(content, xssPayload.payload, xssPayload.marker);

        if (dangerousContext) {
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `CSP Bypass XSS in Form Input "${textInputs[0].name}"`,
            description: `Despite a Content-Security-Policy being present, the form input "${textInputs[0].name}" reflects XSS payload (${xssPayload.type}) in a dangerous context. ${dangerousContext}. The payload is designed to bypass common CSP configurations.`,
            url: form.pageUrl,
            evidence: `Payload: ${xssPayload.payload}\nType: ${xssPayload.type}\n${dangerousContext}`,
            request: {
              method: form.method,
              url: form.action,
              body: textInputs.map((i) => `${i.name}=${xssPayload.payload}`).join('&'),
            },
            timestamp: new Date().toISOString(),
            confidence: 'low',
          });
          break;
        }
      } catch (err) {
        log.debug(`CSP bypass form XSS test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

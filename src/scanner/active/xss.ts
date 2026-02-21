import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { XSS_PAYLOADS, XSS_MARKERS } from '../../config/payloads/xss.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

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

export const xssCheck: ActiveCheck = {
  name: 'xss',
  category: 'xss',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for XSS...`);
      findings.push(...(await testXssOnForms(context, targets.forms, config, requestLogger)));
    }

    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for reflected XSS...`);
      findings.push(...(await testXssOnUrls(context, targets.urlsWithParams, config, requestLogger)));
    }

    return findings;
  },
};

/**
 * Check if nearby content has HTML-encoded versions of the marker,
 * indicating the app IS encoding output (safe, not XSS).
 */
function isHtmlEncoded(content: string, marker: string): boolean {
  // Look for HTML entities near the marker position
  const idx = content.indexOf(marker);
  if (idx === -1) return false;

  // Check a window around the marker for HTML entities
  const windowStart = Math.max(0, idx - 100);
  const windowEnd = Math.min(content.length, idx + marker.length + 100);
  const window = content.slice(windowStart, windowEnd);

  return /&lt;|&gt;|&quot;|&#x27;|&#39;|&amp;/.test(window);
}

/**
 * Check if a payload is reflected in a dangerous (unencoded, executable) context.
 * Returns the context description if dangerous, null if safely encoded.
 */
function checkDangerousReflection(content: string, payload: string, marker?: string | null): string | null {
  // Check full payload first (higher signal)
  if (content.includes(payload)) {
    // Check all context patterns for full payloads
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

async function testXssOnForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = config.profile === 'deep' ? XSS_PAYLOADS : XSS_PAYLOADS.slice(0, 5);

  for (let formIdx = 0; formIdx < forms.length; formIdx++) {
    const form = forms[formIdx];
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const payload of payloads) {
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
              await formLocator.locator(`[name="${input.name}"]`).fill(payload);
            } else {
              await page.fill(`[name="${input.name}"]`, payload);
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
            // Submit the specific form
            const submitBtn = formLocator.locator('button[type="submit"], input[type="submit"]').first();
            if (await submitBtn.count() > 0) {
              await submitBtn.click({ timeout: 5000 });
            } else {
              await formLocator.evaluate((f) => (f as HTMLFormElement).submit());
            }
          } else {
            // Fallback: try any submit button
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
          body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
          phase: 'active-xss',
        });

        const content = responseBody || (await page.content());
        const markerIndex = XSS_PAYLOADS.indexOf(payload);
        const marker = markerIndex >= 0 ? XSS_MARKERS[markerIndex] : null;

        const dangerousContext = checkDangerousReflection(content, payload, marker);

        if (dangerousContext) {
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `Reflected XSS in Form Input "${textInputs[0].name}"`,
            description: `The form input "${textInputs[0].name}" reflects XSS payload in a dangerous context without proper encoding. ${dangerousContext}.`,
            url: form.pageUrl,
            evidence: `Payload: ${payload}\n${dangerousContext}`,
            request: {
              method: form.method,
              url: form.action,
              body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
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
  const payloads = config.profile === 'deep' ? XSS_PAYLOADS : XSS_PAYLOADS.slice(0, 3);

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
      for (const payload of payloads) {
        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, payload);

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
          const markerIndex = XSS_PAYLOADS.indexOf(payload);
          const marker = markerIndex >= 0 ? XSS_MARKERS[markerIndex] : null;

          const dangerousContext = checkDangerousReflection(content, payload, marker);

          if (dangerousContext) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `Reflected XSS in URL Parameter "${param}"`,
              description: `The URL parameter "${param}" reflects XSS payload in a dangerous context without proper encoding. ${dangerousContext}.`,
              url: originalUrl,
              evidence: `Payload: ${payload}\nTest URL: ${testUrl.href}\n${dangerousContext}`,
              request: { method: 'GET', url: testUrl.href },
              timestamp: new Date().toISOString(),
            });
            break;
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

  return findings;
}

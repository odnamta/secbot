import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { XSS_PAYLOADS, XSS_MARKERS } from '../../config/payloads/xss.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

export const xssCheck: ActiveCheck = {
  name: 'xss',
  category: 'xss',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // XSS on forms
    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for XSS...`);
      findings.push(...(await testXssOnForms(context, targets.forms, config, requestLogger)));
    }

    // XSS on URL parameters
    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for reflected XSS...`);
      findings.push(...(await testXssOnUrls(context, targets.urlsWithParams, config, requestLogger)));
    }

    return findings;
  },
};

async function testXssOnForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = config.profile === 'deep' ? XSS_PAYLOADS : XSS_PAYLOADS.slice(0, 5);

  for (const form of forms) {
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const payload of payloads) {
      const page = await context.newPage();
      try {
        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        for (const input of textInputs) {
          try {
            await page.fill(`[name="${input.name}"]`, payload);
          } catch {
            // Input may not be fillable
          }
        }

        let responseBody = '';
        page.on('response', async (response) => {
          try {
            const ct = response.headers()['content-type'] ?? '';
            if (ct.includes('text/html')) {
              responseBody = await response.text();
            }
          } catch {
            // Ignore
          }
        });

        try {
          const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
          if (await submitBtn.count() > 0) {
            await submitBtn.click({ timeout: 5000 });
          } else {
            await page.locator('form').first().evaluate((f) => (f as HTMLFormElement).submit());
          }
          await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        } catch {
          // Form submission may fail
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

        const isReflected =
          content.includes(payload) ||
          (marker && content.includes(marker));

        if (isReflected) {
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `Reflected XSS in Form Input "${textInputs[0].name}"`,
            description: `The form input "${textInputs[0].name}" reflects XSS payload without proper encoding.`,
            url: form.pageUrl,
            evidence: `Payload: ${payload}\nReflected in response body`,
            request: {
              method: form.method,
              url: form.action,
              body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
            },
            timestamp: new Date().toISOString(),
          });
          break;
        }
      } catch {
        // Continue to next payload
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
    const parsedUrl = new URL(originalUrl);
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

          if (content.includes(payload)) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `Reflected XSS in URL Parameter "${param}"`,
              description: `The URL parameter "${param}" reflects XSS payload without proper encoding.`,
              url: originalUrl,
              evidence: `Payload: ${payload}\nTest URL: ${testUrl.href}`,
              request: { method: 'GET', url: testUrl.href },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch {
          // Continue
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

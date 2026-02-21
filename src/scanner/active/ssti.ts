import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { SSTI_PAYLOADS, SSTI_CONTROL_PAYLOADS } from '../../config/payloads/ssti.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

export const sstiCheck: ActiveCheck = {
  name: 'ssti',
  category: 'ssti',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Test URL parameters
    if (targets.urlsWithParams.length > 0) {
      log.info(`Testing ${targets.urlsWithParams.length} URLs for SSTI...`);
      const paramFindings = await testSstiParams(context, targets.urlsWithParams, config, requestLogger);
      findings.push(...paramFindings);
    }

    // Test form inputs
    if (targets.forms.length > 0) {
      log.info(`Testing ${targets.forms.length} forms for SSTI...`);
      const formFindings = await testSstiForms(context, targets.forms, config, requestLogger);
      findings.push(...formFindings);
    }

    return findings;
  },
};

/** Find a control payload for the same engine family */
function findControlPayload(engine: string) {
  return SSTI_CONTROL_PAYLOADS.find((c) => c.engine === engine);
}

async function testSstiParams(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloadsToTest = config.profile === 'deep' ? SSTI_PAYLOADS : SSTI_PAYLOADS.slice(0, 4);

  for (const originalUrl of urls) {
    let foundForUrl = false;
    const parsed = new URL(originalUrl);
    const params = Array.from(parsed.searchParams.keys());

    if (params.length === 0) continue;

    // Get baseline response to check for false positives
    let baselineBody = '';
    const baselinePage = await context.newPage();
    try {
      const baselineResponse = await baselinePage.request.fetch(originalUrl);
      baselineBody = await baselineResponse.text();
    } catch {
      // Baseline fetch may fail
    } finally {
      await baselinePage.close();
    }

    for (const param of params) {
      if (foundForUrl) break;

      for (const sstiPayload of payloadsToTest) {
        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, sstiPayload.payload);

        const page = await context.newPage();
        try {
          const response = await page.request.fetch(testUrl.href);
          const body = await response.text();
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            responseStatus: status,
            phase: 'active-ssti',
          });

          // Check if the expected evaluated value appears in the response
          // but was NOT already present in the baseline
          if (body.includes(sstiPayload.expected) && !baselineBody.includes(sstiPayload.expected)) {
            // Try the control payload for the same engine to confirm actual template evaluation
            let confirmed = false;
            const control = findControlPayload(sstiPayload.engine);

            if (control) {
              const controlUrl = new URL(originalUrl);
              controlUrl.searchParams.set(param, control.payload);
              const controlPage = await context.newPage();
              try {
                const controlResponse = await controlPage.request.fetch(controlUrl.href);
                const controlBody = await controlResponse.text();

                requestLogger?.log({
                  timestamp: new Date().toISOString(),
                  method: 'GET',
                  url: controlUrl.href,
                  responseStatus: controlResponse.status(),
                  phase: 'active-ssti-control',
                });

                if (controlBody.includes(control.expected) && !baselineBody.includes(control.expected)) {
                  confirmed = true;
                }
              } catch {
                // Control check failed — still report the primary finding
              } finally {
                await controlPage.close();
              }
            }

            findings.push({
              id: randomUUID(),
              category: 'ssti',
              severity: 'critical',
              title: `Server-Side Template Injection via "${param}" Parameter${confirmed ? ' (Confirmed)' : ''}`,
              description: `The parameter "${param}" evaluates template expressions server-side (engine: ${sstiPayload.engine}). SSTI can lead to Remote Code Execution (RCE).${confirmed ? ' Confirmed with control payload.' : ''}`,
              url: originalUrl,
              evidence: `Payload: ${sstiPayload.payload}\nExpected: ${sstiPayload.expected}\nEngine: ${sstiPayload.engine}\nConfirmed: ${confirmed}\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method: 'GET', url: testUrl.href },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
            foundForUrl = true;
            break;
          }
        } catch (err) {
          log.debug(`SSTI test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

async function testSstiForms(
  context: BrowserContext,
  forms: { action: string; method: string; inputs: { name: string; type: string; value?: string }[]; pageUrl: string }[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloadsToTest = config.profile === 'deep' ? SSTI_PAYLOADS : SSTI_PAYLOADS.slice(0, 4);

  for (const form of forms) {
    let foundForForm = false;
    const textInputs = form.inputs.filter(
      (i) => !i.type || ['text', 'search', 'email', 'url', 'tel', 'hidden', ''].includes(i.type),
    );

    if (textInputs.length === 0) continue;

    const actionUrl = new URL(form.action || form.pageUrl, form.pageUrl).href;

    // Get baseline response
    let baselineBody = '';
    const baselinePage = await context.newPage();
    try {
      const baselineResponse = await baselinePage.request.fetch(actionUrl);
      baselineBody = await baselineResponse.text();
    } catch {
      // Baseline may fail
    } finally {
      await baselinePage.close();
    }

    for (const input of textInputs) {
      if (foundForForm) break;

      for (const sstiPayload of payloadsToTest) {
        // Build form data
        const formData: Record<string, string> = {};
        for (const inp of form.inputs) {
          formData[inp.name] = inp.value || 'test';
        }
        formData[input.name] = sstiPayload.payload;

        const page = await context.newPage();
        try {
          const method = form.method.toUpperCase();
          let response;
          if (method === 'POST') {
            response = await page.request.post(actionUrl, { form: formData });
          } else {
            const getUrl = new URL(actionUrl);
            for (const [k, v] of Object.entries(formData)) {
              getUrl.searchParams.set(k, v);
            }
            response = await page.request.fetch(getUrl.href);
          }

          const body = await response.text();
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method,
            url: actionUrl,
            responseStatus: status,
            phase: 'active-ssti-form',
          });

          if (body.includes(sstiPayload.expected) && !baselineBody.includes(sstiPayload.expected)) {
            findings.push({
              id: randomUUID(),
              category: 'ssti',
              severity: 'critical',
              title: `Server-Side Template Injection via "${input.name}" Form Input`,
              description: `The form input "${input.name}" on ${form.pageUrl} evaluates template expressions server-side (engine: ${sstiPayload.engine}). SSTI can lead to Remote Code Execution (RCE).`,
              url: form.pageUrl,
              evidence: `Payload: ${sstiPayload.payload}\nExpected: ${sstiPayload.expected}\nEngine: ${sstiPayload.engine}\nForm action: ${actionUrl}\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method, url: actionUrl, body: JSON.stringify(formData) },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
            foundForForm = true;
            break;
          }
        } catch (err) {
          log.debug(`SSTI form test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

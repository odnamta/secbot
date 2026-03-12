import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

// ─── Business endpoint URL patterns ────────────────────────────────
export const BUSINESS_URL_PATTERNS = [
  /\/cart/i,
  /\/checkout/i,
  /\/payment/i,
  /\/order/i,
  /\/purchase/i,
  /\/basket/i,
  /\/billing/i,
  // REST API commerce patterns (e.g. /api/BasketItems, /rest/basket/)
  /\/api\/basket/i,
  /\/api\/order/i,
  /\/api\/product/i,
  /\/api\/cart/i,
  /\/api\/payment/i,
  /\/rest\/basket/i,
  /\/rest\/order/i,
  /\/rest\/product/i,
  // Common e-commerce API patterns
  /\/api\/invoice/i,
  /\/api\/coupon/i,
  /\/api\/discount/i,
  /\/api\/promo/i,
];

// ─── Form field patterns that indicate business logic ──────────────
export const PRICE_FIELD_PATTERNS = [
  /^price$/i,
  /^cost$/i,
  /^amount$/i,
  /^total$/i,
  /^discount$/i,
  /^subtotal$/i,
];

export const QUANTITY_FIELD_PATTERNS = [
  /^quantity$/i,
  /^qty$/i,
];

export const COUPON_FIELD_PATTERNS = [
  /^coupon$/i,
  /^promo$/i,
  /^code$/i,
];

export const BUSINESS_FIELD_PATTERNS = [
  ...PRICE_FIELD_PATTERNS,
  ...QUANTITY_FIELD_PATTERNS,
  ...COUPON_FIELD_PATTERNS,
];

// ─── Manipulation payloads ─────────────────────────────────────────
export const PRICE_PAYLOADS = ['0', '-1', '0.01', '999999'];
export const QUANTITY_PAYLOADS = ['0', '-1', '999999'];

// ─── Step bypass patterns ──────────────────────────────────────────
export const STEP_PARAM_PATTERNS = [/step=/i, /page=/i, /stage=/i, /phase=/i];

/** Check if a URL matches any business endpoint pattern */
export function isBusinessUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return BUSINESS_URL_PATTERNS.some((pattern) => pattern.test(parsed.pathname));
  } catch {
    return false;
  }
}

/** Check if a form contains any business-logic-related fields */
export function hasBusinessFields(form: FormInfo): boolean {
  return form.inputs.some((input) =>
    BUSINESS_FIELD_PATTERNS.some((pattern) => pattern.test(input.name)),
  );
}

/** Get price/amount fields from a form */
export function getPriceFields(form: FormInfo): string[] {
  return form.inputs
    .filter((input) => PRICE_FIELD_PATTERNS.some((pattern) => pattern.test(input.name)))
    .map((input) => input.name);
}

/** Get quantity fields from a form */
export function getQuantityFields(form: FormInfo): string[] {
  return form.inputs
    .filter((input) => QUANTITY_FIELD_PATTERNS.some((pattern) => pattern.test(input.name)))
    .map((input) => input.name);
}

/** Check if a URL contains step/workflow parameters */
export function hasStepParam(url: string): boolean {
  return STEP_PARAM_PATTERNS.some((pattern) => pattern.test(url));
}

/** Extract the step parameter name and value from a URL */
export function extractStepParam(url: string): { param: string; value: string } | null {
  try {
    const parsed = new URL(url);
    for (const [key, value] of parsed.searchParams) {
      if (/^(step|page|stage|phase)$/i.test(key)) {
        return { param: key, value };
      }
    }
  } catch {
    // Invalid URL
  }
  return null;
}

/** Filter forms to only business-relevant ones (by URL or field names) */
export function filterBusinessForms(forms: FormInfo[]): FormInfo[] {
  return forms.filter((form) => {
    const actionUrl = form.action || form.pageUrl;
    return isBusinessUrl(actionUrl) || isBusinessUrl(form.pageUrl) || hasBusinessFields(form);
  });
}

/** Filter API endpoints that match business logic patterns */
export function filterBusinessApiEndpoints(pages: string[], apiEndpoints: string[]): string[] {
  const allUrls = [...new Set([...pages, ...apiEndpoints])];
  return allUrls.filter(isBusinessUrl);
}

export const businessLogicCheck: ActiveCheck = {
  name: 'business-logic',
  category: 'business-logic',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // A) Filter to business-relevant forms
    const businessForms = filterBusinessForms(targets.forms);

    if (businessForms.length > 0) {
      log.info(`Testing ${businessForms.length} business forms for logic flaws...`);
      const formFindings = await testPriceQuantityManipulation(
        context,
        businessForms,
        config,
        requestLogger,
      );
      findings.push(...formFindings);
    }

    // B) Test business API endpoints directly (JSON APIs without HTML forms)
    const businessApis = filterBusinessApiEndpoints(targets.pages, targets.apiEndpoints);
    if (businessApis.length > 0) {
      log.info(`Testing ${businessApis.length} business API endpoint(s) for logic flaws...`);
      const apiFindings = await testApiPriceManipulation(
        context,
        businessApis,
        config,
        requestLogger,
      );
      findings.push(...apiFindings);
    }

    // C) Workflow step bypass — check URLs with step parameters
    const stepUrls = [
      ...targets.urlsWithParams.filter(hasStepParam),
      ...targets.pages.filter(hasStepParam),
    ];
    const uniqueStepUrls = [...new Set(stepUrls)];

    if (uniqueStepUrls.length > 0) {
      log.info(`Testing ${uniqueStepUrls.length} URLs for workflow step bypass...`);
      const stepFindings = await testWorkflowBypass(
        context,
        uniqueStepUrls,
        config,
        requestLogger,
      );
      findings.push(...stepFindings);
    }

    if (businessForms.length === 0 && businessApis.length === 0 && uniqueStepUrls.length === 0) {
      log.info('No business logic endpoints detected — skipping business logic checks');
    }

    return findings;
  },
};

async function testPriceQuantityManipulation(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const form of forms) {
    const actionUrl = new URL(form.action || form.pageUrl, form.pageUrl).href;
    const priceFields = getPriceFields(form);
    const quantityFields = getQuantityFields(form);

    // Test price/amount manipulation
    for (const fieldName of priceFields) {
      for (const payload of PRICE_PAYLOADS) {
        const formData: Record<string, string> = {};
        for (const inp of form.inputs) {
          formData[inp.name] = inp.value || 'test';
        }
        formData[fieldName] = payload;

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

          const status = response.status();
          const body = await response.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method,
            url: actionUrl,
            responseStatus: status,
            phase: 'active-business-logic-price',
          });

          if (status === 200) {
            findings.push({
              id: randomUUID(),
              category: 'business-logic',
              severity: 'high',
              title: `Price Manipulation Accepted — "${fieldName}" set to ${payload}`,
              description: `The form at ${form.pageUrl} accepted a manipulated price/amount value of "${payload}" in the "${fieldName}" field and returned HTTP 200. This may allow attackers to purchase items at arbitrary prices.`,
              url: form.pageUrl,
              evidence: `Field: ${fieldName}\nPayload: ${payload}\nForm action: ${actionUrl}\nHTTP status: ${status}\nResponse snippet: ${body.slice(0, 200)}`,
              request: { method, url: actionUrl, body: JSON.stringify(formData) },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
            // One finding per field is enough
            break;
          }
        } catch (err) {
          log.debug(`Business logic price test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    // Test quantity manipulation
    for (const fieldName of quantityFields) {
      for (const payload of QUANTITY_PAYLOADS) {
        const formData: Record<string, string> = {};
        for (const inp of form.inputs) {
          formData[inp.name] = inp.value || 'test';
        }
        formData[fieldName] = payload;

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

          const status = response.status();
          const body = await response.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method,
            url: actionUrl,
            responseStatus: status,
            phase: 'active-business-logic-quantity',
          });

          if (status === 200) {
            findings.push({
              id: randomUUID(),
              category: 'business-logic',
              severity: 'high',
              title: `Quantity Manipulation Accepted — "${fieldName}" set to ${payload}`,
              description: `The form at ${form.pageUrl} accepted a manipulated quantity value of "${payload}" in the "${fieldName}" field and returned HTTP 200. This may allow attackers to order negative or excessive quantities.`,
              url: form.pageUrl,
              evidence: `Field: ${fieldName}\nPayload: ${payload}\nForm action: ${actionUrl}\nHTTP status: ${status}\nResponse snippet: ${body.slice(0, 200)}`,
              request: { method, url: actionUrl, body: JSON.stringify(formData) },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
            break;
          }
        } catch (err) {
          log.debug(`Business logic quantity test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

/** JSON body payloads for API price/quantity manipulation */
const API_MANIPULATION_PAYLOADS = [
  { field: 'price', value: 0, severity: 'high' as const },
  { field: 'price', value: -1, severity: 'high' as const },
  { field: 'quantity', value: -1, severity: 'high' as const },
  { field: 'quantity', value: 0, severity: 'medium' as const },
  { field: 'total', value: 0, severity: 'high' as const },
  { field: 'amount', value: -1, severity: 'high' as const },
];

async function testApiPriceManipulation(
  context: BrowserContext,
  endpoints: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Test up to 5 business API endpoints
  for (const endpoint of endpoints.slice(0, 5)) {
    // First GET the endpoint to understand its response structure
    const page = await context.newPage();
    try {
      const getResponse = await page.request.fetch(endpoint);
      const getStatus = getResponse.status();
      if (getStatus !== 200) continue;

      const getBody = await getResponse.text();
      let jsonData: Record<string, unknown>;
      try {
        jsonData = JSON.parse(getBody);
        // If response is an array (list endpoint), grab first item
        if (Array.isArray(jsonData)) {
          jsonData = jsonData[0] as Record<string, unknown> || {};
        }
        // If wrapped in { data: [...] }, unwrap
        if (jsonData.data && Array.isArray(jsonData.data)) {
          jsonData = (jsonData.data as Record<string, unknown>[])[0] || {};
        }
      } catch {
        continue; // Not JSON, skip
      }

      // Check if response contains manipulable fields
      const keys = Object.keys(jsonData);
      const manipulableFields = keys.filter((k) =>
        /^(price|cost|amount|total|quantity|qty|discount|subtotal)$/i.test(k),
      );

      if (manipulableFields.length === 0) continue;

      // Try PUT/PATCH with manipulated values
      for (const field of manipulableFields.slice(0, 3)) {
        for (const payload of API_MANIPULATION_PAYLOADS.filter((p) =>
          field.toLowerCase().includes(p.field) || p.field.includes(field.toLowerCase()),
        )) {
          const manipulatedBody = { ...jsonData, [field]: payload.value };
          const putPage = await context.newPage();
          try {
            const putResponse = await putPage.request.fetch(endpoint, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              data: JSON.stringify(manipulatedBody),
            });
            const putStatus = putResponse.status();
            const putBody = await putResponse.text();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'PUT',
              url: endpoint,
              responseStatus: putStatus,
              phase: 'active-business-logic-api-price',
            });

            if (putStatus >= 200 && putStatus < 300) {
              findings.push({
                id: randomUUID(),
                category: 'business-logic',
                severity: payload.severity,
                title: `API Price Manipulation — "${field}" set to ${payload.value}`,
                description: `The API endpoint ${endpoint} accepted a PUT request with "${field}" set to ${payload.value} and returned HTTP ${putStatus}. This may allow attackers to manipulate prices or quantities via the API.`,
                url: endpoint,
                evidence: `Endpoint: ${endpoint}\nField: ${field}\nOriginal value: ${String(jsonData[field])}\nManipulated value: ${payload.value}\nHTTP status: ${putStatus}\nResponse snippet: ${putBody.slice(0, 200)}`,
                request: { method: 'PUT', url: endpoint, body: JSON.stringify({ [field]: payload.value }) },
                response: { status: putStatus, bodySnippet: putBody.slice(0, 200) },
                timestamp: new Date().toISOString(),
                confidence: 'medium',
              });
              break; // One finding per field
            }
          } catch (err) {
            log.debug(`Business logic API test: ${(err as Error).message}`);
          } finally {
            await putPage.close();
          }
          await delay(config.requestDelay);
        }
      }
    } catch (err) {
      log.debug(`Business logic API discovery: ${(err as Error).message}`);
    } finally {
      await page.close();
    }
    await delay(config.requestDelay);
  }

  return findings;
}

async function testWorkflowBypass(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const originalUrl of urls) {
    const stepInfo = extractStepParam(originalUrl);
    if (!stepInfo) continue;

    // Try jumping to a high step number (final step)
    const finalSteps = ['99', '999', 'final', 'complete', 'confirm'];

    for (const finalStep of finalSteps) {
      const testUrl = new URL(originalUrl);
      testUrl.searchParams.set(stepInfo.param, finalStep);

      const page = await context.newPage();
      try {
        const response = await page.request.fetch(testUrl.href);
        const status = response.status();
        const body = await response.text();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: testUrl.href,
          responseStatus: status,
          phase: 'active-business-logic-step-bypass',
        });

        if (status === 200) {
          findings.push({
            id: randomUUID(),
            category: 'business-logic',
            severity: 'medium',
            title: `Workflow Step Bypass — "${stepInfo.param}" jumped to "${finalStep}"`,
            description: `The URL ${originalUrl} allows skipping workflow steps. Setting "${stepInfo.param}" from "${stepInfo.value}" to "${finalStep}" returned HTTP 200, suggesting the server does not enforce sequential step completion.`,
            url: originalUrl,
            evidence: `Original: ${originalUrl}\nBypass URL: ${testUrl.href}\nParameter: ${stepInfo.param}\nOriginal value: ${stepInfo.value}\nInjected value: ${finalStep}\nHTTP status: ${status}\nResponse snippet: ${body.slice(0, 200)}`,
            request: { method: 'GET', url: testUrl.href },
            response: { status, bodySnippet: body.slice(0, 200) },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          });
          // One finding per URL is enough
          break;
        }
      } catch (err) {
        log.debug(`Business logic step bypass test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

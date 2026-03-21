import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/**
 * Content-Type Confusion check (CWE-436).
 *
 * Tests whether endpoints accept unexpected Content-Type headers,
 * which can bypass CSRF token validation, WAF rules, and framework
 * security middleware that only checks specific content types.
 *
 * Attack scenario: A CSRF token check only validates
 * application/x-www-form-urlencoded requests. An attacker submits
 * a cross-origin POST with Content-Type: text/plain (allowed by
 * browser without preflight) — the server processes the body but
 * never validates the missing CSRF token.
 */

/** Content types to test, in order of exploitation likelihood */
const PROBE_CONTENT_TYPES = [
  // text/plain: browsers send without CORS preflight → direct CSRF bypass
  { type: 'text/plain', bypassesPreflight: true, severity: 'high' as const },
  // application/json on form endpoint: may skip form-specific CSRF checks
  { type: 'application/json', bypassesPreflight: false, severity: 'medium' as const },
  // application/xml: may trigger XXE processing in endpoints not expecting XML
  { type: 'application/xml', bypassesPreflight: false, severity: 'medium' as const },
  // multipart/form-data without actual boundary: some parsers silently accept
  { type: 'multipart/form-data; boundary=----', bypassesPreflight: true, severity: 'medium' as const },
] as const;

/** Endpoints likely to be state-changing (worth testing for CSRF bypass) */
const STATE_CHANGING_RE = /\/(login|signup|register|checkout|transfer|payment|settings|profile|password|delete|update|create|submit|feedback|contact|comment|review|order|cart|subscribe|send|confirm|approve|reject|cancel|publish|upload|invite|reset|change|save|edit|modify|add|remove|unsubscribe)/i;

/** Build a request body in the expected format for a given content type */
function buildBody(contentType: string, formData: Record<string, string>): string {
  if (contentType.startsWith('application/json')) {
    return JSON.stringify(formData);
  }
  if (contentType.startsWith('application/xml')) {
    const fields = Object.entries(formData)
      .map(([k, v]) => `<${k}>${v}</${k}>`)
      .join('');
    return `<?xml version="1.0"?><root>${fields}</root>`;
  }
  // For text/plain and multipart: send as url-encoded (simulates browser behavior)
  return new URLSearchParams(formData).toString();
}

/** Extract form fields as key-value pairs for baseline and probe requests */
function extractFormData(form: FormInfo): Record<string, string> {
  const data: Record<string, string> = {};
  for (const input of form.inputs) {
    if (!input.name) continue;
    if (input.type === 'hidden' || input.type === 'submit') continue;
    data[input.name] = input.value || 'test';
  }
  return data;
}

/** Detect if a response indicates the server processed the request (vs rejected) */
function isProcessedResponse(status: number, _body: string, baselineStatus: number): boolean {
  // If baseline itself was rejected (4xx/5xx), we can't meaningfully compare — skip
  if (baselineStatus >= 400) return false;
  // 415 Unsupported Media Type = server correctly rejected
  if (status === 415) return false;
  // Server returned a success or redirect (processed the request)
  if (status >= 200 && status < 400) return true;
  return false;
}

/** Check if the baseline response has CSRF protection indicators */
function hasCSRFProtection(body: string, headers: Record<string, string>): boolean {
  // Check for CSRF token patterns in response
  const csrfPatterns = /csrf|xsrf|_token|authenticity_token|antiforgery|__RequestVerificationToken/i;
  if (csrfPatterns.test(body)) return true;
  // Check for SameSite=Strict on set-cookie
  const setCookie = headers['set-cookie'] ?? '';
  if (/samesite\s*=\s*strict/i.test(setCookie)) return true;
  return false;
}

export const contentTypeConfusionCheck: ActiveCheck = {
  name: 'content-type-confusion',
  category: 'csrf', // Content-type confusion is primarily a CSRF bypass vector
  parallel: false,

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    // Collect state-changing POST forms
    const stateChangingForms = targets.forms.filter((f) => {
      const method = (f.method ?? 'get').toLowerCase();
      if (method !== 'post' && method !== 'put' && method !== 'patch') return false;
      // Filter to state-changing endpoints
      return STATE_CHANGING_RE.test(f.action) || STATE_CHANGING_RE.test(f.pageUrl);
    });

    // Also test API endpoints that accept POST
    const apiEndpoints = targets.apiEndpoints
      .filter((u) => STATE_CHANGING_RE.test(u))
      .slice(0, 5);

    const testTargets: Array<{ url: string; formData: Record<string, string>; source: string }> = [];

    for (const form of stateChangingForms.slice(0, 5)) {
      const formData = extractFormData(form);
      if (Object.keys(formData).length === 0) continue;
      try {
        const actionUrl = new URL(form.action, form.pageUrl).href;
        testTargets.push({ url: actionUrl, formData, source: 'form' });
      } catch { continue; }
    }

    for (const url of apiEndpoints) {
      testTargets.push({ url, formData: { test: 'secbot-probe' }, source: 'api' });
    }

    if (testTargets.length === 0) {
      log.info('[content-type-confusion] No state-changing POST endpoints found');
      return findings;
    }

    log.info(`[content-type-confusion] Testing ${testTargets.length} endpoints with ${PROBE_CONTENT_TYPES.length} content types...`);

    const page = await context.newPage();
    try {
      for (const target of testTargets) {
        // Step 1: Send baseline request with standard content type
        let baselineStatus: number;
        let baselineBody: string;
        let baselineHeaders: Record<string, string>;
        try {
          const baselineResp = await page.request.post(target.url, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: new URLSearchParams(target.formData).toString(),
          });
          baselineStatus = baselineResp.status();
          baselineBody = await baselineResp.text();
          baselineHeaders = Object.fromEntries(
            Object.entries(baselineResp.headers()).map(([k, v]) => [k.toLowerCase(), v]),
          );
        } catch {
          continue; // Endpoint unreachable
        }

        const endpointHasCSRF = hasCSRFProtection(baselineBody, baselineHeaders);

        // Step 2: Test each alternate content type
        for (const probe of PROBE_CONTENT_TYPES) {
          try {
            const body = buildBody(probe.type, target.formData);
            const probeResp = await page.request.post(target.url, {
              headers: { 'Content-Type': probe.type },
              data: body,
            });
            const probeStatus = probeResp.status();
            const probeBody = await probeResp.text();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'POST',
              url: target.url,
              responseStatus: probeStatus,
              phase: 'active-content-type-confusion',
            });

            // Detection: endpoint accepted the unexpected content type
            if (!isProcessedResponse(probeStatus, probeBody, baselineStatus)) continue;

            // 415 Unsupported Media Type = server correctly rejected → not vulnerable
            if (probeStatus === 415) continue;

            // If the endpoint has CSRF protection and text/plain bypasses preflight,
            // this is a high-severity CSRF bypass
            const isCSRFBypass = probe.bypassesPreflight && endpointHasCSRF;
            // If the endpoint returned similar content to baseline, it processed the request
            const processed = Math.abs(baselineBody.length - probeBody.length) < baselineBody.length * 0.5
              || (probeStatus >= 200 && probeStatus < 300);

            if (!processed && !isCSRFBypass) continue;

            const severity = isCSRFBypass ? 'high' : probe.severity;
            const confidence = processed && isCSRFBypass ? 'high' : 'medium';

            findings.push({
              id: randomUUID(),
              category: 'csrf',
              severity,
              confidence,
              title: `Content-Type Confusion: ${probe.type} accepted on ${target.source} endpoint`,
              description: `Endpoint ${target.url} accepts Content-Type: ${probe.type} ` +
                `(baseline: application/x-www-form-urlencoded → ${baselineStatus}, ` +
                `probe: ${probe.type} → ${probeStatus}). ` +
                (isCSRFBypass
                  ? 'This bypasses CSRF token validation because browsers send text/plain without CORS preflight. '
                  : 'Server processes the request with an unexpected content type. ') +
                `CWE-436: Interpretation Conflict.`,
              url: target.url,
              timestamp: new Date().toISOString(),
              evidence: `POST ${target.url} with Content-Type: ${probe.type} returned ${probeStatus} ` +
                `(baseline ${baselineStatus} with application/x-www-form-urlencoded). ` +
                `Response size: baseline=${baselineBody.length}, probe=${probeBody.length}.`,
              evidencePack: {
                payloadUsed: `Content-Type: ${probe.type}`,
                detectionMethod: 'content-type-switch',
                httpExchange: {
                  request: {
                    method: 'POST',
                    url: target.url,
                    headers: { 'Content-Type': probe.type },
                    body: body.slice(0, 500),
                  },
                  response: {
                    status: probeStatus,
                    headers: Object.fromEntries(
                      Object.entries(probeResp.headers()).map(([k, v]) => [k.toLowerCase(), v]),
                    ),
                    body: probeBody.slice(0, 1000),
                  },
                },
                curlCommand: `curl -X POST '${target.url}' -H 'Content-Type: ${probe.type}' -d '${body.slice(0, 200).replace(/'/g, "\\'")}'`,
              },
            });

            // One finding per endpoint per content type is enough
            break;
          } catch {
            continue;
          }
        }
      }
    } finally {
      await page.close();
    }

    log.info(`[content-type-confusion] ${findings.length} findings`);
    return findings;
  },
};

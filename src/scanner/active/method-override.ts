import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/**
 * HTTP Method Override check (CWE-650).
 *
 * Tests whether endpoints honor method override headers/parameters,
 * which can bypass access controls that only check the actual HTTP method.
 *
 * Attack scenario: ACL allows POST /api/users but blocks DELETE /api/users.
 * Attacker sends POST /api/users with X-HTTP-Method-Override: DELETE,
 * and the framework routes it as a DELETE request, bypassing the ACL.
 *
 * Common in: Rails (_method param), Django, Spring, Express method-override.
 */

/** Override mechanisms to test */
const OVERRIDE_METHODS = [
  { header: 'X-HTTP-Method-Override', name: 'X-HTTP-Method-Override header' },
  { header: 'X-HTTP-Method', name: 'X-HTTP-Method header' },
  { header: 'X-Method-Override', name: 'X-Method-Override header' },
] as const;

/** Override via query/body parameter */
const PARAM_OVERRIDES = ['_method', 'method', '_httpmethod'] as const;

/** Dangerous methods to test for override acceptance */
const DANGEROUS_METHODS = ['DELETE', 'PUT', 'PATCH'] as const;

/** Endpoints worth testing (user data, admin, resource endpoints) */
const SENSITIVE_ENDPOINT_RE = /\/(user|profile|account|admin|settings|api|resource|item|record|entry|data|object|entity|member|session|token)\b/i;

/** Check if a response indicates the method override was accepted */
function isOverrideAccepted(
  baselineStatus: number,
  baselineBody: string,
  probeStatus: number,
  probeBody: string,
  method: string,
): boolean {
  // Server returned a different status (processed the override method)
  if (probeStatus !== baselineStatus) return true;
  // Body significantly different (server routed to a different handler)
  if (Math.abs(baselineBody.length - probeBody.length) > 50) {
    // Check it's not just a different error message of similar length
    if (probeBody !== baselineBody) return true;
  }
  // Method-specific indicators in response
  const methodLower = method.toLowerCase();
  if (probeBody.includes(`"method":"${methodLower}"`) || probeBody.includes(`"method":"${method}"`)) return true;
  // 405 Method Not Allowed with Allow header listing the override method = server recognized it
  if (probeStatus === 405 && probeBody.toLowerCase().includes(methodLower)) return true;
  return false;
}

export const methodOverrideCheck: ActiveCheck = {
  name: 'method-override',
  category: 'broken-access-control',
  parallel: false,

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    // Collect candidate endpoints: API endpoints + pages with sensitive paths
    const candidates = new Set<string>();
    for (const url of targets.apiEndpoints) {
      candidates.add(url.split('?')[0]);
    }
    for (const url of targets.pages) {
      if (SENSITIVE_ENDPOINT_RE.test(url)) {
        candidates.add(url.split('?')[0]);
      }
    }

    const testUrls = [...candidates].slice(0, 8);

    if (testUrls.length === 0) {
      log.info('[method-override] No candidate endpoints found');
      return findings;
    }

    log.info(`[method-override] Testing ${testUrls.length} endpoints for method override acceptance...`);

    const page = await context.newPage();
    try {
      for (const url of testUrls) {
        // Step 1: Baseline POST request
        let baselineStatus: number;
        let baselineBody: string;
        try {
          const baselineResp = await page.request.post(url, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: 'secbot=probe',
          });
          baselineStatus = baselineResp.status();
          baselineBody = await baselineResp.text();
        } catch {
          continue;
        }

        // Step 2: Test header-based overrides
        for (const override of OVERRIDE_METHODS) {
          for (const method of DANGEROUS_METHODS) {
            try {
              const probeResp = await page.request.post(url, {
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                  [override.header]: method,
                },
                data: 'secbot=probe',
              });
              const probeStatus = probeResp.status();
              const probeBody = await probeResp.text();

              requestLogger?.log({
                timestamp: new Date().toISOString(),
                method: 'POST',
                url,
                responseStatus: probeStatus,
                phase: 'active-method-override',
              });

              if (isOverrideAccepted(baselineStatus, baselineBody, probeStatus, probeBody, method)) {
                findings.push({
                  id: randomUUID(),
                  category: 'broken-access-control',
                  severity: method === 'DELETE' ? 'high' : 'medium',
                  confidence: 'medium',
                  title: `HTTP Method Override: ${override.name} accepted (${method})`,
                  timestamp: new Date().toISOString(),
                  description: `Endpoint ${url} honors the ${override.header}: ${method} header. ` +
                    `A POST request with this header is routed as a ${method} request. ` +
                    `This can bypass ACLs that only check the actual HTTP method. ` +
                    `Baseline POST → ${baselineStatus}, override ${method} → ${probeStatus}. ` +
                    `CWE-650: Trusting HTTP Permission Methods on the Server Side.`,
                  url,
                  evidence: `POST ${url} with ${override.header}: ${method} → ${probeStatus} ` +
                    `(baseline POST → ${baselineStatus}). Response size: ` +
                    `baseline=${baselineBody.length}, probe=${probeBody.length}.`,
                  evidencePack: {
                    payloadUsed: `${override.header}: ${method}`,
                    detectionMethod: 'method-override-header',
                    httpExchange: {
                      request: {
                        method: 'POST',
                        url,
                        headers: {
                          'Content-Type': 'application/x-www-form-urlencoded',
                          [override.header]: method,
                        },
                        body: 'secbot=probe',
                      },
                      response: {
                        status: probeStatus,
                        body: probeBody.slice(0, 1000),
                      },
                    },
                    curlCommand: `curl -X POST '${url}' -H '${override.header}: ${method}' -d 'secbot=probe'`,
                  },
                });
                // One finding per endpoint per header is enough
                break;
              }
            } catch {
              continue;
            }
          }
        }

        // Step 3: Test parameter-based overrides (_method=DELETE)
        for (const param of PARAM_OVERRIDES) {
          for (const method of DANGEROUS_METHODS) {
            try {
              const probeResp = await page.request.post(url, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: `secbot=probe&${param}=${method}`,
              });
              const probeStatus = probeResp.status();
              const probeBody = await probeResp.text();

              requestLogger?.log({
                timestamp: new Date().toISOString(),
                method: 'POST',
                url,
                responseStatus: probeStatus,
                phase: 'active-method-override',
              });

              if (isOverrideAccepted(baselineStatus, baselineBody, probeStatus, probeBody, method)) {
                findings.push({
                  id: randomUUID(),
                  category: 'broken-access-control',
                  severity: method === 'DELETE' ? 'high' : 'medium',
                  confidence: 'medium',
                  title: `HTTP Method Override: ${param} parameter accepted (${method})`,
                  timestamp: new Date().toISOString(),
                  description: `Endpoint ${url} honors the ${param}=${method} body parameter. ` +
                    `This is commonly used in Rails/Django/Laravel to tunnel HTTP methods ` +
                    `through POST requests. If the ACL checks the original method (POST) ` +
                    `but the framework routes based on ${param}, access controls are bypassed. ` +
                    `CWE-650: Trusting HTTP Permission Methods on the Server Side.`,
                  url,
                  evidence: `POST ${url} with body param ${param}=${method} → ${probeStatus} ` +
                    `(baseline POST → ${baselineStatus}).`,
                  evidencePack: {
                    payloadUsed: `${param}=${method}`,
                    detectionMethod: 'method-override-param',
                    httpExchange: {
                      request: {
                        method: 'POST',
                        url,
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `secbot=probe&${param}=${method}`,
                      },
                      response: {
                        status: probeStatus,
                        body: probeBody.slice(0, 1000),
                      },
                    },
                    curlCommand: `curl -X POST '${url}' -d 'secbot=probe&${param}=${method}'`,
                  },
                });
                break;
              }
            } catch {
              continue;
            }
          }
        }
      }
    } finally {
      await page.close();
    }

    log.info(`[method-override] ${findings.length} findings`);
    return findings;
  },
};

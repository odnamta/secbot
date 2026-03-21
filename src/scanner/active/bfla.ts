import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/**
 * Broken Function-Level Authorization (BFLA) check — CWE-285, OWASP API5:2023.
 *
 * Unlike the general access-control check (which probes hardcoded admin paths),
 * BFLA works by *inferring* admin/privileged API functions from discovered endpoints
 * and testing whether unauthenticated or low-privilege requests can reach them.
 *
 * Strategy:
 *   1. From discovered API endpoints, infer sibling admin functions
 *      (e.g., /api/users → /api/users/export, /api/admin/users, /api/users/bulk-delete)
 *   2. Probe for undocumented privileged operations on known resources
 *      (e.g., GET /api/orders → DELETE /api/orders/1, PUT /api/orders/1/status)
 *   3. Test privilege escalation parameters on existing endpoints
 *      (e.g., add ?role=admin, ?admin=true, ?is_staff=1 to existing API calls)
 */

/** Admin-function suffixes to append to discovered API base paths */
const ADMIN_FUNCTION_SUFFIXES = [
  '/admin', '/export', '/import', '/bulk-delete', '/bulk-update',
  '/config', '/settings', '/users', '/roles', '/permissions',
  '/debug', '/internal', '/stats', '/metrics', '/logs',
  '/backup', '/migrate', '/seed', '/reset', '/purge',
];

/** Admin-prefixed variants to try when we know the resource name */
const ADMIN_PREFIX_PATTERNS = [
  '/admin/{resource}',
  '/internal/{resource}',
  '/manage/{resource}',
  '/staff/{resource}',
  '/backoffice/{resource}',
];

/** Privilege escalation query parameters */
const PRIV_ESC_PARAMS: Array<{ key: string; value: string }> = [
  { key: 'role', value: 'admin' },
  { key: 'admin', value: 'true' },
  { key: 'is_admin', value: '1' },
  { key: 'is_staff', value: '1' },
  { key: 'access_level', value: 'admin' },
  { key: 'user_type', value: 'admin' },
  { key: 'privilege', value: 'admin' },
  { key: 'permissions', value: 'all' },
];

/** Dangerous HTTP methods to probe on discovered resource endpoints */
const DANGEROUS_METHODS = ['DELETE', 'PUT', 'PATCH'] as const;

/** Extract the API base path and resource name from a URL
 *  e.g., /api/v1/users/123 → { base: '/api/v1/users', resource: 'users', hasId: true }
 *  e.g., /api/orders → { base: '/api/orders', resource: 'orders', hasId: false }
 */
function parseApiEndpoint(url: string): { base: string; resource: string; hasId: boolean } | null {
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split('/').filter(Boolean);

    // Need at least 2 segments (e.g., api/users)
    if (segments.length < 2) return null;

    // Check if last segment is a numeric ID or UUID
    const lastSeg = segments[segments.length - 1];
    const hasId = /^\d+$/.test(lastSeg) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(lastSeg);

    const resourceSegments = hasId ? segments.slice(0, -1) : segments;
    const resource = resourceSegments[resourceSegments.length - 1];
    const base = '/' + resourceSegments.join('/');

    return { base, resource, hasId };
  } catch {
    return null;
  }
}

/** Check if a response indicates the endpoint exists and is functional (not 404/405) */
function isAccessible(status: number): boolean {
  return status >= 200 && status < 400;
}

/** Check if a response indicates the endpoint exists but is forbidden */
function isForbidden(status: number): boolean {
  return status === 401 || status === 403;
}

export const bflaCheck: ActiveCheck = {
  name: 'bfla',
  category: 'broken-access-control',
  parallel: false,

  async run(context, targets, config, requestLogger): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const origin = new URL(config.targetUrl).origin;
    const testedUrls = new Set<string>();

    // Parse all API endpoints to understand the API structure
    const parsedEndpoints = targets.apiEndpoints
      .map((ep) => ({ url: ep, ...parseApiEndpoint(ep) }))
      .filter((ep): ep is { url: string; base: string; resource: string; hasId: boolean } =>
        ep.base !== null);

    if (parsedEndpoints.length === 0) {
      log.info('BFLA: no API endpoints to test');
      return findings;
    }

    // Deduplicate by base path
    const uniqueBases = new Map<string, typeof parsedEndpoints[0]>();
    for (const ep of parsedEndpoints) {
      if (!uniqueBases.has(ep.base)) uniqueBases.set(ep.base, ep);
    }

    log.info(`BFLA: testing ${uniqueBases.size} unique API base paths for function-level auth bypass`);

    // Limit based on profile
    const maxBases = config.profile === 'quick' ? 3 : config.profile === 'deep' ? 15 : 8;
    const suffixLimit = config.profile === 'quick' ? 5 : config.profile === 'deep' ? ADMIN_FUNCTION_SUFFIXES.length : 10;
    const bases = [...uniqueBases.values()].slice(0, maxBases);

    // ─── Phase 1: Admin function enumeration ────────────────────────────
    // For each discovered API base path, probe for admin-only sibling functions
    for (const ep of bases) {
      const suffixes = ADMIN_FUNCTION_SUFFIXES.slice(0, suffixLimit);

      for (const suffix of suffixes) {
        const probeUrl = `${origin}${ep.base}${suffix}`;
        if (testedUrls.has(probeUrl)) continue;
        testedUrls.add(probeUrl);

        const page = await context.newPage();
        try {
          const resp = await page.request.fetch(probeUrl, {
            maxRedirects: 0,
            timeout: config.timeout,
          });
          const status = resp.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: probeUrl,
            responseStatus: status,
            phase: 'active-bfla-admin-enum',
          });

          if (isAccessible(status)) {
            const body = await resp.text();
            // Verify it's not an empty response or a generic error page
            if (body.length > 50) {
              const isJson = body.trimStart().startsWith('{') || body.trimStart().startsWith('[');
              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity: /delete|purge|reset|migrate|backup|debug|internal|admin/i.test(suffix) ? 'critical' : 'high',
                title: `BFLA: Undocumented Admin Function Accessible — ${ep.base}${suffix}`,
                description: `The admin/privileged function "${ep.base}${suffix}" is accessible without elevated authorization ` +
                  `(HTTP ${status}). This endpoint was discovered by probing sibling paths of "${ep.base}". ` +
                  `Admin functions should require explicit role-based authorization checks (CWE-285).`,
                url: probeUrl,
                evidence: [
                  `Discovered from: ${ep.url}`,
                  `Probe: GET ${ep.base}${suffix}`,
                  `Status: ${status}`,
                  `Response type: ${isJson ? 'JSON' : 'HTML/text'}`,
                  `Response length: ${body.length}`,
                  `Response snippet: ${body.slice(0, 300)}`,
                ].join('\n'),
                request: { method: 'GET', url: probeUrl },
                response: { status, bodySnippet: body.slice(0, 200) },
                timestamp: new Date().toISOString(),
                confidence: isJson ? 'high' : 'medium',
                evidencePack: { detectionMethod: 'endpoint-probe' },
              });
            }
          }
        } catch (err) {
          log.debug(`BFLA admin enum: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    // ─── Phase 2: Admin-prefixed resource variants ──────────────────────
    // If /api/users exists, try /admin/users, /internal/users, etc.
    for (const ep of bases.slice(0, 5)) {
      for (const pattern of ADMIN_PREFIX_PATTERNS) {
        const adminPath = pattern.replace('{resource}', ep.resource);
        // Skip if this would produce the same URL as the original
        if (adminPath === ep.base) continue;

        // Reconstruct: use origin + api version prefix (if any) + admin pattern
        const versionMatch = ep.base.match(/^(\/api\/v\d+)\//);
        const fullPath = versionMatch
          ? `${origin}${versionMatch[1]}${adminPath}`
          : `${origin}${adminPath}`;

        if (testedUrls.has(fullPath)) continue;
        testedUrls.add(fullPath);

        const page = await context.newPage();
        try {
          const resp = await page.request.fetch(fullPath, {
            maxRedirects: 0,
            timeout: config.timeout,
          });
          const status = resp.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: fullPath,
            responseStatus: status,
            phase: 'active-bfla-admin-prefix',
          });

          if (isAccessible(status)) {
            const body = await resp.text();
            if (body.length > 50) {
              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity: 'critical',
                title: `BFLA: Admin-Prefixed Endpoint Accessible — ${adminPath}`,
                description: `The admin-prefixed endpoint "${fullPath}" is accessible without authorization. ` +
                  `Discovered by applying admin prefix patterns to known resource "${ep.resource}". ` +
                  `This suggests the API has parallel admin routes without proper function-level authorization (CWE-285).`,
                url: fullPath,
                evidence: [
                  `Base resource: ${ep.url}`,
                  `Admin variant: ${adminPath}`,
                  `Status: ${status}`,
                  `Response length: ${body.length}`,
                  `Response snippet: ${body.slice(0, 300)}`,
                ].join('\n'),
                request: { method: 'GET', url: fullPath },
                response: { status, bodySnippet: body.slice(0, 200) },
                timestamp: new Date().toISOString(),
                confidence: 'high',
                evidencePack: { detectionMethod: 'endpoint-probe' },
              });
              break; // One admin prefix finding per resource is enough
            }
          }
        } catch (err) {
          log.debug(`BFLA admin prefix: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    // ─── Phase 3: Dangerous method probing on known resources ───────────
    // If GET /api/users/123 works, try DELETE /api/users/123, PUT /api/users/123
    if (config.profile !== 'quick') {
      const resourceEndpoints = parsedEndpoints.filter((ep) => ep.hasId).slice(0, 5);

      for (const ep of resourceEndpoints) {
        for (const method of DANGEROUS_METHODS) {
          const page = await context.newPage();
          try {
            // Use a safe probe: send request without body, check if the method is accepted
            // A real DELETE/PUT would be destructive, so we just check the status code
            const resp = await page.request.fetch(ep.url, {
              method,
              maxRedirects: 0,
              timeout: config.timeout,
              // Send empty body for PUT/PATCH to avoid modifying data
              ...(method !== 'DELETE' ? { data: '' } : {}),
            });
            const status = resp.status();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method,
              url: ep.url,
              responseStatus: status,
              phase: 'active-bfla-method-probe',
            });

            // If the method is accepted (not 405 Method Not Allowed, not 401/403)
            // and the endpoint responds successfully, this may indicate missing function-level auth
            if (isAccessible(status) && status !== 301 && status !== 302) {
              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity: method === 'DELETE' ? 'critical' : 'high',
                title: `BFLA: ${method} Method Accepted on Resource — ${new URL(ep.url).pathname}`,
                description: `The API endpoint "${new URL(ep.url).pathname}" accepts ${method} requests without explicit ` +
                  `authorization checks (HTTP ${status}). If this is a read-only resource for the current user, ` +
                  `${method} should be restricted to authorized roles only (CWE-285).`,
                url: ep.url,
                evidence: [
                  `Endpoint: ${ep.url}`,
                  `Method: ${method}`,
                  `Status: ${status}`,
                  `Expected: 401/403/405 for unprivileged access`,
                ].join('\n'),
                request: { method, url: ep.url },
                response: { status, bodySnippet: '' },
                timestamp: new Date().toISOString(),
                confidence: 'medium',
                evidencePack: { detectionMethod: 'method-probe' },
              });
              break; // One method finding per endpoint
            }
          } catch (err) {
            log.debug(`BFLA method probe: ${(err as Error).message}`);
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }
      }
    }

    // ─── Phase 4: Privilege escalation parameters ───────────────────────
    // Add ?role=admin, ?admin=true etc. to existing API endpoints
    if (config.profile === 'deep') {
      for (const ep of parsedEndpoints.slice(0, 5)) {
        for (const param of PRIV_ESC_PARAMS.slice(0, 5)) {
          const page = await context.newPage();
          try {
            const probeUrl = new URL(ep.url);
            probeUrl.searchParams.set(param.key, param.value);
            const fullUrl = probeUrl.toString();

            if (testedUrls.has(fullUrl)) continue;
            testedUrls.add(fullUrl);

            // Get baseline without the param
            const baseResp = await page.request.fetch(ep.url, {
              maxRedirects: 0,
              timeout: config.timeout,
            });
            const baseBody = await baseResp.text();
            const baseStatus = baseResp.status();

            // Now with the priv-esc param
            const privResp = await page.request.fetch(fullUrl, {
              maxRedirects: 0,
              timeout: config.timeout,
            });
            const privBody = await privResp.text();
            const privStatus = privResp.status();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: fullUrl,
              responseStatus: privStatus,
              phase: 'active-bfla-priv-esc',
            });

            // If adding the admin param changes the response significantly, it may be honored
            if (
              privStatus >= 200 && privStatus < 300 &&
              baseStatus >= 200 && baseStatus < 300 &&
              privBody.length > baseBody.length * 1.3 && // 30% more content
              privBody.length > 100
            ) {
              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity: 'high',
                title: `BFLA: Privilege Escalation via ${param.key}=${param.value} — ${new URL(ep.url).pathname}`,
                description: `Adding "${param.key}=${param.value}" to the API endpoint "${new URL(ep.url).pathname}" ` +
                  `returned significantly more data (${baseBody.length} → ${privBody.length} bytes). ` +
                  `The server may be honoring client-supplied privilege parameters (CWE-285).`,
                url: fullUrl,
                evidence: [
                  `Baseline: ${ep.url} (${baseBody.length} bytes)`,
                  `With param: ${fullUrl} (${privBody.length} bytes)`,
                  `Size increase: ${((privBody.length / baseBody.length - 1) * 100).toFixed(0)}%`,
                  `Parameter: ${param.key}=${param.value}`,
                ].join('\n'),
                request: { method: 'GET', url: fullUrl },
                response: { status: privStatus, bodySnippet: privBody.slice(0, 200) },
                timestamp: new Date().toISOString(),
                confidence: 'medium',
                evidencePack: { detectionMethod: 'parameter-injection' },
              });
              break; // One priv-esc finding per endpoint
            }
          } catch (err) {
            log.debug(`BFLA priv esc: ${(err as Error).message}`);
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }
      }
    }

    log.info(`BFLA: ${findings.length} finding(s)`);
    return findings;
  },
};

import { randomUUID } from 'node:crypto';
import { chromium, type BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/** URL patterns that suggest admin/privileged endpoints */
const ADMIN_URL_PATTERNS = /\/(admin|dashboard|manage|settings|config|users|roles|permissions|billing|internal|staff|moderate|review|reports|analytics|system|control|panel)/i;

/** HTTP methods to test for method override bypass */
const OVERRIDE_METHODS = ['PUT', 'DELETE', 'PATCH'] as const;

/** Headers used to bypass URL-based access control */
const BYPASS_HEADERS: Array<{ name: string; value: string }> = [
  { name: 'X-Original-URL', value: '' },  // value set per-request
  { name: 'X-Rewrite-URL', value: '' },
  { name: 'X-Forwarded-For', value: '127.0.0.1' },
  { name: 'X-Custom-IP-Authorization', value: '127.0.0.1' },
];

/** Detect if a response indicates successful access (not blocked) */
function isSuccessResponse(status: number): boolean {
  return status >= 200 && status < 400;
}

/** Detect if a response indicates access denied */
function isDeniedResponse(status: number): boolean {
  return status === 401 || status === 403;
}

/** Extract admin-only endpoints from crawl — pages that require elevated privileges */
export function identifyPrivilegedEndpoints(pages: string[]): string[] {
  return pages.filter((url) => {
    try {
      const parsed = new URL(url);
      return ADMIN_URL_PATTERNS.test(parsed.pathname);
    } catch {
      return false;
    }
  });
}

export const accessControlCheck: ActiveCheck = {
  name: 'access-control',
  category: 'broken-access-control',
  async run(context, targets, config, requestLogger) {
    // Broken access control requires two different auth sessions
    if (!config.authStorageState) {
      log.info('Access control check skipped: no --auth provided (requires authentication)');
      return [];
    }
    if (!config.idorAltAuthState) {
      log.info('Access control check skipped: no --idor-alt-auth provided. Provide a regular user auth state via --idor-alt-auth to test if admin endpoints are accessible by regular users.');
      return [];
    }

    const findings: RawFinding[] = [];

    // Identify admin/privileged endpoints from crawl
    const allUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])];
    const privilegedEndpoints = identifyPrivilegedEndpoints(allUrls);

    if (privilegedEndpoints.length === 0) {
      log.info('Access control check: no privileged endpoints detected');
      return [];
    }

    log.info(`Testing ${privilegedEndpoints.length} privileged endpoints for broken access control...`);

    // Phase 1: Test if admin endpoints are accessible as regular user
    // The primary auth (--auth) is the admin, --idor-alt-auth is the regular user
    let altContext: BrowserContext | undefined;
    try {
      const browser = chromium.connect
        ? context.browser()!
        : await chromium.launch({ headless: true });
      altContext = await browser.newContext({
        storageState: config.idorAltAuthState,
      });

      for (const endpoint of privilegedEndpoints) {
        const page = await altContext.newPage();
        try {
          const response = await page.request.fetch(endpoint);
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: endpoint,
            responseStatus: status,
            phase: 'active-access-control',
          });

          if (isSuccessResponse(status)) {
            // Regular user can access admin endpoint — broken access control
            const body = await response.text();
            findings.push({
              id: randomUUID(),
              category: 'broken-access-control',
              severity: 'critical',
              title: `Broken Access Control: Admin Endpoint Accessible by Regular User`,
              description: `The privileged endpoint "${endpoint}" is accessible with regular user credentials. This allows unauthorized access to admin functionality. The response status was ${status}.`,
              url: endpoint,
              evidence: `Endpoint: ${endpoint}\nAccess as regular user: ${status} (should be 401/403)\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method: 'GET', url: endpoint },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
          }
        } catch (err) {
          log.debug(`Access control test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    } finally {
      if (altContext) {
        await altContext.close();
      }
    }

    // Phase 2: Test HTTP method override on protected endpoints
    // Use the regular user context to test if method changes bypass auth
    for (const endpoint of privilegedEndpoints.slice(0, 5)) {
      for (const method of OVERRIDE_METHODS) {
        const page = await context.newPage();
        try {
          const response = await page.request.fetch(endpoint, { method });
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method,
            url: endpoint,
            responseStatus: status,
            phase: 'active-access-control-method',
          });

          // If a different method succeeds where GET might have been blocked
          if (isSuccessResponse(status)) {
            const body = await response.text();
            findings.push({
              id: randomUUID(),
              category: 'broken-access-control',
              severity: 'high',
              title: `HTTP Method Override Bypass on "${new URL(endpoint).pathname}"`,
              description: `The endpoint "${endpoint}" responds to ${method} requests with status ${status}. HTTP method override may bypass access controls that only check GET/POST.`,
              url: endpoint,
              evidence: `Method: ${method}\nStatus: ${status}\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method, url: endpoint },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
              confidence: 'medium',
            });
            break; // One finding per endpoint is enough
          }
        } catch (err) {
          log.debug(`Method override test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    // Phase 3: Header-based bypass (X-Original-URL, X-Forwarded-For)
    for (const endpoint of privilegedEndpoints.slice(0, 3)) {
      const parsed = new URL(endpoint);

      for (const header of BYPASS_HEADERS) {
        const page = await context.newPage();
        try {
          const headerValue = header.name.includes('URL') ? parsed.pathname : header.value;
          const baseUrl = header.name.includes('URL') ? `${parsed.origin}/` : endpoint;

          const response = await page.request.fetch(baseUrl, {
            headers: { [header.name]: headerValue },
          });
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: baseUrl,
            responseStatus: status,
            phase: 'active-access-control-header',
          });

          if (isSuccessResponse(status)) {
            const body = await response.text();
            // Check if the response contains admin-related content
            if (ADMIN_URL_PATTERNS.test(body) || body.length > 500) {
              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity: 'high',
                title: `Header-Based Access Control Bypass via ${header.name}`,
                description: `Access controls on "${endpoint}" can be bypassed using the "${header.name}" header. The server processed the request and returned admin content.`,
                url: endpoint,
                evidence: `Header: ${header.name}: ${headerValue}\nStatus: ${status}\nResponse length: ${body.length}\nResponse snippet: ${body.slice(0, 300)}`,
                request: { method: 'GET', url: baseUrl },
                response: { status, bodySnippet: body.slice(0, 200) },
                timestamp: new Date().toISOString(),
                confidence: 'medium',
              });
              break;
            }
          }
        } catch (err) {
          log.debug(`Header bypass test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    log.info(`Access control check: ${findings.length} finding(s)`);
    return findings;
  },
};

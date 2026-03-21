import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, CrawledPage } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';

/** File extensions that are typically static assets (CDN-served) */
const STATIC_ASSET_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp|avif)(\?|$)/i;

/** Check if Set-Cookie headers all have SameSite=Lax or Strict (mitigates CORS credential theft) */
function hasSameSiteProtection(headers: Record<string, string>): boolean {
  // Collect all set-cookie values — Playwright merges multiple Set-Cookie into one string separated by \n
  const setCookieRaw = headers['set-cookie'];
  if (!setCookieRaw) return false; // No cookies = no mitigation (but also no theft vector)

  const setCookies = setCookieRaw.split('\n').filter(Boolean);
  if (setCookies.length === 0) return false;

  // Check if ALL cookies have SameSite=Lax or SameSite=Strict
  return setCookies.every(cookie => {
    const sameSiteMatch = /samesite\s*=\s*(lax|strict|none)/i.exec(cookie);
    if (!sameSiteMatch) return false; // No explicit SameSite — treat as unprotected (older browsers don't default to Lax)
    const value = sameSiteMatch[1].toLowerCase();
    return value === 'lax' || value === 'strict';
  });
}

/** Check if a URL is likely an API endpoint vs a static asset */
function isApiEndpoint(url: string, contentType?: string): boolean {
  // Static asset by extension — not an API endpoint
  if (STATIC_ASSET_RE.test(url)) return false;
  // Contains /api/ in path
  if (/\/api\//i.test(url)) return true;
  // Returns JSON content type
  if (contentType && contentType.includes('application/json')) return true;
  // Default: treat as potentially interesting (non-static page)
  return true;
}

export const corsCheck: ActiveCheck = {
  parallel: true,
  name: 'cors',
  category: 'cors-misconfiguration',
  async run(context, targets, config, requestLogger) {
    // Test all unique URLs — API endpoints plus all pages
    // The per-origin limit (10 URLs) in testCorsMisconfiguration prevents over-testing
    const testUrls = [...new Set([...targets.apiEndpoints, ...targets.pages])];
    log.info(`Testing CORS configuration on ${testUrls.length} URLs...`);
    return testCorsMisconfiguration(context, testUrls, config, requestLogger);
  },
};

async function testCorsMisconfiguration(
  context: BrowserContext,
  pageUrls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const evilOrigin = 'https://evil.example.com';

  // Get unique origins and test a few URLs from each
  const byOrigin = new Map<string, string[]>();
  for (const url of pageUrls) {
    try {
      const origin = new URL(url).origin;
      const existing = byOrigin.get(origin) ?? [];
      existing.push(url);
      byOrigin.set(origin, existing);
    } catch {
      // Skip invalid URLs
    }
  }

  for (const [, urls] of byOrigin) {
    // Test up to 25 URLs per origin — CORS misconfigs are often on specific endpoints
    const testUrls = urls.slice(0, 25);

    for (const url of testUrls) {
      const page = await context.newPage();
      try {
        // Test 1: Simple request with evil Origin
        const response = await page.request.fetch(url, {
          headers: { Origin: evilOrigin },
        });

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url,
          headers: { Origin: evilOrigin },
          responseStatus: response.status(),
          phase: 'active-cors',
        });

        const acao = response.headers()['access-control-allow-origin'];
        const acac = response.headers()['access-control-allow-credentials'];
        const contentType = response.headers()['content-type'] ?? '';

        // Only flag wildcard ACAO on API endpoints, not static assets
        // Downgrade severity for non-functional endpoints (4xx/5xx responses)
        // A reflected origin on a 405/404/500 is less exploitable than on a 200
        const statusCode = response.status();
        const isNonFunctional = statusCode >= 400;
        const sameSiteProtected = hasSameSiteProtection(response.headers());
        const contentLength = response.headers()['content-length'];
        const isEmptyResponse = contentLength === '0';
        const mitigationNotes: string[] = [];
        if (isNonFunctional) mitigationNotes.push(`Endpoint returned HTTP ${statusCode}, which may limit exploitability.`);
        if (sameSiteProtected) mitigationNotes.push('All cookies use SameSite=Lax or Strict, preventing cross-origin cookie attachment via fetch/XHR.');
        if (isEmptyResponse) mitigationNotes.push('Response body is empty (Content-Length: 0), so no data can be stolen.');
        const mitigationSuffix = mitigationNotes.length > 0 ? ` Note: ${mitigationNotes.join(' ')}` : '';

        // Count active mitigations for severity downgrade decisions
        const hasMitigations = sameSiteProtected || isEmptyResponse || isNonFunctional;

        if (acao === '*' && acac === 'true') {
          // Wildcard + credentials — downgrade if any mitigation present
          const severity = hasMitigations ? 'medium' as const : 'high' as const;
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity,
            title: 'CORS Wildcard with Credentials',
            description:
              'The server allows any origin with credentials, enabling cross-site data theft.' + mitigationSuffix,
            url,
            evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
            response: {
              status: statusCode,
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
            confidence: hasMitigations ? 'low' : 'low',
          });
        } else if (acao === '*' && !isApiEndpoint(url, contentType)) {
          // Wildcard on static assets is normal — skip
          log.debug(`CORS wildcard on static asset, skipping: ${url}`);
        } else if (acao === evilOrigin) {
          // With credentials: critical (downgraded if any mitigation present)
          // Without credentials: high (downgraded to medium if mitigated)
          let severity: 'critical' | 'high' | 'medium';
          if (acac === 'true') {
            if (sameSiteProtected || isEmptyResponse) severity = 'medium';
            else if (isNonFunctional) severity = 'high';
            else severity = 'critical';
          } else {
            severity = hasMitigations ? 'medium' : 'high';
          }
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity,
            title: acac === 'true'
              ? 'CORS Reflects Origin with Credentials'
              : 'CORS Reflects Arbitrary Origin',
            description: (acac === 'true'
              ? 'The server reflects the Origin header with credentials allowed. This is the most dangerous CORS misconfiguration, enabling full cross-site data theft with authentication.'
              : 'The server reflects the Origin header in Access-Control-Allow-Origin, allowing any site to read responses.') + mitigationSuffix,
            url,
            evidence: `Origin: ${evilOrigin}\nAccess-Control-Allow-Origin: ${acao}${acac === 'true' ? '\nAccess-Control-Allow-Credentials: true' : ''}`,
            response: {
              status: statusCode,
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
            confidence: (sameSiteProtected || isEmptyResponse) ? 'low' : (isNonFunctional ? 'low' : (acac === 'true' ? 'high' : 'medium')),
          });
        } else if (acao === 'null') {
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity: 'medium',
            title: 'CORS Allows Null Origin',
            description:
              'The server allows the "null" origin, which can be exploited via sandboxed iframes.',
            url,
            evidence: `Access-Control-Allow-Origin: null`,
            response: {
              status: response.status(),
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
            confidence: 'medium',
          });
        }

        // Test 2: Subdomain prefix/suffix bypass
        // Many CORS implementations use regex like /\.example\.com$/ but forget to anchor,
        // allowing evilexample.com, example.com.evil.com, or evil.example.com
        if (!findings.some((f) => f.url === url)) {
          const targetOrigin = new URL(url).origin;
          const targetHost = new URL(url).hostname;
          const bypassOrigins = [
            `https://evil${targetHost}`,           // Prefix bypass: evilexample.com
            `https://${targetHost}.evil.com`,       // Suffix bypass: example.com.evil.com
            `https://subdomain.${targetHost}`,      // Subdomain: may be overly trusted
          ];

          for (const bypassOrigin of bypassOrigins) {
            if (bypassOrigin === targetOrigin) continue; // Skip if it matches the actual origin
            try {
              const bypassResponse = await page.request.fetch(url, {
                headers: { Origin: bypassOrigin },
              });

              requestLogger?.log({
                timestamp: new Date().toISOString(),
                method: 'GET',
                url,
                headers: { Origin: bypassOrigin },
                responseStatus: bypassResponse.status(),
                phase: 'active-cors-bypass',
              });

              const bypassAcao = bypassResponse.headers()['access-control-allow-origin'];
              const bypassAcac = bypassResponse.headers()['access-control-allow-credentials'];

              if (bypassAcao === bypassOrigin) {
                const bypassType = bypassOrigin.startsWith(`https://evil${targetHost}`)
                  ? 'prefix' : bypassOrigin.endsWith('.evil.com') ? 'suffix' : 'subdomain';
                findings.push({
                  id: randomUUID(),
                  category: 'cors-misconfiguration',
                  severity: bypassAcac === 'true' ? 'critical' : 'high',
                  title: `CORS Origin Validation Bypass (${bypassType})`,
                  description: `The server CORS validation can be bypassed using a ${bypassType}-based origin (${bypassOrigin}). The regex/string matching is not properly anchored, allowing attacker-controlled domains to read authenticated responses.${bypassAcac === 'true' ? ' Credentials are allowed, making this fully exploitable for cross-site data theft.' : ''}`,
                  url,
                  evidence: `Bypass origin: ${bypassOrigin}\nAccess-Control-Allow-Origin: ${bypassAcao}${bypassAcac === 'true' ? '\nAccess-Control-Allow-Credentials: true' : ''}`,
                  response: {
                    status: bypassResponse.status(),
                    headers: bypassResponse.headers(),
                  },
                  timestamp: new Date().toISOString(),
                  confidence: 'high',
                });
                break; // One bypass finding per URL is enough
              }
            } catch {
              // Bypass test may fail
            }
          }
        }

        // Test 3: Send Origin: null actively
        try {
          const nullResponse = await page.request.fetch(url, {
            headers: { Origin: 'null' },
          });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url,
            headers: { Origin: 'null' },
            responseStatus: nullResponse.status(),
            phase: 'active-cors',
          });

          const nullAcao = nullResponse.headers()['access-control-allow-origin'];
          const nullAcac = nullResponse.headers()['access-control-allow-credentials'];

          if (nullAcao === 'null' && !findings.some((f) => f.url === url && f.title.includes('Null Origin'))) {
            findings.push({
              id: randomUUID(),
              category: 'cors-misconfiguration',
              severity: nullAcac === 'true' ? 'high' : 'medium',
              title: 'CORS Allows Null Origin',
              description:
                'The server reflects Origin: null in Access-Control-Allow-Origin. This can be exploited via sandboxed iframes or data: URIs to bypass CORS controls.',
              url,
              evidence: `Origin: null\nAccess-Control-Allow-Origin: null${nullAcac === 'true' ? '\nAccess-Control-Allow-Credentials: true' : ''}`,
              response: {
                status: nullResponse.status(),
                headers: nullResponse.headers(),
              },
              timestamp: new Date().toISOString(),
              confidence: 'medium',
            });
          }
        } catch {
          // Origin: null test may fail
        }

        // Test 4: OPTIONS preflight to check CORS policy enforcement
        try {
          const preflight = await page.request.fetch(url, {
            method: 'OPTIONS',
            headers: {
              Origin: evilOrigin,
              'Access-Control-Request-Method': 'POST',
              'Access-Control-Request-Headers': 'Content-Type, Authorization',
            },
          });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'OPTIONS',
            url,
            headers: { Origin: evilOrigin, 'Access-Control-Request-Method': 'POST' },
            responseStatus: preflight.status(),
            phase: 'active-cors',
          });

          const preflightAcao = preflight.headers()['access-control-allow-origin'];
          const allowMethods = preflight.headers()['access-control-allow-methods'];
          const preflightAcac = preflight.headers()['access-control-allow-credentials'];

          // Overly permissive preflight — only exploitable with credentials
          // ACAO: * without credentials is safe per browser spec (cookies not sent)
          if (preflightAcao === '*' || preflightAcao === evilOrigin) {
            if (allowMethods?.includes('*') || (allowMethods?.includes('DELETE') && allowMethods?.includes('PUT'))) {
              const hasCredentials = preflightAcac === 'true';
              // Wildcard without credentials is not exploitable — browsers block credentialed
              // cross-origin requests when ACAO is *. Only flag when credentials are present
              // or when origin is reflected (not wildcard).
              if (hasCredentials || preflightAcao === evilOrigin) {
                findings.push({
                  id: randomUUID(),
                  category: 'cors-misconfiguration',
                  severity: hasCredentials ? 'high' : 'medium',
                  title: hasCredentials
                    ? 'CORS Preflight Allows Dangerous Methods with Credentials'
                    : 'CORS Preflight Reflects Origin with Dangerous Methods',
                  description: hasCredentials
                    ? 'The server CORS preflight allows arbitrary origins with credentials and dangerous HTTP methods (DELETE, PUT). This enables authenticated cross-site state-changing requests.'
                    : 'The server reflects the Origin header in preflight with dangerous HTTP methods. Without credentials, the impact is limited to reading responses from the attacker\'s own requests.',
                  url,
                  evidence: `Origin: ${evilOrigin}\nAccess-Control-Allow-Origin: ${preflightAcao}\nAccess-Control-Allow-Methods: ${allowMethods}${hasCredentials ? '\nAccess-Control-Allow-Credentials: true' : ''}`,
                  response: {
                    status: preflight.status(),
                    headers: preflight.headers(),
                  },
                  timestamp: new Date().toISOString(),
                  confidence: hasCredentials ? 'high' : 'medium',
                });
              } else {
                log.debug(`CORS preflight: ${url} allows * with methods but no credentials — safe per spec`);
              }
            }
          }
        } catch {
          // OPTIONS preflight may not be supported
        }
      } catch {
        // Continue
      } finally {
        await page.close();
      }
    }
  }

  return findings;
}

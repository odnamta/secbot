import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, CrawledPage } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';

export const corsCheck: ActiveCheck = {
  name: 'cors',
  category: 'cors-misconfiguration',
  async run(context, targets, config, requestLogger) {
    // Prioritize API endpoints, fall back to regular pages
    const testUrls = targets.apiEndpoints.length > 0
      ? [...targets.apiEndpoints, ...targets.pages.slice(0, 2)]
      : targets.pages;
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
    const testUrls = urls.slice(0, 3);

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

        if (acao === '*' && acac === 'true') {
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity: 'high',
            title: 'CORS Wildcard with Credentials',
            description:
              'The server allows any origin with credentials, enabling cross-site data theft.',
            url,
            evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
            response: {
              status: response.status(),
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
          });
        } else if (acao === evilOrigin) {
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity: 'high',
            title: 'CORS Reflects Arbitrary Origin',
            description:
              'The server reflects the Origin header in Access-Control-Allow-Origin, allowing any site to read responses.',
            url,
            evidence: `Origin: ${evilOrigin}\nAccess-Control-Allow-Origin: ${acao}`,
            response: {
              status: response.status(),
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
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
          });
        }

        // Test 2: OPTIONS preflight to check CORS policy enforcement
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
          const allowHeaders = preflight.headers()['access-control-allow-headers'];

          // Overly permissive preflight
          if (preflightAcao === '*' || preflightAcao === evilOrigin) {
            if (allowMethods?.includes('*') || (allowMethods?.includes('DELETE') && allowMethods?.includes('PUT'))) {
              findings.push({
                id: randomUUID(),
                category: 'cors-misconfiguration',
                severity: 'high',
                title: 'CORS Preflight Allows Dangerous Methods',
                description:
                  'The server CORS preflight response allows arbitrary origins with dangerous HTTP methods (DELETE, PUT). This enables cross-site state-changing requests.',
                url,
                evidence: `Origin: ${evilOrigin}\nAccess-Control-Allow-Origin: ${preflightAcao}\nAccess-Control-Allow-Methods: ${allowMethods}`,
                response: {
                  status: preflight.status(),
                  headers: preflight.headers(),
                },
                timestamp: new Date().toISOString(),
              });
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

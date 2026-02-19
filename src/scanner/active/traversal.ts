import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { TRAVERSAL_PAYLOADS, TRAVERSAL_SUCCESS_PATTERNS } from '../../config/payloads/traversal.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';

export const traversalCheck: ActiveCheck = {
  name: 'traversal',
  category: 'directory-traversal',
  async run(context, targets, config, requestLogger) {
    if (targets.apiEndpoints.length === 0) return [];

    log.info(`Testing ${targets.apiEndpoints.length} API endpoints for directory traversal...`);
    return testDirectoryTraversal(context, targets.apiEndpoints, config, requestLogger);
  },
};

async function testDirectoryTraversal(
  context: BrowserContext,
  apiEndpoints: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const endpoint of apiEndpoints) {
    for (const payload of TRAVERSAL_PAYLOADS.slice(0, 2)) {
      const testUrl = endpoint.replace(/\/[^/]*$/, `/${payload}`);

      const page = await context.newPage();
      try {
        const response = await page.request.fetch(testUrl);
        const body = await response.text();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: testUrl,
          responseStatus: response.status(),
          phase: 'active-traversal',
        });

        for (const pattern of TRAVERSAL_SUCCESS_PATTERNS) {
          if (pattern.test(body)) {
            findings.push({
              id: randomUUID(),
              category: 'directory-traversal',
              severity: 'critical',
              title: 'Directory Traversal on API Endpoint',
              description: `The API endpoint is vulnerable to directory traversal, allowing access to system files.`,
              url: endpoint,
              evidence: `Payload: ${payload}\nResponse contains system file content`,
              request: { method: 'GET', url: testUrl },
              response: { status: response.status(), bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        }
      } catch {
        // Continue
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

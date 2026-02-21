import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { TRAVERSAL_PAYLOADS, TRAVERSAL_SUCCESS_PATTERNS } from '../../config/payloads/traversal.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

export const traversalCheck: ActiveCheck = {
  name: 'traversal',
  category: 'directory-traversal',
  async run(context, targets, config, requestLogger) {
    // Combine API endpoints and file-param URLs, deduplicated
    const allTargets = [...new Set([...targets.apiEndpoints, ...targets.fileParams])];

    if (allTargets.length === 0) return [];

    log.info(`Testing ${allTargets.length} URLs for directory traversal...`);
    return testDirectoryTraversal(context, allTargets, config, requestLogger);
  },
};

/** Common query params that accept file paths */
const FILE_PARAMS = /^(file|path|page|template|include|doc|folder|dir|name|src|resource|load|image|img|document|attachment)$/i;

async function testDirectoryTraversal(
  context: BrowserContext,
  endpoints: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloadsToTest = config.profile === 'deep' ? TRAVERSAL_PAYLOADS : TRAVERSAL_PAYLOADS.slice(0, 2);

  for (const endpoint of endpoints) {
    // Strategy 1: Path segment replacement (for API-like endpoints with path segments)
    if (/\/[^/?]+$/.test(new URL(endpoint).pathname)) {
      for (const payload of payloadsToTest.slice(0, 2)) {
        const testUrl = endpoint.replace(/\/[^/?]*(\?|$)/, `/${payload}$1`);
        const found = await testTraversalUrl(context, testUrl, endpoint, payload, requestLogger);
        if (found) { findings.push(found); break; }
        await delay(config.requestDelay);
      }
    }

    // Strategy 2: Query parameter injection — test any params that look file-related
    try {
      const parsed = new URL(endpoint);
      const fileParams = Array.from(parsed.searchParams.keys()).filter((k) => FILE_PARAMS.test(k));
      for (const param of fileParams) {
        for (const payload of payloadsToTest.slice(0, 2)) {
          const testUrl = new URL(endpoint);
          testUrl.searchParams.set(param, payload);
          const found = await testTraversalUrl(context, testUrl.href, endpoint, payload, requestLogger);
          if (found) { findings.push(found); break; }
          await delay(config.requestDelay);
        }
      }
    } catch (err) {
      log.debug(`Traversal URL parse: ${(err as Error).message}`);
    }
  }

  return findings;
}

async function testTraversalUrl(
  context: BrowserContext,
  testUrl: string,
  originalEndpoint: string,
  payload: string,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
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
        return {
          id: randomUUID(),
          category: 'directory-traversal',
          severity: 'critical',
          title: 'Directory Traversal',
          description: `The endpoint is vulnerable to directory traversal, allowing access to system files.`,
          url: originalEndpoint,
          evidence: `Payload: ${payload}\nTest URL: ${testUrl}\nResponse contains system file content`,
          request: { method: 'GET', url: testUrl },
          response: { status: response.status(), bodySnippet: body.slice(0, 200) },
          timestamp: new Date().toISOString(),
        };
      }
    }
  } catch (err) {
    log.debug(`Traversal test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }
  return null;
}

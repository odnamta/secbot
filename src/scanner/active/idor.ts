import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/**
 * Regex to find sequential numeric IDs in URL path segments.
 * Matches patterns like /users/123, /api/v1/invoices/456, /orders/78
 * Captures: [full match, resource name, numeric ID]
 */
const SEQUENTIAL_ID_RE = /\/([a-z][a-z0-9_-]*?)\/(\d+)(?:\/|$|\?)/gi;

/** Extract ID patterns from a URL */
function extractIdPatterns(url: string): Array<{ url: string; resource: string; id: number; idIndex: number }> {
  const patterns: Array<{ url: string; resource: string; id: number; idIndex: number }> = [];
  const parsed = new URL(url);
  const path = parsed.pathname;

  let match: RegExpExecArray | null;
  const re = new RegExp(SEQUENTIAL_ID_RE.source, SEQUENTIAL_ID_RE.flags);
  while ((match = re.exec(path)) !== null) {
    const id = parseInt(match[2], 10);
    // Skip very large IDs (likely not sequential), version numbers like v1/v2, and 0
    if (id === 0 || id > 999999) continue;
    if (/^v\d+$/.test(match[1])) continue;

    patterns.push({
      url,
      resource: match[1],
      id,
      idIndex: match.index + match[1].length + 1, // position of the ID in path
    });
  }

  return patterns;
}

/** Build a URL with a different ID at the given position */
function replaceIdInUrl(url: string, pattern: { resource: string; id: number }, newId: number): string {
  const parsed = new URL(url);
  // Replace the specific /resource/id pattern with /resource/newId
  parsed.pathname = parsed.pathname.replace(
    new RegExp(`(/${escapeRegex(pattern.resource)}/)(${pattern.id})(?=/|$)`),
    `$1${newId}`,
  );
  return parsed.href;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export const idorCheck: ActiveCheck = {
  name: 'idor',
  category: 'idor',
  async run(context, targets, config, requestLogger) {
    // IDOR without auth is meaningless — skip entirely
    if (!config.authStorageState) {
      log.info('IDOR check skipped: no auth storage state configured');
      return [];
    }

    // Collect all URLs that have sequential numeric IDs
    const allUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])];
    const idPatterns = allUrls.flatMap(extractIdPatterns);

    if (idPatterns.length === 0) {
      log.info('IDOR check: no sequential ID patterns found in URLs');
      return [];
    }

    // Deduplicate by resource name (test each resource pattern once)
    const seen = new Set<string>();
    const uniquePatterns = idPatterns.filter((p) => {
      const key = `${new URL(p.url).origin}:${p.resource}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    log.info(`Testing ${uniquePatterns.length} URL patterns for IDOR vulnerabilities...`);
    return testIdor(context, uniquePatterns, config, requestLogger);
  },
};

async function testIdor(
  context: BrowserContext,
  patterns: Array<{ url: string; resource: string; id: number; idIndex: number }>,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const pattern of patterns) {
    try {
      // Step 1: Fetch baseline (the original URL)
      const baselinePage = await context.newPage();
      let baselineStatus: number;
      let baselineContentType: string;
      let baselineBodyLength: number;
      try {
        const baselineResponse = await baselinePage.request.fetch(pattern.url);
        baselineStatus = baselineResponse.status();
        baselineContentType = baselineResponse.headers()['content-type'] ?? '';
        const baselineBody = await baselineResponse.text();
        baselineBodyLength = baselineBody.length;

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: pattern.url,
          responseStatus: baselineStatus,
          phase: 'active-idor',
        });

        // If baseline doesn't return 200, skip — can't establish access
        if (baselineStatus !== 200) {
          continue;
        }
      } finally {
        await baselinePage.close();
      }

      // Step 2: Try adjacent IDs (id+1, id-1)
      const adjacentIds = [pattern.id + 1, pattern.id - 1].filter((id) => id > 0);

      for (const adjId of adjacentIds) {
        const adjUrl = replaceIdInUrl(pattern.url, pattern, adjId);

        const adjPage = await context.newPage();
        try {
          const adjResponse = await adjPage.request.fetch(adjUrl);
          const adjStatus = adjResponse.status();
          const adjContentType = adjResponse.headers()['content-type'] ?? '';
          const adjBody = await adjResponse.text();
          const adjBodyLength = adjBody.length;

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: adjUrl,
            responseStatus: adjStatus,
            phase: 'active-idor',
          });

          // Flag as potential IDOR if:
          // 1. Adjacent ID returns 200 (same as baseline)
          // 2. Same content-type
          if (adjStatus === 200 && sameContentType(baselineContentType, adjContentType)) {
            findings.push({
              id: randomUUID(),
              category: 'idor',
              severity: 'high',
              title: `Potential IDOR on /${pattern.resource}/:id`,
              description:
                `Accessing /${pattern.resource}/${adjId} with the current auth session returned a successful response (HTTP 200), ` +
                `suggesting the application does not verify resource ownership. ` +
                `An attacker could enumerate IDs to access other users' ${pattern.resource} data.`,
              url: pattern.url,
              evidence:
                `Baseline: GET ${pattern.url} -> ${baselineStatus} (${baselineBodyLength} bytes, ${baselineContentType})\n` +
                `Adjacent: GET ${adjUrl} -> ${adjStatus} (${adjBodyLength} bytes, ${adjContentType})`,
              request: { method: 'GET', url: adjUrl },
              response: {
                status: adjStatus,
                headers: { 'content-type': adjContentType },
                bodySnippet: adjBody.slice(0, 200),
              },
              timestamp: new Date().toISOString(),
              affectedUrls: [pattern.url, adjUrl],
            });

            // One finding per resource pattern is enough
            break;
          }
        } catch (err) {
          log.debug(`IDOR test: ${(err as Error).message}`);
        } finally {
          await adjPage.close();
        }

        await delay(config.requestDelay);
      }
    } catch (err) {
      log.debug(`IDOR baseline: ${(err as Error).message}`);
    }

    await delay(config.requestDelay);
  }

  return findings;
}

/** Check if two content-type headers represent the same type (ignoring charset etc.) */
function sameContentType(a: string, b: string): boolean {
  const normalize = (ct: string) => ct.split(';')[0].trim().toLowerCase();
  return normalize(a) === normalize(b);
}

import { randomUUID } from 'node:crypto';
import { chromium, type BrowserContext } from 'playwright';
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
    if (id === 0 || id > 999999) continue;
    if (/^v\d+$/.test(match[1])) continue;

    patterns.push({
      url,
      resource: match[1],
      id,
      idIndex: match.index + match[1].length + 1,
    });
  }

  return patterns;
}

/** Build a URL with a different ID at the given position */
function replaceIdInUrl(url: string, pattern: { resource: string; id: number }, newId: number): string {
  const parsed = new URL(url);
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
    // IDOR requires two different auth sessions to be meaningful.
    // Single-session testing only proves resources exist — not a vulnerability.
    if (!config.authStorageState) {
      log.info('IDOR check skipped: no --auth provided (requires authentication)');
      return [];
    }
    if (!config.idorAltAuthState) {
      log.info('IDOR check skipped: no --idor-alt-auth provided. Single-session IDOR detection produces false positives. Provide a second user\'s auth state to enable meaningful IDOR testing.');
      return [];
    }

    const allUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])];
    const idPatterns = allUrls.flatMap(extractIdPatterns);

    if (idPatterns.length === 0) {
      log.info('IDOR check: no sequential ID patterns found in URLs');
      return [];
    }

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
  primaryContext: BrowserContext,
  patterns: Array<{ url: string; resource: string; id: number; idIndex: number }>,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Launch a separate browser with the alternate user's auth state.
  // Primary context = User A (owner). Alt context = User B (attacker).
  const altBrowser = await chromium.launch({ headless: true });
  const altContext = await altBrowser.newContext({ storageState: config.idorAltAuthState });

  try {
    for (const pattern of patterns) {
      try {
        // Step 1: Fetch baseline with User A (primary auth) — confirm resource exists
        const baselinePage = await primaryContext.newPage();
        let baselineStatus: number;
        let baselineContentType: string;
        let baselineBody: string;
        try {
          const baselineResponse = await baselinePage.request.fetch(pattern.url);
          baselineStatus = baselineResponse.status();
          baselineContentType = baselineResponse.headers()['content-type'] ?? '';
          baselineBody = await baselineResponse.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: pattern.url,
            responseStatus: baselineStatus,
            phase: 'active-idor',
          });

          if (baselineStatus !== 200) continue;
        } finally {
          await baselinePage.close();
        }

        // Step 2: Probe User A's resource with User B's auth (alt context)
        // If User B can access User A's resource, that's IDOR.
        const probePage = await altContext.newPage();
        try {
          const probeResponse = await probePage.request.fetch(pattern.url);
          const probeStatus = probeResponse.status();
          const probeContentType = probeResponse.headers()['content-type'] ?? '';
          const probeBody = await probeResponse.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: pattern.url,
            responseStatus: probeStatus,
            phase: 'active-idor-alt',
          });

          // IDOR confirmed if:
          // 1. User B gets 200 on User A's resource
          // 2. Same content type (not an error page)
          // 3. Response body is similar (not a generic "not found" with 200 status)
          if (
            probeStatus === 200 &&
            sameContentType(baselineContentType, probeContentType) &&
            bodySimilarity(baselineBody, probeBody) > 0.5
          ) {
            findings.push({
              id: randomUUID(),
              category: 'idor',
              severity: 'high',
              title: `IDOR: User B can access /${pattern.resource}/:id`,
              description:
                `A different authenticated user (User B) can access /${pattern.resource}/${pattern.id} which belongs to User A. ` +
                `The application does not verify resource ownership. ` +
                `Response bodies are ${Math.round(bodySimilarity(baselineBody, probeBody) * 100)}% similar.`,
              url: pattern.url,
              evidence:
                `User A: GET ${pattern.url} -> ${baselineStatus} (${baselineBody.length} bytes)\n` +
                `User B: GET ${pattern.url} -> ${probeStatus} (${probeBody.length} bytes)\n` +
                `Body similarity: ${Math.round(bodySimilarity(baselineBody, probeBody) * 100)}%`,
              request: { method: 'GET', url: pattern.url },
              response: {
                status: probeStatus,
                headers: { 'content-type': probeContentType },
                bodySnippet: probeBody.slice(0, 200),
              },
              timestamp: new Date().toISOString(),
              affectedUrls: [pattern.url],
            });
          }
        } catch (err) {
          log.debug(`IDOR probe: ${(err as Error).message}`);
        } finally {
          await probePage.close();
        }

        await delay(config.requestDelay);
      } catch (err) {
        log.debug(`IDOR baseline: ${(err as Error).message}`);
      }
    }
  } finally {
    await altContext.close();
    await altBrowser.close();
  }

  return findings;
}

/** Rough body similarity based on length ratio */
function bodySimilarity(a: string, b: string): number {
  if (a.length === 0 && b.length === 0) return 1;
  if (a.length === 0 || b.length === 0) return 0;
  const ratio = Math.min(a.length, b.length) / Math.max(a.length, b.length);
  return ratio;
}

/** Check if two content-type headers represent the same type (ignoring charset etc.) */
function sameContentType(a: string, b: string): boolean {
  const normalize = (ct: string) => ct.split(';')[0].trim().toLowerCase();
  return normalize(a) === normalize(b);
}

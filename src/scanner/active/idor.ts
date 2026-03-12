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

/**
 * Regex to find UUIDs in URL path segments.
 * Matches patterns like /documents/550e8400-e29b-41d4-a716-446655440000
 * Captures: [full match, resource name, UUID]
 */
const UUID_PATH_RE = /\/([a-z][a-z0-9_-]*?)\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)/gi;

/**
 * Regex for UUID v4 format in query param values.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Query parameter names that are typically ID fields.
 * Matched case-insensitively.
 */
const ID_PARAM_NAMES = /^(?:id|user_id|account_id|order_id|invoice_id|item_id|product_id|doc_id|record_id|uid|pid|oid|cid|profile_id|customer_id|employee_id|member_id|ticket_id|case_id|file_id)$/i;

/** A query parameter containing an ID-like value */
export interface QueryParamId {
  url: string;
  param: string;
  value: string;
  type: 'numeric' | 'uuid';
}

/**
 * Extract ID-like query parameters from a URL.
 * Matches known ID param names with numeric (1-999999) or UUID values.
 */
export function extractQueryParamIds(url: string): QueryParamId[] {
  const results: QueryParamId[] = [];
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return results;
  }

  for (const [param, value] of parsed.searchParams.entries()) {
    if (!ID_PARAM_NAMES.test(param)) continue;

    if (UUID_RE.test(value)) {
      results.push({ url, param, value, type: 'uuid' });
    } else if (/^\d+$/.test(value)) {
      const n = parseInt(value, 10);
      if (n >= 1 && n <= 999999) {
        results.push({ url, param, value, type: 'numeric' });
      }
    }
  }

  return results;
}

/**
 * Generate adjacent IDs for horizontal enumeration probing.
 * - numeric: returns [value-1, value+1], skipping 0
 * - uuid: returns [] (UUIDs cannot be enumerated)
 */
export function generateAdjacentIds(value: string, type: 'numeric' | 'uuid'): number[] {
  if (type === 'uuid') return [];

  const n = parseInt(value, 10);
  const adjacent: number[] = [];
  if (n - 1 > 0) adjacent.push(n - 1);
  adjacent.push(n + 1);
  return adjacent;
}

/** Result of extractIdPatterns — id can be numeric (path segment) or string (UUID path) */
export type IdPattern = {
  url: string;
  resource: string;
  id: number | string;
  idIndex: number;
};

/** Extract ID patterns from a URL (numeric path IDs and UUID path IDs) */
export function extractIdPatterns(url: string): IdPattern[] {
  const patterns: IdPattern[] = [];
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return patterns;
  }
  const path = parsed.pathname;

  // Numeric IDs in path segments
  let match: RegExpExecArray | null;
  const numericRe = new RegExp(SEQUENTIAL_ID_RE.source, SEQUENTIAL_ID_RE.flags);
  while ((match = numericRe.exec(path)) !== null) {
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

  // UUID IDs in path segments
  const uuidRe = new RegExp(UUID_PATH_RE.source, UUID_PATH_RE.flags);
  while ((match = uuidRe.exec(path)) !== null) {
    if (/^v\d+$/.test(match[1])) continue;

    patterns.push({
      url,
      resource: match[1],
      id: match[2],
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

    // --- Path-based IDOR (numeric IDs only — replaceIdInUrl requires a number) ---
    const allUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])];
    const idPatterns = allUrls.flatMap(extractIdPatterns);
    const numericPathPatterns = idPatterns.filter(
      (p): p is IdPattern & { id: number } => typeof p.id === 'number',
    );

    const seen = new Set<string>();
    const uniqueNumericPatterns = numericPathPatterns.filter((p) => {
      const key = `${new URL(p.url).origin}:${p.resource}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    let findings: RawFinding[] = [];

    if (uniqueNumericPatterns.length > 0) {
      log.info(`Testing ${uniqueNumericPatterns.length} path ID patterns for IDOR vulnerabilities...`);
      findings = await testIdor(context, uniqueNumericPatterns, config, requestLogger);
    } else {
      log.info('IDOR check: no sequential ID patterns found in URLs');
    }

    // --- Query parameter IDOR ---
    const allUrlsWithParams = [
      ...new Set([...targets.pages, ...targets.urlsWithParams, ...targets.apiEndpoints]),
    ];
    const queryParamIds = allUrlsWithParams.flatMap(extractQueryParamIds);

    if (queryParamIds.length > 0) {
      const qSeen = new Set<string>();
      const uniqueQueryParams = queryParamIds.filter((q) => {
        const key = `${new URL(q.url).origin}:${q.param}`;
        if (qSeen.has(q.url + ':' + q.param)) return false;
        qSeen.add(q.url + ':' + q.param);
        return !seen.has(key); // don't re-test what path IDOR already covers
      });

      if (uniqueQueryParams.length > 0) {
        log.info(`Testing ${uniqueQueryParams.length} query param ID patterns for IDOR vulnerabilities...`);
        const qFindings = await testQueryParamIdor(context, uniqueQueryParams, config, requestLogger);
        findings = findings.concat(qFindings);
      }
    }

    return findings;
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

/** Test IDOR via query parameter ID substitution (adjacent ID enumeration) */
async function testQueryParamIdor(
  primaryContext: BrowserContext,
  queryParamIds: QueryParamId[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  const altBrowser = await chromium.launch({ headless: true });
  const altContext = await altBrowser.newContext({ storageState: config.idorAltAuthState });

  try {
    for (const qp of queryParamIds) {
      try {
        // Baseline: fetch the original URL with User A's auth
        const baselinePage = await primaryContext.newPage();
        let baselineStatus: number;
        let baselineContentType: string;
        let baselineBody: string;
        try {
          const baselineResponse = await baselinePage.request.fetch(qp.url);
          baselineStatus = baselineResponse.status();
          baselineContentType = baselineResponse.headers()['content-type'] ?? '';
          baselineBody = await baselineResponse.text();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: qp.url,
            responseStatus: baselineStatus,
            phase: 'active-idor',
          });

          if (baselineStatus !== 200) continue;
        } finally {
          await baselinePage.close();
        }

        // Build probe URLs with adjacent IDs
        const adjacentIds = generateAdjacentIds(qp.value, qp.type);
        for (const adjacentId of adjacentIds) {
          const probeUrl = new URL(qp.url);
          probeUrl.searchParams.set(qp.param, String(adjacentId));
          const probeHref = probeUrl.href;

          const probePage = await altContext.newPage();
          try {
            const probeResponse = await probePage.request.fetch(probeHref);
            const probeStatus = probeResponse.status();
            const probeContentType = probeResponse.headers()['content-type'] ?? '';
            const probeBody = await probeResponse.text();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'GET',
              url: probeHref,
              responseStatus: probeStatus,
              phase: 'active-idor-alt',
            });

            if (
              probeStatus === 200 &&
              sameContentType(baselineContentType, probeContentType) &&
              bodySimilarity(baselineBody, probeBody) > 0.5
            ) {
              const similarity = Math.round(bodySimilarity(baselineBody, probeBody) * 100);
              findings.push({
                id: randomUUID(),
                category: 'idor',
                severity: 'high',
                title: `IDOR: Horizontal enumeration via ?${qp.param}=`,
                description:
                  `User B can access a different user's resource by modifying the ${qp.param} query parameter from ${qp.value} to ${adjacentId}. ` +
                  `The application does not verify resource ownership for this parameter. ` +
                  `Response bodies are ${similarity}% similar.`,
                url: qp.url,
                evidence:
                  `User A: GET ${qp.url} -> ${baselineStatus} (${baselineBody.length} bytes)\n` +
                  `User B: GET ${probeHref} -> ${probeStatus} (${probeBody.length} bytes)\n` +
                  `Body similarity: ${similarity}%`,
                request: { method: 'GET', url: probeHref },
                response: {
                  status: probeStatus,
                  headers: { 'content-type': probeContentType },
                  bodySnippet: probeBody.slice(0, 200),
                },
                timestamp: new Date().toISOString(),
                affectedUrls: [qp.url, probeHref],
              });
            }
          } catch (err) {
            log.debug(`IDOR query param probe: ${(err as Error).message}`);
          } finally {
            await probePage.close();
          }

          await delay(config.requestDelay);
        }
      } catch (err) {
        log.debug(`IDOR query param baseline: ${(err as Error).message}`);
      }
    }
  } finally {
    await altContext.close();
    await altBrowser.close();
  }

  return findings;
}

/** Token-based Jaccard similarity — compares actual content, not just length */
function bodySimilarity(body1: string, body2: string): number {
  if (body1 === body2) return 1.0;
  if (!body1 || !body2) return 0.0;

  // For JSON responses, compare structure (keys) not values.
  // If both are JSON and keys match >0.9, it's "same structure, different data" — IDOR signal.
  const jsonSim = jsonKeySimilarity(body1, body2);
  if (jsonSim >= 0) return jsonSim;

  // Normalize: strip dynamic content (timestamps, tokens, session IDs)
  const normalize = (s: string) => s
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[UUID]')
    .replace(/\b\d{10,13}\b/g, '[TIMESTAMP]')
    .replace(/\b[A-Za-z0-9+/=]{20,}\b/g, '[TOKEN]');

  const tokens1 = new Set(normalize(body1).split(/\s+/).filter(Boolean));
  const tokens2 = new Set(normalize(body2).split(/\s+/).filter(Boolean));

  if (tokens1.size === 0 && tokens2.size === 0) return 1.0;

  let intersection = 0;
  for (const t of tokens1) {
    if (tokens2.has(t)) intersection++;
  }

  const union = tokens1.size + tokens2.size - intersection;
  return union === 0 ? 1.0 : intersection / union;
}

/** For JSON responses, compare structure (keys) not values */
function jsonKeySimilarity(body1: string, body2: string): number {
  try {
    const extractKeys = (obj: unknown, prefix = ''): string[] => {
      if (obj === null || typeof obj !== 'object') return [];
      const keys: string[] = [];
      for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        const path = prefix ? `${prefix}.${k}` : k;
        keys.push(path);
        keys.push(...extractKeys(v, path));
      }
      return keys;
    };

    const keys1 = new Set(extractKeys(JSON.parse(body1)));
    const keys2 = new Set(extractKeys(JSON.parse(body2)));

    let intersection = 0;
    for (const k of keys1) if (keys2.has(k)) intersection++;
    const union = keys1.size + keys2.size - intersection;
    return union === 0 ? 1.0 : intersection / union;
  } catch {
    return -1; // Not JSON
  }
}

/** Check if two content-type headers represent the same type (ignoring charset etc.) */
function sameContentType(a: string, b: string): boolean {
  const normalize = (ct: string) => ct.split(';')[0].trim().toLowerCase();
  return normalize(a) === normalize(b);
}

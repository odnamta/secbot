import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/**
 * Regex to detect versioned API path segments like /v1/, /v2/, /v3/ etc.
 * Captures: full match, prefix (before version), version number, suffix (after version)
 */
const VERSION_PATTERN = /^(.*\/v)(\d+)(\/.*)?$/;

/** Max endpoints to probe per scan */
const MAX_ENDPOINTS = 10;

/** How many older versions to probe (v{N-1} and v{N-2}) */
const MAX_VERSION_DEPTH = 2;

/**
 * Extract version info from a URL path.
 * Returns null if no version pattern is found.
 */
export function extractVersionInfo(url: string): {
  currentVersion: number;
  prefix: string;
  suffix: string;
  fullUrl: string;
} | null {
  try {
    const parsed = new URL(url);
    const match = parsed.pathname.match(VERSION_PATTERN);
    if (!match) return null;

    const [, prefix, versionStr, suffix = ''] = match;
    const version = parseInt(versionStr, 10);

    // Only consider v2+ (there's nothing older than v1 to probe)
    if (version < 2) return null;

    return {
      currentVersion: version,
      prefix,
      suffix,
      fullUrl: url,
    };
  } catch {
    return null;
  }
}

/**
 * Generate older version URLs for a given versioned URL.
 * E.g., /api/v3/users -> [/api/v2/users, /api/v1/users]
 */
export function generateOlderVersionUrls(url: string): string[] {
  const info = extractVersionInfo(url);
  if (!info) return [];

  const olderUrls: string[] = [];
  const parsed = new URL(url);

  for (let i = 1; i <= MAX_VERSION_DEPTH; i++) {
    const olderVersion = info.currentVersion - i;
    if (olderVersion < 1) break;

    const olderPath = `${info.prefix}${olderVersion}${info.suffix}`;
    const olderUrl = new URL(parsed.href);
    olderUrl.pathname = olderPath;
    olderUrls.push(olderUrl.href);
  }

  return olderUrls;
}

export const apiVersionCheck: ActiveCheck = {
  parallel: true,
  name: 'api-version',
  category: 'api-versioning',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Collect all versioned API endpoints from pages and apiEndpoints
    const allUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])];
    const versionedUrls = allUrls.filter((u) => extractVersionInfo(u) !== null);

    if (versionedUrls.length === 0) return findings;

    const testUrls = versionedUrls.slice(0, MAX_ENDPOINTS);
    log.info(`Testing ${testUrls.length} versioned API endpoints for version downgrade...`);

    for (const currentUrl of testUrls) {
      const olderUrls = generateOlderVersionUrls(currentUrl);
      if (olderUrls.length === 0) continue;

      // First, fetch the current version to get baseline status + body size
      const baseline = await fetchUrl(context, currentUrl, requestLogger);
      if (!baseline) continue;

      for (const olderUrl of olderUrls) {
        await delay(config.requestDelay);

        const older = await fetchUrl(context, olderUrl, requestLogger);
        if (!older) continue;

        // Check 1: Auth bypass — older version returns 200/30x while current requires auth
        const currentRequiresAuth = baseline.status === 401 || baseline.status === 403;
        const olderIsAccessible = older.status >= 200 && older.status < 400;

        if (currentRequiresAuth && olderIsAccessible) {
          findings.push({
            id: randomUUID(),
            category: 'api-versioning',
            severity: 'high',
            title: 'API Version Downgrade — Authentication Bypass',
            description:
              `The current API version (${currentUrl}) requires authentication (HTTP ${baseline.status}), `
              + `but an older version (${olderUrl}) is accessible without auth (HTTP ${older.status}). `
              + 'An attacker can bypass authentication by targeting the older API version. '
              + 'This is a broken access control vulnerability (OWASP A01:2021).',
            url: olderUrl,
            evidence: [
              `Current version: ${currentUrl} -> HTTP ${baseline.status}`,
              `Older version: ${olderUrl} -> HTTP ${older.status}`,
              `Body size (current): ${baseline.bodyLength} bytes`,
              `Body size (older): ${older.bodyLength} bytes`,
            ].join('\n'),
            request: { method: 'GET', url: olderUrl },
            response: {
              status: older.status,
              bodySnippet: older.bodySnippet,
            },
            timestamp: new Date().toISOString(),
            affectedUrls: [currentUrl, olderUrl],
            confidence: 'high',
          });
          continue; // No need to also check body size if auth bypass found
        }

        // Check 2: Data exposure — older version returns significantly larger body
        // (potentially exposes more data fields than the newer, hardened version)
        const bothAccessible =
          baseline.status >= 200 && baseline.status < 400 &&
          older.status >= 200 && older.status < 400;

        if (bothAccessible && older.bodyLength > 0 && baseline.bodyLength > 0) {
          const ratio = older.bodyLength / baseline.bodyLength;
          // Flag if older version returns >50% more data
          if (ratio > 1.5) {
            findings.push({
              id: randomUUID(),
              category: 'api-versioning',
              severity: 'medium',
              title: 'API Version Downgrade — Potential Data Exposure',
              description:
                `The older API version (${olderUrl}) returns significantly more data `
                + `(${older.bodyLength} bytes) than the current version (${currentUrl}, ${baseline.bodyLength} bytes). `
                + 'The older version may expose additional fields, deprecated data, or internal details '
                + 'that were removed in newer versions for security reasons.',
              url: olderUrl,
              evidence: [
                `Current version: ${currentUrl} -> HTTP ${baseline.status} (${baseline.bodyLength} bytes)`,
                `Older version: ${olderUrl} -> HTTP ${older.status} (${older.bodyLength} bytes)`,
                `Body size ratio: ${ratio.toFixed(1)}x larger in older version`,
              ].join('\n'),
              request: { method: 'GET', url: olderUrl },
              response: {
                status: older.status,
                bodySnippet: older.bodySnippet,
              },
              timestamp: new Date().toISOString(),
              affectedUrls: [currentUrl, olderUrl],
              confidence: 'medium',
            });
          }
        }
      }

      await delay(config.requestDelay);
    }

    return findings;
  },
};

interface FetchResult {
  status: number;
  bodyLength: number;
  bodySnippet: string;
}

async function fetchUrl(
  context: BrowserContext,
  url: string,
  requestLogger?: RequestLogger,
): Promise<FetchResult | null> {
  const page = await context.newPage();
  try {
    const response = await page.request.fetch(url, { maxRedirects: 0 });
    const status = response.status();
    const body = await response.text();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'GET',
      url,
      responseStatus: status,
      phase: 'active-api-version',
    });

    return {
      status,
      bodyLength: body.length,
      bodySnippet: body.slice(0, 200),
    };
  } catch (err) {
    log.debug(`API version probe failed for ${url}: ${(err as Error).message}`);
    return null;
  } finally {
    await page.close();
  }
}

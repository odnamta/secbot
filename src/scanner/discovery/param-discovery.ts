import { FastEngine, type FastResponse } from '../fast-engine.js';
import { log } from '../../utils/logger.js';

/** Common hidden parameter names — curated from Arjun/Burp/real-world experience */
const COMMON_PARAMS = [
  // Debug/admin
  'debug', 'test', 'verbose', 'admin', 'internal', 'dev', 'staging',
  'trace', 'log', 'monitor', 'profile', 'benchmark', 'console',
  // Auth/access
  'token', 'key', 'api_key', 'apikey', 'secret', 'auth', 'access_token',
  'session', 'jwt', 'bearer', 'password', 'user', 'username', 'role',
  'is_admin', 'privilege', 'permission',
  // Display/format
  'format', 'type', 'output', 'content_type', 'accept', 'encoding',
  'lang', 'language', 'locale', 'timezone', 'theme', 'view', 'mode',
  'layout', 'template', 'render', 'raw', 'json', 'xml', 'csv',
  // Data control
  'limit', 'offset', 'page', 'per_page', 'size', 'count', 'max',
  'sort', 'order', 'orderby', 'sort_by', 'direction', 'asc', 'desc',
  'filter', 'where', 'query', 'search', 'q', 'keyword', 'term',
  'fields', 'select', 'include', 'exclude', 'expand', 'embed',
  // SSRF/redirect
  'url', 'uri', 'path', 'file', 'filename', 'src', 'source', 'dest',
  'destination', 'redirect', 'redirect_uri', 'return_url', 'return_to',
  'next', 'continue', 'goto', 'target', 'link', 'ref', 'reference',
  'callback', 'callback_url', 'webhook', 'endpoint',
  // Injection targets
  'id', 'uid', 'user_id', 'account_id', 'item_id', 'product_id',
  'order_id', 'category', 'cat', 'tag', 'name', 'title', 'slug',
  'email', 'phone', 'address', 'comment', 'message', 'body', 'text',
  'data', 'input', 'value', 'content', 'description',
  // Config
  'config', 'settings', 'options', 'env', 'environment',
  'version', 'v', 'api_version',
  // Cache/proxy
  'cache', 'no_cache', 'nocache', 'refresh', 'reload', 'purge',
  'proxy', 'forward', 'via',
  // Misc
  'action', 'method', 'cmd', 'command', 'exec', 'run',
  'jsonp', 'padding',
  'origin', 'host', 'referer', 'referrer',
  'x-forwarded-for', 'x-real-ip',
];

/** Probe value injected into candidate parameters */
const PROBE_VALUE = 'secbot_probe_value';

export interface DiscoveredParam {
  url: string;
  param: string;
  evidence: 'status-change' | 'body-change' | 'header-change' | 'error-triggered';
  baselineStatus: number;
  probeStatus: number;
  bodyLengthDiff: number;
}

export interface ParamDiscoveryOptions {
  concurrency?: number;
  timeout?: number;
  requestDelay?: number;
  proxy?: string;
  userAgent?: string;
  maxParams?: number; // limit params to test per URL, default 100
  maxUrls?: number; // limit URLs to test, default 10
  extraHeaders?: Record<string, string>;
}

/** Response fingerprint used for comparison */
export interface ResponseFingerprint {
  status: number;
  bodyLength: number;
  headerCount: number;
  /** Sorted, lowercased header names for stable comparison */
  headerNames: string[];
  /** MD5-ish content hash: first 200 + last 200 chars of body */
  bodySketch: string;
}

/**
 * Build a fingerprint from a FastResponse for baseline comparison.
 */
export function fingerprint(resp: FastResponse): ResponseFingerprint {
  const headerNames = Object.keys(resp.headers).map(h => h.toLowerCase()).sort();
  const body = resp.body;
  const bodySketch = body.length <= 400
    ? body
    : body.slice(0, 200) + body.slice(-200);
  return {
    status: resp.status,
    bodyLength: body.length,
    headerCount: headerNames.length,
    headerNames,
    bodySketch,
  };
}

/**
 * Compare a probe fingerprint against the baseline.
 * Returns the evidence type if a meaningful difference is detected, or null otherwise.
 */
export function compareFingerprints(
  baseline: ResponseFingerprint,
  probe: ResponseFingerprint,
): DiscoveredParam['evidence'] | null {
  // 1. Status code change — strongest signal
  if (baseline.status !== probe.status) {
    // Error triggered: 200 -> 4xx/5xx
    if (baseline.status < 400 && probe.status >= 400) {
      return 'error-triggered';
    }
    // Any other status change (redirect, etc.) — param is processed
    return 'status-change';
  }

  // 2. New headers appeared — param triggers different behavior
  if (probe.headerCount > baseline.headerCount) {
    const baselineSet = new Set(baseline.headerNames);
    const newHeaders = probe.headerNames.filter(h => !baselineSet.has(h));
    if (newHeaders.length > 0) {
      return 'header-change';
    }
  }

  // 3. Body length differs by >10% — param affects output
  if (baseline.bodyLength > 0) {
    const diff = Math.abs(probe.bodyLength - baseline.bodyLength);
    const pct = diff / baseline.bodyLength;
    if (pct > 0.10) {
      return 'body-change';
    }
  } else if (probe.bodyLength > 50) {
    // Baseline was empty, probe has content — definitely processed
    return 'body-change';
  }

  return null;
}

/**
 * Filter out params that already exist in a URL's query string.
 * No point probing a param the app already uses visibly.
 */
function filterExistingParams(url: string, params: string[]): string[] {
  try {
    const existing = new Set(
      [...new URL(url).searchParams.keys()].map(k => k.toLowerCase()),
    );
    return params.filter(p => !existing.has(p.toLowerCase()));
  } catch {
    return params;
  }
}

/**
 * Build probe URL by appending param=value to the given base URL.
 * Handles URLs that already have query strings.
 */
export function buildProbeUrl(baseUrl: string, param: string, value: string): string {
  try {
    const u = new URL(baseUrl);
    u.searchParams.set(param, value);
    return u.href;
  } catch {
    // Fallback for malformed URLs
    const sep = baseUrl.includes('?') ? '&' : '?';
    return `${baseUrl}${sep}${encodeURIComponent(param)}=${encodeURIComponent(value)}`;
  }
}

/**
 * Run hidden parameter discovery against a list of target URLs.
 *
 * For each URL:
 * 1. Send a baseline request (no extra params), fingerprint the response
 * 2. For each candidate param, send request with ?param=secbot_probe_value
 * 3. Compare response fingerprint to baseline
 * 4. Return only params that caused detectable changes
 */
export async function discoverParams(
  urls: string[],
  options: ParamDiscoveryOptions = {},
): Promise<DiscoveredParam[]> {
  const {
    concurrency = 10,
    timeout = 8000,
    requestDelay = 50,
    proxy,
    userAgent,
    maxParams = 100,
    maxUrls = 10,
    extraHeaders,
  } = options;

  // Limit URLs to test
  const targetUrls = urls.slice(0, maxUrls);
  if (targetUrls.length === 0) {
    return [];
  }

  // Limit params list
  const paramList = COMMON_PARAMS.slice(0, maxParams);

  log.info(`Param discovery: testing ${paramList.length} params on ${targetUrls.length} URLs`);

  const engine = new FastEngine({
    concurrency,
    requestDelay,
    proxy,
    userAgent: userAgent ?? 'Mozilla/5.0 (compatible; SecBot/2.0)',
    rateLimitRps: concurrency,
    defaultHeaders: extraHeaders,
  });

  const discovered: DiscoveredParam[] = [];

  for (const url of targetUrls) {
    // Step 1: Baseline — send 3 requests to establish a stable fingerprint
    // (reduces false positives from dynamic content like timestamps, CSRF tokens)
    let baselineFingerprints: ResponseFingerprint[];
    try {
      const baselineResponses = await engine.batch(
        [url, url, url],
        { method: 'GET', timeout },
      );
      baselineFingerprints = baselineResponses
        .filter((r): r is FastResponse => r !== null)
        .map(fingerprint);
    } catch (err) {
      log.debug(`Param discovery: baseline failed for ${url}: ${err}`);
      continue;
    }

    if (baselineFingerprints.length === 0) {
      log.debug(`Param discovery: no baseline responses for ${url}`);
      continue;
    }

    // Use the first baseline as the reference, but track body length variance
    const baseline = baselineFingerprints[0];
    const bodyLengthVariance = baselineFingerprints.length >= 2
      ? Math.max(
          ...baselineFingerprints.map(fp =>
            Math.abs(fp.bodyLength - baseline.bodyLength),
          ),
        )
      : 0;

    // Filter out params that already exist in the URL
    const candidateParams = filterExistingParams(url, paramList);

    // Step 2: Probe each candidate param
    const probeUrls = candidateParams.map(p => buildProbeUrl(url, p, PROBE_VALUE));
    const probeResults = await engine.batch(probeUrls, { method: 'GET', timeout });

    // Step 3: Compare each probe result to baseline
    for (let i = 0; i < candidateParams.length; i++) {
      const resp = probeResults[i];
      if (!resp) continue;

      const probeFp = fingerprint(resp);
      const evidence = compareFingerprints(baseline, probeFp);

      if (!evidence) continue;

      // Extra validation: if evidence is body-change, check against baseline variance
      // to avoid false positives from dynamic content
      if (evidence === 'body-change') {
        const diff = Math.abs(probeFp.bodyLength - baseline.bodyLength);
        // Body diff must exceed natural variance by at least 2x + 50 bytes
        if (diff <= bodyLengthVariance * 2 + 50) {
          continue;
        }
      }

      discovered.push({
        url,
        param: candidateParams[i],
        evidence,
        baselineStatus: baseline.status,
        probeStatus: probeFp.status,
        bodyLengthDiff: probeFp.bodyLength - baseline.bodyLength,
      });
    }

    const urlHits = discovered.filter(d => d.url === url).length;
    if (urlHits > 0) {
      log.info(`Param discovery: ${urlHits} hidden params found on ${url}`);
    }
  }

  const stats = engine.getStats();
  log.info(
    `Param discovery: found ${discovered.length} hidden params ` +
    `across ${targetUrls.length} URLs ` +
    `(${stats.total} requests, ${stats.errors} errors)`,
  );

  return discovered;
}

/**
 * Convert discovered params into URLs with query strings,
 * suitable for merging into ScanTargets.urlsWithParams.
 */
export function discoveredParamsToUrls(params: DiscoveredParam[]): string[] {
  const urls = new Set<string>();
  for (const p of params) {
    // Build URL with the discovered param (use a benign value)
    const probeUrl = buildProbeUrl(p.url, p.param, '1');
    urls.add(probeUrl);
  }
  return [...urls];
}

export { COMMON_PARAMS };

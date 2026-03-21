import type { BrowserContext } from 'playwright';
import type {
  RawFinding,
  ScanConfig,
  CrawledPage,
  FormInfo,
  AttackPlan,
  CheckCategory,
  CheckAuditEntry,
  ScanScope,
} from '../types.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import { RateLimiter } from '../../utils/rate-limiter.js';
import { DomainRateLimiter } from '../../utils/domain-rate-limiter.js';
import { isInScope } from '../../utils/scope.js';
import { xssCheck } from './xss.js';
import { sqliCheck } from './sqli.js';
import { corsCheck } from './cors.js';
import { redirectCheck } from './redirect.js';
import { traversalCheck } from './traversal.js';
import { ssrfCheck } from './ssrf.js';
import { sstiCheck } from './ssti.js';
import { cmdiCheck } from './cmdi.js';
import { idorCheck } from './idor.js';
import { tlsCheck } from './tls.js';
import { sriCheck } from './sri.js';
import { infoDisclosureCheck } from './info-disclosure.js';
import { jsCveCheck } from './js-cve.js';
import { crlfCheck } from './crlf.js';
import { rateLimitCheck } from './rate-limit.js';
import { jwtCheck } from './jwt.js';
import { raceCheck } from './race.js';
import { graphqlCheck } from './graphql.js';
import { hostHeaderCheck } from './host-header.js';
import { apiVersionCheck } from './api-version.js';
import { fileUploadCheck } from './file-upload.js';
import { businessLogicCheck } from './business-logic.js';
import { websocketCheck } from './websocket.js';
import { accessControlCheck } from './access-control.js';
import { subdomainTakeoverCheck } from './subdomain-takeover.js';
import { oauthCheck } from './oauth.js';
import { cachePoisoningCheck } from './cache-poisoning.js';
import { csrfCheck } from './csrf.js';
import { prototypePollutionCheck } from './prototype-pollution.js';
import { xxeCheck } from './xxe.js';
import { insecureDeserializationCheck } from './insecure-deserialization.js';
import { requestSmugglingCheck } from './request-smuggling.js';
import { ldapInjectionCheck } from './ldap-injection.js';
import { userEnumCheck } from './user-enum.js';
import { massAssignmentCheck } from './mass-assignment.js';
import { contentTypeConfusionCheck } from './content-type-confusion.js';
import { methodOverrideCheck } from './method-override.js';
import { emailInjectionCheck } from './email-injection.js';
import { bflaCheck } from './bfla.js';
import { clickjackingCheck } from './clickjacking.js';
import { timingAttackCheck } from './timing-attack.js';
import { verboseErrorsCheck } from './verbose-errors.js';
import { xpathInjectionCheck } from './xpath-injection.js';
import { log } from '../../utils/logger.js';

export interface ScanTargets {
  pages: string[];
  forms: FormInfo[];
  urlsWithParams: string[];
  apiEndpoints: string[];
  redirectUrls: string[];
  fileParams: string[]; // URLs with file-like parameters (path, file, doc, image, etc.)
}

export interface ActiveCheck {
  name: string;
  category: CheckCategory;
  /** If true, this check can run concurrently with other parallel checks (read-only, no state mutation) */
  parallel?: boolean;
  run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]>;
}

/** Registry of all available active checks */
export const CHECK_REGISTRY: ActiveCheck[] = [
  xssCheck,
  sqliCheck,
  corsCheck,
  redirectCheck,
  traversalCheck,
  ssrfCheck,
  sstiCheck,
  cmdiCheck,
  idorCheck,
  tlsCheck,
  sriCheck,
  infoDisclosureCheck,
  jsCveCheck,
  crlfCheck,
  rateLimitCheck,
  jwtCheck,
  raceCheck,
  graphqlCheck,
  hostHeaderCheck,
  apiVersionCheck,
  fileUploadCheck,
  businessLogicCheck,
  websocketCheck,
  accessControlCheck,
  subdomainTakeoverCheck,
  oauthCheck,
  cachePoisoningCheck,
  csrfCheck,
  prototypePollutionCheck,
  xxeCheck,
  insecureDeserializationCheck,
  requestSmugglingCheck,
  ldapInjectionCheck,
  userEnumCheck,
  massAssignmentCheck,
  contentTypeConfusionCheck,
  methodOverrideCheck,
  emailInjectionCheck,
  bflaCheck,
  clickjackingCheck,
  timingAttackCheck,
  verboseErrorsCheck,
  xpathInjectionCheck,
];

/**
 * Register an additional check (e.g. from a plugin) into the global registry.
 * Duplicates (by name) are skipped with a warning.
 */
export function registerPlugin(check: ActiveCheck): void {
  const existing = CHECK_REGISTRY.find((c) => c.name === check.name);
  if (existing) {
    log.warn(`Plugin "${check.name}" conflicts with existing check — skipping`);
    return;
  }
  CHECK_REGISTRY.push(check);
  log.info(`Registered plugin check: ${check.name}`);
}

/**
 * Load plugins from disk and register them into CHECK_REGISTRY.
 * Called once at startup before running scans.
 */
export async function loadAndRegisterPlugins(pluginDir?: string): Promise<void> {
  // Dynamic import to avoid circular dependency issues at module level
  const { loadPlugins } = await import('../../plugins/loader.js');
  const plugins = await loadPlugins(pluginDir);
  for (const plugin of plugins) {
    registerPlugin(plugin);
  }
}

/** Split checks into parallel (safe to run concurrently) and sequential groups */
export function splitChecksByParallelism(checks: ActiveCheck[]): {
  parallel: ActiveCheck[];
  sequential: ActiveCheck[];
} {
  return {
    parallel: checks.filter((c) => c.parallel),
    sequential: checks.filter((c) => !c.parallel),
  };
}

/** Regex for redirect-related parameter names */
const REDIRECT_PARAM_RE = /[?&](url|redirect|next|return|goto|dest|callback|redir|forward|ref|out|continue|target|path|link|returnUrl|redirectUrl|returnTo|return_to|redirect_uri|redirect_url|to|rurl)=/i;

/** Regex for file-like parameter names */
const FILE_PARAM_NAMES = /^(file|path|page|template|include|doc|folder|dir|name|src|resource|load|image|img|document|attachment)$/i;

/** Check if a parameter value looks file-like (contains dots, slashes, or common extensions) */
function isFileLikeValue(value: string): boolean {
  if (!value) return false;
  // Contains path separators
  if (value.includes('/') || value.includes('\\')) return true;
  // Contains common file extensions
  if (/\.\w{1,5}$/.test(value)) return true;
  // Contains directory traversal patterns
  if (value.includes('..')) return true;
  return false;
}

/** Regex for XHR/API response content types */
const API_CONTENT_TYPE_RE = /application\/json|application\/graphql|application\/xml|text\/xml/i;

/** URL patterns indicating API endpoints (broader than just /api/) */
const API_URL_PATTERN_RE = /\/api\/|\/graphql|\/v[0-9]+\/|\/rest\/|\/rpc\/|\/query|\/mutation|\/endpoint/i;

/** Static asset patterns to exclude from API endpoint discovery */
const STATIC_ASSET_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|mp[34]|webm)(\?|$)/i;

/** Analytics/tracking URL patterns — not worth testing for injection vulns */
const TRACKING_URL_RE = /\/(?:ga|gtag|g\/collect|analytics|beacon|pixel|tr|__utm|_ga|go9u\/ga|j\/collect|pagead|ad_event|conversion|log_event)\b/i;

/** URLs with excessive query params (>15) are almost always tracking/telemetry, not user input */
function hasExcessiveParams(url: string): boolean {
  try {
    const params = new URL(url).searchParams;
    let count = 0;
    for (const _ of params) { count++; if (count > 15) return true; }
    return false;
  } catch { return false; }
}

/** Check if a URL is a tracking/analytics endpoint not worth XSS testing */
function isTrackingUrl(url: string): boolean {
  return TRACKING_URL_RE.test(url) || hasExcessiveParams(url);
}

/** Build scan targets from crawled pages, filtering by scope.
 * Optionally accepts intercepted responses to discover API endpoints from network traffic.
 */
export function buildTargets(
  pages: CrawledPage[],
  targetUrl: string,
  scope?: ScanScope,
  interceptedResponses?: Array<{ url: string; status: number; headers: Record<string, string> }>,
): ScanTargets {
  const inScope = (url: string) => isInScope(url, targetUrl, scope);

  const scopedPages = pages.filter((p) => inScope(p.url));
  const rawForms = scopedPages.flatMap((p) => p.forms).filter((f) => {
    try { return inScope(new URL(f.action, f.pageUrl).href); } catch (err) { log.debug(`Scope check: ${(err as Error).message}`); return true; }
  });
  // Deduplicate forms by method+action to avoid testing the same search form from every page
  const formDedup = new Map<string, typeof rawForms[0]>();
  for (const form of rawForms) {
    const key = `${form.method}:${form.action}`;
    if (!formDedup.has(key)) formDedup.set(key, form);
  }
  const allForms = [...formDedup.values()];
  if (rawForms.length !== allForms.length) {
    log.info(`Form dedup: ${rawForms.length} → ${allForms.length} unique forms`);
  }
  const urlsWithParamsSet = new Set(scopedPages.map((p) => p.url).filter((u) => u.includes('?') && !isTrackingUrl(u)));
  const apiEndpointSet = new Set(scopedPages.map((p) => p.url).filter((u) => /\/api\//i.test(u)));
  const redirectUrls = scopedPages
    .flatMap((p) => p.links)
    .filter((l) => REDIRECT_PARAM_RE.test(l))
    .filter(inScope);

  // Extract API endpoints and parameterized URLs from intercepted network traffic
  if (interceptedResponses) {
    for (const resp of interceptedResponses) {
      try {
        if (!inScope(resp.url)) continue;
        if (STATIC_ASSET_RE.test(resp.url)) continue;

        const contentType = resp.headers['content-type'] ?? '';

        // API endpoint: URL matches API pattern or response is JSON/XML
        if (API_URL_PATTERN_RE.test(resp.url) || API_CONTENT_TYPE_RE.test(contentType)) {
          // Strip query params to get the base API endpoint
          const baseUrl = resp.url.split('?')[0];
          apiEndpointSet.add(baseUrl);
        }

        // URL with query parameters (discovered from network traffic)
        // Exclude tracking/analytics URLs — they waste XSS testing time
        if (resp.url.includes('?') && !STATIC_ASSET_RE.test(resp.url) && !isTrackingUrl(resp.url)) {
          urlsWithParamsSet.add(resp.url);
        }
      } catch {
        // Skip malformed URLs
      }
    }

    const networkApis = apiEndpointSet.size - scopedPages.map((p) => p.url).filter((u) => /\/api\//i.test(u)).length;
    const networkParams = urlsWithParamsSet.size - scopedPages.map((p) => p.url).filter((u) => u.includes('?')).length;
    if (networkApis > 0 || networkParams > 0) {
      log.info(`Network traffic discovery: +${networkApis} API endpoints, +${networkParams} parameterized URLs`);
    }
  }

  // Detect URLs with file-like parameters
  const fileParams: string[] = [];
  const allUrls = scopedPages.flatMap((p) => [p.url, ...p.links]).filter(inScope);
  for (const url of allUrls) {
    try {
      const parsed = new URL(url);
      for (const [key, value] of parsed.searchParams) {
        if (FILE_PARAM_NAMES.test(key) || isFileLikeValue(value)) {
          fileParams.push(url);
          break;
        }
      }
    } catch {
      // Skip invalid URLs
    }
  }

  return {
    pages: scopedPages.map((p) => p.url),
    forms: allForms,
    urlsWithParams: [...urlsWithParamsSet],
    apiEndpoints: [...apiEndpointSet],
    redirectUrls,
    fileParams: [...new Set(fileParams)],
  };
}

/** Result of running active checks — includes findings and an audit trail */
export interface ActiveCheckResult {
  findings: RawFinding[];
  audit: CheckAuditEntry[];
}

/**
 * Run active security checks.
 * If an attack plan is provided, only run recommended checks in priority order.
 * Otherwise, run all checks (except traversal on quick profile).
 *
 * Returns both findings and a per-check audit trail (status, duration, error).
 */
export async function runActiveChecks(
  context: BrowserContext,
  pages: CrawledPage[],
  config: ScanConfig,
  attackPlan?: AttackPlan,
  requestLogger?: RequestLogger,
  interceptedResponses?: Array<{ url: string; status: number; headers: Record<string, string> }>,
): Promise<ActiveCheckResult> {
  const audit: CheckAuditEntry[] = [];

  if (config.profile === 'quick' && !attackPlan) {
    log.info('Quick profile — skipping active checks');
    return { findings: [], audit };
  }

  const targets = buildTargets(pages, config.targetUrl, config.scope, interceptedResponses);
  const findings: RawFinding[] = [];

  // Create adaptive rate limiter — use per-domain limiter when rateLimits config is present
  const domainRateLimiter = config.rateLimits
    ? new DomainRateLimiter(config.rateLimits, { initialDelayMs: config.requestDelay })
    : undefined;
  const rateLimiter = domainRateLimiter
    ? domainRateLimiter.getLimiter(config.targetUrl)
    : new RateLimiter({
        requestsPerSecond: config.rateLimitRps,
        initialDelayMs: config.requestDelay,
      });

  if (domainRateLimiter) {
    log.info(`Using per-domain rate limiter (${domainRateLimiter.getPatterns().size} patterns, default ${domainRateLimiter.getDefaultRps()} rps)`);
  }

  let checksToRun: ActiveCheck[];

  // Build focusAreas map from attack plan (AI planner → per-check targeting)
  const focusAreasMap = new Map<string, string[]>();
  if (attackPlan) {
    for (const rec of attackPlan.recommendedChecks) {
      if (rec.focusAreas?.length) {
        focusAreasMap.set(rec.name, rec.focusAreas);
      }
    }
    if (focusAreasMap.size > 0) {
      log.info(`AI focus areas: ${[...focusAreasMap.entries()].map(([k, v]) => `${k}(${v.length})`).join(', ')}`);
    }
  }

  if (attackPlan) {
    // Run only recommended checks in priority order
    const sorted = [...attackPlan.recommendedChecks].sort((a, b) => a.priority - b.priority);
    checksToRun = sorted
      .map((rec) => CHECK_REGISTRY.find((c) => c.name === rec.name))
      .filter((c): c is ActiveCheck => c !== undefined);

    log.info(`Running ${checksToRun.length} AI-recommended checks: ${checksToRun.map((c) => c.name).join(', ')}`);
  } else {
    // Run all checks (skip traversal only on quick profile)
    checksToRun = CHECK_REGISTRY.filter((c) => {
      if (c.name === 'traversal' && config.profile === 'quick') return false;
      return true;
    });
    log.info(`Running ${checksToRun.length} active checks: ${checksToRun.map((c) => c.name).join(', ')}`);
  }

  // Apply --exclude-checks filter
  if (config.excludeChecks?.length) {
    const excludeSet = new Set(config.excludeChecks);
    const excluded = checksToRun.filter((c) => excludeSet.has(c.name));
    checksToRun = checksToRun.filter((c) => !excludeSet.has(c.name));

    if (excluded.length > 0) {
      log.info(`Excluded checks: ${excluded.map((c) => c.name).join(', ')}`);
      // Record skipped checks in audit
      for (const check of excluded) {
        audit.push({ name: check.name, status: 'skipped', findingsCount: 0, durationMs: 0 });
      }
    }

    // Warn about invalid exclude names (names that don't match any registered check)
    const validNames = new Set(CHECK_REGISTRY.map((c) => c.name));
    const invalidNames = config.excludeChecks.filter((name) => !validNames.has(name));
    if (invalidNames.length > 0) {
      log.warn(`Unknown check names in --exclude-checks (ignored): ${invalidNames.join(', ')}`);
    }
  }

  const { parallel, sequential } = splitChecksByParallelism(checksToRun);

  // Helper: create per-check config with AI focus areas threaded in
  const configForCheck = (checkName: string): ScanConfig => {
    const areas = focusAreasMap.get(checkName);
    if (!areas) return config;
    return { ...config, aiFocusAreas: areas };
  };

  // Helper: run a single check with audit tracking
  const runWithAudit = async (check: ActiveCheck): Promise<RawFinding[]> => {
    const startMs = Date.now();
    try {
      const result = await check.run(context, targets, configForCheck(check.name), requestLogger);
      audit.push({
        name: check.name,
        status: 'completed',
        findingsCount: result.length,
        durationMs: Date.now() - startMs,
      });
      return result;
    } catch (err) {
      const errorMsg = (err as Error).message;
      log.warn(`Active check "${check.name}" failed: ${errorMsg}`);
      audit.push({
        name: check.name,
        status: 'failed',
        findingsCount: 0,
        durationMs: Date.now() - startMs,
        error: errorMsg,
      });
      return [];
    }
  };

  // Phase A: Run parallel checks concurrently (read-only, no state mutation)
  if (parallel.length > 0) {
    log.info(`Running ${parallel.length} checks in parallel: ${parallel.map((c) => c.name).join(', ')}`);
    const parallelResults = await Promise.allSettled(
      parallel.map(async (check) => runWithAudit(check)),
    );
    for (const result of parallelResults) {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      }
    }
  }

  // Phase B: Run sequential checks one-by-one (inject payloads, may trigger WAF)
  if (sequential.length > 0) {
    log.info(`Running ${sequential.length} checks sequentially: ${sequential.map((c) => c.name).join(', ')}`);
    for (let i = 0; i < sequential.length; i++) {
      const check = sequential[i];
      if (i > 0) {
        await rateLimiter.acquire();
      }
      const checkFindings = await runWithAudit(check);
      findings.push(...checkFindings);
    }
  }

  // Log rate limiter stats
  const stats = rateLimiter.getStats();
  log.info(`Rate limiter: ${stats.totalRequests} inter-check delays, ${stats.backoffs} backoffs, final delay ${stats.currentDelayMs}ms`);

  // Warn if majority of checks failed — scan results may be incomplete
  const failedCount = audit.filter((a) => a.status === 'failed').length;
  const totalAttempted = audit.filter((a) => a.status !== 'skipped').length;
  if (totalAttempted > 0 && failedCount > totalAttempted * 0.5) {
    log.error(
      `WARNING: ${failedCount}/${totalAttempted} active checks failed (>${Math.round((failedCount / totalAttempted) * 100)}%). ` +
      `Scan results may be incomplete — browser crash or target instability suspected. ` +
      `Failed: ${audit.filter((a) => a.status === 'failed').map((a) => a.name).join(', ')}`,
    );
  }

  log.info(`Active scan: ${findings.length} raw findings (${audit.filter((a) => a.status === 'completed').length} completed, ${failedCount} failed, ${audit.filter((a) => a.status === 'skipped').length} skipped)`);
  return { findings, audit };
}

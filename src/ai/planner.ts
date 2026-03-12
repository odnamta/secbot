import type { ReconResult, CrawledPage, AttackPlan, ScanProfile } from '../scanner/types.js';
import type { PayloadContext } from '../utils/payload-context.js';
import type { LearningContext } from '../learning/types.js';
import { askClaude, parseJsonResponse } from './client.js';
import { buildPlannerPrompt, buildPlannerUserPrompt, ALL_PLANNER_CHECKS } from './prompts.js';
import type { PlannerCheckType } from './prompts.js';
import { log } from '../utils/logger.js';
import { AICache } from '../utils/ai-cache.js';

const aiCache = new AICache();

/**
 * Determine which check types are relevant based on discovered targets.
 * This avoids sending irrelevant check descriptions to the AI planner,
 * saving tokens.
 */
export function determineRelevantChecks(
  url: string,
  recon: ReconResult,
  pages: CrawledPage[],
): PlannerCheckType[] {
  const relevant: PlannerCheckType[] = [];

  const allForms = pages.flatMap((p) => p.forms);
  const urlsWithParams = pages.map((p) => p.url).filter((u) => u.includes('?'));
  const redirectParams = pages.flatMap((p) => p.links).filter((l) =>
    /[?&](url|redirect|next|return|goto|dest)=/i.test(l),
  );
  const urlAcceptingParams = allForms.filter((f) =>
    f.inputs.some((i) => /url|link|src|image|proxy/i.test(i.name)),
  );
  const numericIdUrls = recon.endpoints.apiRoutes.filter((r) => /\/\d+/.test(r));
  const apiEndpoints = pages.map((p) => p.url).filter((u) => /\/api\//i.test(u));
  const isHttps = url.startsWith('https://');
  const hasTemplateEngine = recon.techStack.detected.some(
    (t: string) => /jinja|django|flask|express|ejs|pug/i.test(t),
  );

  // CORS — always relevant (low cost, high value)
  relevant.push('cors');

  // XSS — needs forms or URL params
  if (allForms.length > 0 || urlsWithParams.length > 0) {
    relevant.push('xss');
  }

  // SQLi — needs forms or URL params
  if (allForms.length > 0 || urlsWithParams.length > 0) {
    relevant.push('sqli');
  }

  // Redirect — needs redirect params
  if (redirectParams.length > 0) {
    relevant.push('redirect');
  }

  // Traversal — needs API endpoints or file-like params
  if (apiEndpoints.length > 0 || urlsWithParams.length > 0) {
    relevant.push('traversal');
  }

  // SSRF — needs URL-accepting params or API routes
  if (urlAcceptingParams.length > 0 || apiEndpoints.length > 0 || urlsWithParams.length > 0) {
    relevant.push('ssrf');
  }

  // SSTI — needs template engine or forms
  if (hasTemplateEngine || allForms.length > 0) {
    relevant.push('ssti');
  }

  // CMDi — needs API routes or forms
  if (apiEndpoints.length > 0 || allForms.length > 0) {
    relevant.push('cmdi');
  }

  // IDOR — needs sequential IDs in API routes
  if (numericIdUrls.length > 0) {
    relevant.push('idor');
  }

  // TLS — only for HTTPS targets
  if (isHttps) {
    relevant.push('tls');
  }

  // SRI — needs crawled pages (external scripts/stylesheets)
  if (pages.length > 0) {
    relevant.push('sri');
  }

  // ─── New check types (v0.12+) ──────────────────────────────────────

  // Rate limit — relevant when forms or API endpoints exist (login, signup, API)
  if (allForms.length > 0 || apiEndpoints.length > 0) {
    relevant.push('rate-limit');
  }

  // JWT — relevant when JWT-like tokens detected in cookies or page scripts
  const hasJwtLikeTokens = pages.some((p) =>
    p.cookies.some((c) => /eyJ[a-zA-Z0-9_-]+\.eyJ/i.test(c.value ?? '')) ||
    p.scripts.some((s) => /localStorage|sessionStorage|jwt|token/i.test(s)),
  );
  if (hasJwtLikeTokens || apiEndpoints.length > 0) {
    relevant.push('jwt');
  }

  // Race condition — relevant when state-changing forms exist
  const hasStateChangingForms = allForms.some((f) =>
    f.method?.toLowerCase() === 'post' ||
    f.inputs.some((i) => /checkout|transfer|submit|vote|coupon|redeem/i.test(i.name)),
  );
  if (hasStateChangingForms || apiEndpoints.length > 0) {
    relevant.push('race');
  }

  // GraphQL — relevant when /graphql endpoint found
  if (recon.endpoints.graphql.length > 0) {
    relevant.push('graphql');
  }

  // Host header — always relevant (low cost)
  relevant.push('host-header');

  // File upload — relevant when forms have file inputs
  const hasFileInputs = allForms.some((f) => f.inputs.some((i) => i.type === 'file'));
  if (hasFileInputs) {
    relevant.push('file-upload');
  }

  // Broken access control — relevant when admin-like URLs detected
  const allUrls = [...recon.endpoints.pages, ...recon.endpoints.apiRoutes];
  const hasAdminUrls = allUrls.some((u) =>
    /\/(admin|dashboard|manage|panel|settings|console)/i.test(u),
  );
  if (hasAdminUrls) {
    relevant.push('access-control');
  }

  // Business logic — relevant when business-like form fields detected
  const hasBusinessFields = allForms.some((f) =>
    f.inputs.some((i) => /price|quantity|amount|total|discount|coupon|qty/i.test(i.name)),
  );
  if (hasBusinessFields || apiEndpoints.length > 0) {
    relevant.push('business-logic');
  }

  // WebSocket — relevant when socket.io or ws:// URLs found
  const hasWebSocket = pages.some((p) =>
    p.scripts.some((s) => /socket\.io|ws:\/\/|wss:\/\//i.test(s)) ||
    p.links.some((l) => /ws:\/\/|wss:\/\//i.test(l)),
  );
  if (hasWebSocket) {
    relevant.push('websocket');
  }

  // API versioning — relevant when /api/v{N}/ patterns found
  const hasApiVersioning = recon.endpoints.apiRoutes.some((r) => /\/api\/v\d+/i.test(r));
  if (hasApiVersioning) {
    relevant.push('api-version');
  }

  // Info disclosure — always relevant (low cost, high value)
  relevant.push('info-disclosure');

  // JS CVE — relevant when pages have been crawled (JS libraries on pages)
  if (pages.length > 0) {
    relevant.push('js-cve');
  }

  // CRLF injection — relevant when URL params or form inputs exist
  if (urlsWithParams.length > 0 || allForms.length > 0) {
    relevant.push('crlf');
  }

  // Subdomain takeover — always include (check reads subdomainResults from config;
  // if none are present the check returns early with 0 findings)
  relevant.push('subdomain-takeover');

  // OAuth — relevant when OAuth-related URLs detected
  const allPageUrls = pages.flatMap((p) => [p.url, ...p.links]);
  const oauthPatterns = [/\/oauth\//i, /\/authorize/i, /\/auth\/callback/i, /\/login\/oauth/i,
    /\/api\/auth/i, /\/connect\/authorize/i, /\.well-known\/openid/i, /\/token$/i, /\/oauth2\//i];
  const hasOAuthEndpoints = allPageUrls.some((u) => oauthPatterns.some((p) => p.test(u))) ||
    recon.endpoints.apiRoutes.some((r) => oauthPatterns.some((p) => p.test(r)));
  if (hasOAuthEndpoints) {
    relevant.push('oauth');
  }

  // Cache poisoning — relevant when pages have been crawled
  // (caching is common on any deployed web app; the check detects caching headers on the fly)
  if (pages.length > 0) {
    relevant.push('cache-poisoning');
  }

  return relevant;
}

/**
 * Use AI to plan which active checks to run based on reconnaissance.
 * Falls back to a default plan (all checks) if AI is unavailable.
 */
export async function planAttack(
  url: string,
  recon: ReconResult,
  pages: CrawledPage[],
  profile: ScanProfile,
  payloadContext?: PayloadContext,
  learningContext?: LearningContext,
): Promise<AttackPlan> {
  log.info('AI planning attack strategy...');

  const relevantChecks = determineRelevantChecks(url, recon, pages);
  log.info(`Relevant checks for target: ${relevantChecks.join(', ')} (${relevantChecks.length}/${ALL_PLANNER_CHECKS.length})`);

  // Check AI response cache before making an API call
  const reconHash = aiCache.generateKey({ recon });
  const cacheKey = aiCache.generateKey({ targetUrl: url, reconHash, profile });
  const cached = await aiCache.get(cacheKey);

  if (cached) {
    const parsed = parseJsonResponse<AttackPlan>(cached);
    if (parsed?.recommendedChecks) {
      log.info('Using cached attack plan');
      return parsed;
    }
  }

  const systemPrompt = buildPlannerPrompt(relevantChecks);
  const userPrompt = buildPlannerUserPrompt(url, recon, pages, profile, payloadContext);
  const response = await askClaude(systemPrompt, userPrompt);

  if (response) {
    const parsed = parseJsonResponse<AttackPlan>(response);
    if (parsed?.recommendedChecks) {
      log.info(
        `AI plan: ${parsed.recommendedChecks.length} checks recommended` +
        (Object.keys(parsed.skipReasons ?? {}).length > 0
          ? `, ${Object.keys(parsed.skipReasons).length} skipped`
          : ''),
      );
      // Cache the raw response for future runs
      await aiCache.set(cacheKey, response);
      return parsed;
    }
    log.warn('AI planner returned invalid JSON — using default plan');
  } else {
    log.info('AI unavailable — using default attack plan');
  }

  return buildDefaultPlan(recon, pages, profile, learningContext);
}

function buildDefaultPlan(
  recon: ReconResult,
  pages: CrawledPage[],
  profile: ScanProfile,
  learningContext?: LearningContext,
): AttackPlan {
  const allForms = pages.flatMap((p) => p.forms);
  const urlsWithParams = pages.map((p) => p.url).filter((u) => u.includes('?'));
  const redirectUrls = pages.flatMap((p) => p.links).filter((l) =>
    /[?&](url|redirect|next|return|goto|dest)=/i.test(l),
  );
  const apiEndpoints = pages.map((p) => p.url).filter((u) => /\/api\//i.test(u));
  const targetUrl = recon.endpoints.pages[0] ?? '';

  const checks: AttackPlan['recommendedChecks'] = [];
  const skipReasons: Record<string, string> = {};
  let priority = 1;

  // CORS is always worth checking (low cost)
  checks.push({
    name: 'cors',
    priority: priority++,
    reason: 'Low-cost check with high-value findings',
  });

  // TLS: always on HTTPS targets
  if (targetUrl.startsWith('https://')) {
    checks.push({
      name: 'tls',
      priority: priority++,
      reason: 'HTTPS target — verify TLS configuration',
    });
  } else {
    skipReasons['tls'] = 'Not an HTTPS target';
  }

  // SRI: always check when pages have been crawled
  if (pages.length > 0) {
    checks.push({
      name: 'sri',
      priority: priority++,
      reason: 'Check external resources for subresource integrity',
    });
  } else {
    skipReasons['sri'] = 'No pages crawled';
  }

  // XSS if forms or URL params exist
  if (allForms.length > 0 || urlsWithParams.length > 0) {
    checks.push({
      name: 'xss',
      priority: priority++,
      reason: `${allForms.length} forms, ${urlsWithParams.length} parameterized URLs`,
    });
  } else {
    skipReasons['xss'] = 'No forms or parameterized URLs found';
  }

  // SQLi if forms exist
  if (allForms.length > 0) {
    checks.push({
      name: 'sqli',
      priority: priority++,
      reason: `${allForms.length} forms to test`,
    });
  } else {
    skipReasons['sqli'] = 'No forms found';
  }

  // Open redirect if redirect params exist
  if (redirectUrls.length > 0) {
    checks.push({
      name: 'redirect',
      priority: priority++,
      reason: `${redirectUrls.length} URLs with redirect parameters`,
    });
  } else {
    skipReasons['redirect'] = 'No redirect parameters found';
  }

  // SSRF: when URL-accepting parameters exist
  if (allForms.some((f) => f.inputs.some((i) => /url|link|src|image|proxy/i.test(i.name)))
      || apiEndpoints.length > 0) {
    checks.push({
      name: 'ssrf',
      priority: priority++,
      reason: 'URL-accepting parameters or API routes detected',
    });
  } else {
    skipReasons['ssrf'] = 'No URL-accepting parameters or API routes found';
  }

  // SSTI: when template engine detected or forms exist
  if (recon.techStack.detected.some((t: string) => /jinja|django|flask|express|ejs|pug/i.test(t))
      || allForms.length > 0) {
    checks.push({
      name: 'ssti',
      priority: priority++,
      reason: 'Template engine detected or forms available for injection testing',
    });
  } else {
    skipReasons['ssti'] = 'No template engine detected and no forms found';
  }

  // Command injection: when API routes or forms exist
  if (apiEndpoints.length > 0 || allForms.length > 0) {
    checks.push({
      name: 'cmdi',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints, ${allForms.length} forms for command injection testing`,
    });
  } else {
    skipReasons['cmdi'] = 'No API endpoints or forms found';
  }

  // IDOR: when sequential IDs in URLs
  if (recon.endpoints.apiRoutes.some((r: string) => /\/\d+/.test(r))) {
    checks.push({
      name: 'idor',
      priority: priority++,
      reason: 'Sequential numeric IDs detected in API routes',
    });
  } else {
    skipReasons['idor'] = 'No sequential numeric IDs found in URLs';
  }

  // Directory traversal on deep profile with API endpoints
  if (profile === 'deep' && apiEndpoints.length > 0) {
    checks.push({
      name: 'traversal',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints (deep profile)`,
    });
  } else if (apiEndpoints.length === 0) {
    skipReasons['traversal'] = 'No API endpoints found';
  } else {
    skipReasons['traversal'] = 'Only run in deep profile';
  }

  // ─── New check types (v0.12+) ──────────────────────────────────────

  // Rate limit: when forms or API endpoints exist
  if (allForms.length > 0 || apiEndpoints.length > 0) {
    checks.push({
      name: 'rate-limit',
      priority: priority++,
      reason: `${allForms.length} forms, ${apiEndpoints.length} API endpoints for brute-force testing`,
    });
  } else {
    skipReasons['rate-limit'] = 'No forms or API endpoints found';
  }

  // JWT: when API endpoints exist (JWT common with APIs)
  if (apiEndpoints.length > 0) {
    checks.push({
      name: 'jwt',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints — check JWT security`,
    });
  } else {
    skipReasons['jwt'] = 'No API endpoints found';
  }

  // Race condition: when state-changing forms or API endpoints exist
  if (allForms.length > 0 || apiEndpoints.length > 0) {
    checks.push({
      name: 'race',
      priority: priority++,
      reason: `${allForms.length} forms, ${apiEndpoints.length} API endpoints for race condition testing`,
    });
  } else {
    skipReasons['race'] = 'No forms or API endpoints found';
  }

  // GraphQL: when /graphql endpoints discovered
  if (recon.endpoints.graphql.length > 0) {
    checks.push({
      name: 'graphql',
      priority: priority++,
      reason: `${recon.endpoints.graphql.length} GraphQL endpoint(s) discovered`,
    });
  } else {
    skipReasons['graphql'] = 'No GraphQL endpoints found';
  }

  // Host header: always worth checking (low cost)
  checks.push({
    name: 'host-header',
    priority: priority++,
    reason: 'Low-cost check for host header injection',
  });

  // File upload: when file inputs exist in forms
  const hasFileInputs = allForms.some((f) => f.inputs.some((i) => i.type === 'file'));
  if (hasFileInputs) {
    checks.push({
      name: 'file-upload',
      priority: priority++,
      reason: 'File upload forms detected',
    });
  } else {
    skipReasons['file-upload'] = 'No file upload forms found';
  }

  // Broken access control: when admin-like URLs detected
  const allDiscoveredUrls = [...recon.endpoints.pages, ...recon.endpoints.apiRoutes];
  const hasAdminUrls = allDiscoveredUrls.some((u) =>
    /\/(admin|dashboard|manage|panel|settings|console)/i.test(u),
  );
  if (hasAdminUrls) {
    checks.push({
      name: 'access-control',
      priority: priority++,
      reason: 'Admin-like URLs detected — test access control',
    });
  } else {
    skipReasons['access-control'] = 'No admin-like URLs found';
  }

  // Business logic: when business-like form fields detected
  const hasBusinessFields = allForms.some((f) =>
    f.inputs.some((i) => /price|quantity|amount|total|discount|coupon|qty/i.test(i.name)),
  );
  if (hasBusinessFields) {
    checks.push({
      name: 'business-logic',
      priority: priority++,
      reason: 'Business logic form fields detected (price, quantity, etc.)',
    });
  } else {
    skipReasons['business-logic'] = 'No business logic form fields found';
  }

  // WebSocket: when socket.io or ws:// references found
  // Note: pages is not directly available in buildDefaultPlan, so we check recon endpoints
  skipReasons['websocket'] = 'WebSocket detection requires crawled page analysis';

  // API versioning: when /api/v{N}/ patterns found
  const hasApiVersioning = recon.endpoints.apiRoutes.some((r) => /\/api\/v\d+/i.test(r));
  if (hasApiVersioning) {
    checks.push({
      name: 'api-version',
      priority: priority++,
      reason: 'API versioned routes detected — probe older versions',
    });
  } else {
    skipReasons['api-version'] = 'No versioned API routes found';
  }

  // Info disclosure: always relevant (low cost, high value)
  checks.push({
    name: 'info-disclosure',
    priority: priority++,
    reason: 'Low-cost probe for exposed .git, .env, source maps, debug endpoints',
  });

  // JS CVE: when pages have been crawled
  if (pages.length > 0) {
    checks.push({
      name: 'js-cve',
      priority: priority++,
      reason: 'Scan client-side JS libraries for known CVEs',
    });
  } else {
    skipReasons['js-cve'] = 'No pages crawled';
  }

  // CRLF injection: when URL params or form inputs exist
  if (urlsWithParams.length > 0 || allForms.length > 0) {
    checks.push({
      name: 'crlf',
      priority: priority++,
      reason: `${urlsWithParams.length} parameterized URLs, ${allForms.length} forms for CRLF testing`,
    });
  } else {
    skipReasons['crlf'] = 'No URL parameters or forms found';
  }

  // OAuth: when OAuth-related endpoints detected
  const oauthPatterns = [/\/oauth\//i, /\/authorize/i, /\/auth\/callback/i, /\/login\/oauth/i,
    /\/api\/auth/i, /\/connect\/authorize/i, /\.well-known\/openid/i, /\/token$/i, /\/oauth2\//i];
  const hasOAuthEndpoints = recon.endpoints.apiRoutes.some((r) =>
    oauthPatterns.some((p) => p.test(r)),
  ) || recon.endpoints.pages.some((r) =>
    oauthPatterns.some((p) => p.test(r)),
  );
  if (hasOAuthEndpoints) {
    checks.push({
      name: 'oauth',
      priority: priority++,
      reason: 'OAuth endpoints detected — test for missing state, redirect_uri bypass, token leakage',
    });
  } else {
    skipReasons['oauth'] = 'No OAuth endpoints detected';
  }

  // Cache poisoning: when pages have been crawled (check detects caching on the fly)
  if (pages.length > 0) {
    checks.push({
      name: 'cache-poisoning',
      priority: priority++,
      reason: 'Test unkeyed HTTP headers for cache poisoning via reflected values',
    });
  } else {
    skipReasons['cache-poisoning'] = 'No pages crawled';
  }

  // ─── Learning-based reordering (v1.0) ───────────────────────────────
  if (learningContext?.techProfile) {
    const { prioritize, deprioritize } = learningContext.techProfile;
    for (const check of checks) {
      if (prioritize.includes(check.name)) {
        check.priority = Math.max(1, check.priority - 5);
        check.reason += ' [learning: historically effective]';
      }
      if (deprioritize.includes(check.name)) {
        check.priority += 10;
        check.reason += ' [learning: historically ineffective]';
      }
    }
    checks.sort((a, b) => a.priority - b.priority);
    log.info(`Learning context applied: prioritize=[${prioritize.join(',')}], deprioritize=[${deprioritize.join(',')}]`);
  }

  // Limit by profile
  const maxChecks = profile === 'quick' ? 3 : profile === 'standard' ? 6 : checks.length;
  const limited = checks.slice(0, maxChecks);

  return {
    recommendedChecks: limited,
    reasoning: `Default plan: ${limited.length} checks based on available targets` +
      (learningContext?.techProfile ? ' (adjusted by learning data)' : ''),
    skipReasons,
  };
}

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
  interceptedResponses?: Array<{ url: string; status: number; headers: Record<string, string> }>,
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

  // Also count API endpoints discovered from network traffic (XHR/fetch)
  if (interceptedResponses) {
    const targetHost = new URL(url).hostname;
    const staticRe = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp)(\?|$)/i;
    const apiRe = /\/api\/|\/graphql|\/v[0-9]+\/|\/rest\/|\/rpc\//i;
    const jsonRe = /application\/json/i;
    for (const resp of interceptedResponses) {
      try {
        const respHost = new URL(resp.url).hostname;
        if (respHost !== targetHost) continue;
        if (staticRe.test(resp.url)) continue;
        const ct = resp.headers['content-type'] ?? '';
        if (apiRe.test(resp.url) || jsonRe.test(ct)) {
          apiEndpoints.push(resp.url.split('?')[0]);
        }
        if (resp.url.includes('?') && !staticRe.test(resp.url)) {
          urlsWithParams.push(resp.url);
        }
      } catch { /* skip */ }
    }
  }
  const isHttps = url.startsWith('https://');
  const hasTemplateEngine = recon.techStack.detected.some(
    (t: string) => /jinja|django|flask|express|ejs|pug/i.test(t),
  );

  // CORS — always relevant (low cost, high value)
  relevant.push('cors');

  // XSS — always relevant when pages exist (DOM XSS + paramless probing work without forms/params)
  if (pages.length > 0 || allForms.length > 0 || urlsWithParams.length > 0) {
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

  // SSTI — needs template engine, forms, or URL params with template-suggestive names
  const hasTemplateParams = urlsWithParams.some((u) => {
    try {
      return [...new URL(u).searchParams.keys()].some((k) =>
        /^(template|name|view|page|render|layout|theme|skin|tpl|lang|locale|msg|text|content|title|subject|body|greeting|message|format|display)$/i.test(k),
      );
    } catch { return false; }
  });
  if (hasTemplateEngine || allForms.length > 0 || hasTemplateParams) {
    relevant.push('ssti');
  }

  // CMDi — needs API routes, forms, or URLs with query params
  if (apiEndpoints.length > 0 || allForms.length > 0 || urlsWithParams.length > 0) {
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
    f.inputs.some((i) => /price|quantity|amount|total|discount|coupon|qty|cost|fee|charge|value|units|count|items|stock|wallet|credit|balance|payment/i.test(i.name)),
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

  // CSRF — relevant when state-changing forms or API endpoints exist
  const hasPostForms = allForms.some((f) =>
    /^(post|put|patch|delete)$/i.test(f.method ?? 'get'),
  );
  if (hasPostForms || apiEndpoints.length > 0) {
    relevant.push('csrf');
  }

  // Prototype pollution — relevant when Node.js/Express detected, API endpoints, or URL params exist
  const isNodeAppRelevant = recon.techStack.detected.some((t: string) =>
    /node|express|next\.?js|nuxt|koa|fastify|hapi|nestjs/i.test(t),
  );
  if (isNodeAppRelevant || apiEndpoints.length > 0 || urlsWithParams.length > 0) {
    relevant.push('prototype-pollution');
  }

  // XXE — relevant when API endpoints exist (especially SOAP, XML-RPC, or any POST endpoint)
  if (apiEndpoints.length > 0 || allForms.length > 0) {
    relevant.push('xxe');
  }

  // Insecure deserialization — relevant when API endpoints, SOAP/RPC, or backend tech detected
  const hasDeserializationRisk = recon.techStack.detected.some((t: string) =>
    /java|spring|tomcat|php|laravel|symfony|python|django|flask|\.net|asp\.net|ruby|rails/i.test(t),
  );
  if (apiEndpoints.length > 0 || hasDeserializationRisk || hasPostForms) {
    relevant.push('insecure-deserialization');
  }

  // Request smuggling — relevant for most production apps (they sit behind proxies/CDNs)
  // Detect proxy indicators from intercepted responses
  const hasProxyIndicators = interceptedResponses?.some((r) => {
    const h = r.headers;
    return h['x-cache'] || h['cf-cache-status'] || h['x-varnish'] || h['via'] ||
      h['x-served-by'] || h['x-amz-cf-id'] || h['x-cdn'] || h['server']?.includes('cloudflare');
  }) ?? false;
  if (hasProxyIndicators || pages.length > 0) {
    relevant.push('request-smuggling');
  }

  // LDAP injection — relevant when login forms or LDAP-related param names exist
  const ldapParamRe = /^(username|user|uid|cn|sn|dn|login|name|search|query|q|filter|account|email|samaccountname)$/i;
  const hasLdapParams = urlsWithParams.some((u) => {
    try { return [...new URL(u).searchParams.keys()].some((k) => ldapParamRe.test(k)); } catch { return false; }
  });
  const hasLoginForms = allForms.some((f) =>
    f.inputs.some((i) => ldapParamRe.test(i.name ?? '')),
  );
  if (hasLdapParams || hasLoginForms) {
    relevant.push('ldap-injection');
  }

  // Content-type confusion — relevant when state-changing POST forms exist
  const ctConfusionRe = /\/(login|signup|register|checkout|transfer|payment|settings|profile|password|delete|update|create|submit|feedback|contact|comment|review|order|cart|subscribe|send|confirm|approve|reject|cancel|publish|upload|invite|reset|change|save|edit)/i;
  const hasCtTargetForms = allForms.some((f) =>
    /^(post|put|patch)$/i.test(f.method ?? 'get') &&
    (ctConfusionRe.test(f.action) || ctConfusionRe.test(f.pageUrl ?? '')),
  );
  if (hasCtTargetForms || apiEndpoints.length > 0) {
    relevant.push('content-type-confusion');
  }

  // Method override — relevant when API endpoints or sensitive paths exist
  const sensitiveEndpointRe = /\/(user|profile|account|admin|settings|api|resource|item|record|data|session)\b/i;
  const hasSensitiveEndpoints = apiEndpoints.length > 0 ||
    [...recon.endpoints.pages, ...recon.endpoints.apiRoutes].some((u) => sensitiveEndpointRe.test(u));
  if (hasSensitiveEndpoints) {
    relevant.push('method-override');
  }

  // Email injection — relevant when contact/feedback/support forms detected
  const emailFormRe = /\/(contact|feedback|support|help|enquiry|inquiry|message|send-?mail|mail|email|subscribe|newsletter|invite|referral|share|report|notify)/i;
  const hasEmailForms = allForms.some((f) =>
    /^post$/i.test(f.method ?? 'get') &&
    (emailFormRe.test(f.action) || emailFormRe.test(f.pageUrl ?? '')) &&
    f.inputs.some((i) => /^(email|e-?mail|from|subject|message|body|content)$/i.test(i.name ?? '')),
  );
  if (hasEmailForms) {
    relevant.push('email-injection');
  }

  // BFLA — relevant when API endpoints exist (function enumeration needs API paths)
  if (apiEndpoints.length > 0 || recon.endpoints.apiRoutes.length > 0) {
    relevant.push('bfla');
  }

  // Clickjacking — relevant when pages exist (tests if pages can be framed)
  if (pages.length > 0) {
    relevant.push('clickjacking');
  }

  // Timing attack — relevant when login forms or auth endpoints exist
  const hasAuthEndpoints = pages.some((p) =>
    /\/(login|signin|auth|authenticate|forgot|reset|recover|password)/i.test(p.url),
  );
  const hasPasswordFields = pages.some((p) =>
    p.forms.some((f) => f.inputs.some((i) => i.type === 'password')),
  );
  if (hasAuthEndpoints || hasPasswordFields) {
    relevant.push('timing-attack');
  }

  // Verbose errors — always relevant (every app can have error handling issues)
  if (pages.length > 0) {
    relevant.push('verbose-errors');
  }

  // XPath injection — relevant when parameterized URLs or forms exist
  if (urlsWithParams.length > 0 || allForms.length > 0) {
    relevant.push('xpath-injection');
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
  interceptedResponses?: Array<{ url: string; status: number; headers: Record<string, string> }>,
): Promise<AttackPlan> {
  log.info('AI planning attack strategy...');

  const relevantChecks = determineRelevantChecks(url, recon, pages, interceptedResponses);
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
  const userPrompt = buildPlannerUserPrompt(url, recon, pages, profile, payloadContext, learningContext);
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
    log.warn('AI unavailable — using rule-based attack plan (set ANTHROPIC_API_KEY for AI-powered planning)');
  }

  return buildDefaultPlan(recon, pages, profile, learningContext);
}

export function buildDefaultPlan(
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

  // XSS — always run when pages exist (DOM XSS + paramless probing work without forms/params)
  if (pages.length > 0 || allForms.length > 0 || urlsWithParams.length > 0) {
    checks.push({
      name: 'xss',
      priority: priority++,
      reason: `${pages.length} pages, ${allForms.length} forms, ${urlsWithParams.length} parameterized URLs`,
    });
  } else {
    skipReasons['xss'] = 'No pages, forms, or parameterized URLs found';
  }

  // SQLi if forms or URL params exist
  if (allForms.length > 0 || urlsWithParams.length > 0) {
    checks.push({
      name: 'sqli',
      priority: priority++,
      reason: `${allForms.length} forms, ${urlsWithParams.length} parameterized URLs`,
    });
  } else {
    skipReasons['sqli'] = 'No forms or parameterized URLs found';
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

  // SSTI: when template engine detected, forms exist, or template-suggestive URL params found
  const hasTemplateParamsDefault = urlsWithParams.some((u) => {
    try {
      return [...new URL(u).searchParams.keys()].some((k) =>
        /^(template|name|view|page|render|layout|theme|skin|tpl|lang|locale|msg|text|content|title|subject|body|greeting|message|format|display)$/i.test(k),
      );
    } catch { return false; }
  });
  if (recon.techStack.detected.some((t: string) => /jinja|django|flask|express|ejs|pug/i.test(t))
      || allForms.length > 0 || hasTemplateParamsDefault) {
    checks.push({
      name: 'ssti',
      priority: priority++,
      reason: `Template ${hasTemplateParamsDefault ? 'params' : recon.techStack.detected.length > 0 ? 'engine' : 'forms'} detected`,
    });
  } else {
    skipReasons['ssti'] = 'No template engine, forms, or template-suggestive params found';
  }

  // Command injection: when API routes, forms, or URL params exist
  if (apiEndpoints.length > 0 || allForms.length > 0 || urlsWithParams.length > 0) {
    checks.push({
      name: 'cmdi',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints, ${allForms.length} forms, ${urlsWithParams.length} parameterized URLs`,
    });
  } else {
    skipReasons['cmdi'] = 'No API endpoints, forms, or parameterized URLs found';
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

  // Directory traversal when API endpoints, parameterized URLs, or file-like paths exist
  const hasFilePaths = pages.some((p) =>
    /\/(files?|assets?|images?|uploads?|downloads?|documents?|media|static|attachments?|storage)\//i.test(p.url),
  );
  if (apiEndpoints.length > 0 || urlsWithParams.length > 0 || hasFilePaths) {
    checks.push({
      name: 'traversal',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints, ${urlsWithParams.length} parameterized URLs${hasFilePaths ? ', file-like paths' : ''}`,
    });
  } else {
    skipReasons['traversal'] = 'No API endpoints, parameterized URLs, or file-like paths found';
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

  // JWT: when API endpoints exist or JWT-like tokens detected in cookies
  const hasJwtCookies = pages.some((p) =>
    p.cookies.some((c) => /eyJ[a-zA-Z0-9_-]+\.eyJ/i.test(c.value ?? '')),
  );
  if (apiEndpoints.length > 0 || hasJwtCookies) {
    checks.push({
      name: 'jwt',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints${hasJwtCookies ? ' + JWT cookies detected' : ''} — check JWT security`,
    });
  } else {
    skipReasons['jwt'] = 'No API endpoints or JWT tokens found';
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

  // Business logic: when business-like form fields or API endpoints detected
  const hasBusinessFieldsDefault = allForms.some((f) =>
    f.inputs.some((i) => /price|quantity|amount|total|discount|coupon|qty|cost|fee|charge|value|units|count|items|stock|wallet|credit|balance|payment/i.test(i.name)),
  );
  if (hasBusinessFieldsDefault || apiEndpoints.length > 0) {
    checks.push({
      name: 'business-logic',
      priority: priority++,
      reason: `Business logic ${hasBusinessFieldsDefault ? 'form fields' : 'API endpoints'} detected`,
    });
  } else {
    skipReasons['business-logic'] = 'No business logic form fields or API endpoints found';
  }

  // WebSocket: when socket.io or ws:// references found in pages
  const hasWebSocketDefault = pages.some((p) =>
    p.scripts.some((s) => /socket\.io|ws:\/\/|wss:\/\//i.test(s)) ||
    p.links.some((l) => /ws:\/\/|wss:\/\//i.test(l)),
  );
  if (hasWebSocketDefault) {
    checks.push({
      name: 'websocket',
      priority: priority++,
      reason: 'WebSocket references found in page scripts/links',
    });
  } else {
    skipReasons['websocket'] = 'No WebSocket references found';
  }

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

  // CSRF: when state-changing forms or API endpoints exist
  const hasPostFormsDefault = allForms.some((f) =>
    /^(post|put|patch|delete)$/i.test(f.method ?? 'get'),
  );
  if (hasPostFormsDefault || apiEndpoints.length > 0) {
    checks.push({
      name: 'csrf',
      priority: priority++,
      reason: `${allForms.filter((f) => /^(post|put|patch|delete)$/i.test(f.method ?? 'get')).length} POST forms, ${apiEndpoints.length} API endpoints`,
    });
  } else {
    skipReasons['csrf'] = 'No POST forms or API endpoints found';
  }

  // Prototype pollution: when Node.js/Express detected, API endpoints, or URL params exist
  const isNodeAppDefault = recon.techStack.detected.some((t: string) =>
    /node|express|next\.?js|nuxt|koa|fastify|hapi|nestjs/i.test(t),
  );
  if (isNodeAppDefault || apiEndpoints.length > 0 || urlsWithParams.length > 0) {
    checks.push({
      name: 'prototype-pollution',
      priority: priority++,
      reason: `${isNodeAppDefault ? 'Node.js detected' : apiEndpoints.length > 0 ? `${apiEndpoints.length} API endpoints` : 'URL params'} — test for __proto__/constructor.prototype injection`,
    });
  } else {
    skipReasons['prototype-pollution'] = 'No Node.js framework, API endpoints, or URL params detected';
  }

  // XXE: when API endpoints or forms exist (any POST endpoint might accept XML)
  if (apiEndpoints.length > 0 || allForms.length > 0) {
    checks.push({
      name: 'xxe',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints, ${allForms.length} forms — test XML entity injection`,
    });
  } else {
    skipReasons['xxe'] = 'No API endpoints or forms detected';
  }

  // Insecure deserialization: when API endpoints, POST forms, or backend tech detected
  const hasDeserializationRiskDefault = recon.techStack.detected.some((t: string) =>
    /java|spring|tomcat|php|laravel|symfony|python|django|flask|\.net|asp\.net|ruby|rails/i.test(t),
  );
  if (apiEndpoints.length > 0 || hasDeserializationRiskDefault || hasPostFormsDefault) {
    checks.push({
      name: 'insecure-deserialization',
      priority: priority++,
      reason: `${hasDeserializationRiskDefault ? 'Backend tech detected' : `${apiEndpoints.length} API endpoints`} — test deserialization`,
    });
  } else {
    skipReasons['insecure-deserialization'] = 'No API endpoints, POST forms, or backend tech detected';
  }

  // Request smuggling: relevant for most production apps behind proxies/CDNs
  if (pages.length > 0) {
    checks.push({
      name: 'request-smuggling',
      priority: priority++,
      reason: 'Test CL.TE/TE.CL desync between proxy and backend',
    });
  } else {
    skipReasons['request-smuggling'] = 'No pages crawled';
  }

  // LDAP injection: when login forms with LDAP-related params exist
  const ldapParamReDefault = /^(username|user|uid|cn|sn|dn|login|name|search|query|q|filter|account|email|samaccountname)$/i;
  const hasLdapParamsDefault = urlsWithParams.some((u) => {
    try { return [...new URL(u).searchParams.keys()].some((k) => ldapParamReDefault.test(k)); } catch { return false; }
  });
  const hasLoginFormsDefault = allForms.some((f) =>
    f.inputs.some((i) => ldapParamReDefault.test(i.name ?? '')),
  );
  if (hasLdapParamsDefault || hasLoginFormsDefault) {
    checks.push({
      name: 'ldap-injection',
      priority: priority++,
      reason: `${hasLoginFormsDefault ? 'Login forms' : 'URL params'} with LDAP-related field names`,
    });
  } else {
    skipReasons['ldap-injection'] = 'No LDAP-related params or login forms found';
  }

  // Username enumeration: when login/register/reset forms exist
  const hasAuthForms = allForms.some((f) =>
    f.inputs.some((i) => /^(username|user|email|login|uid|account|name)$/i.test(i.name)) &&
    (f.inputs.some((i) => i.type === 'password' || /^(password|pass|pwd)$/i.test(i.name)) ||
     /\/(login|signin|register|signup|forgot|reset)\b/i.test(f.action) ||
     /\/(login|signin|register|signup|forgot|reset)\b/i.test(f.pageUrl)),
  );
  if (hasAuthForms) {
    checks.push({
      name: 'user-enum',
      priority: priority++,
      reason: 'Auth forms detected — test for username enumeration via response discrepancies',
    });
  } else {
    skipReasons['user-enum'] = 'No login/register/reset forms found';
  }

  // Mass assignment: when API endpoints or user-profile-like forms exist
  const hasMutableEndpoints = [...recon.endpoints.apiRoutes, ...recon.endpoints.pages].some((u) =>
    /\/(user|profile|account|settings|preferences|register|signup|update|edit|me|self)\b/i.test(u),
  );
  const hasUserDataForms = allForms.some((f) =>
    /^(post|put|patch)$/i.test(f.method ?? 'get') &&
    f.inputs.some((i) => /^(name|email|username|phone|bio|company|title|first_?name|last_?name)$/i.test(i.name)),
  );
  if (hasMutableEndpoints || hasUserDataForms) {
    checks.push({
      name: 'mass-assignment',
      priority: priority++,
      reason: `${hasMutableEndpoints ? 'Mutable API endpoints' : 'User data forms'} detected — test for over-posting`,
    });
  } else {
    skipReasons['mass-assignment'] = 'No mutable user/profile/account endpoints or user data forms found';
  }

  // Content-type confusion: when state-changing POST forms or API endpoints exist
  const stateChangingReDefault = /\/(login|signup|register|checkout|transfer|payment|settings|profile|password|delete|update|create|submit|feedback|contact|comment|review|order|cart|subscribe|send|confirm|approve|reject|cancel|publish|upload|invite|reset|change|save|edit)/i;
  const hasStateChangingFormsDefault = allForms.some((f) =>
    /^(post|put|patch)$/i.test(f.method ?? 'get') &&
    (stateChangingReDefault.test(f.action) || stateChangingReDefault.test(f.pageUrl ?? '')),
  );
  if (hasStateChangingFormsDefault || apiEndpoints.length > 0) {
    checks.push({
      name: 'content-type-confusion',
      priority: priority++,
      reason: `${hasStateChangingFormsDefault ? 'State-changing forms' : 'API endpoints'} detected — test Content-Type bypass`,
    });
  } else {
    skipReasons['content-type-confusion'] = 'No state-changing POST forms or API endpoints found';
  }

  // Method override: when API endpoints or sensitive paths exist
  const sensitiveEndpointReDefault = /\/(user|profile|account|admin|settings|api|resource|item|record|data|session)\b/i;
  const hasSensitiveEndpointsDefault = apiEndpoints.length > 0 ||
    allDiscoveredUrls.some((u) => sensitiveEndpointReDefault.test(u));
  if (hasSensitiveEndpointsDefault) {
    checks.push({
      name: 'method-override',
      priority: priority++,
      reason: `${apiEndpoints.length > 0 ? 'API endpoints' : 'Sensitive paths'} detected — test X-HTTP-Method-Override`,
    });
  } else {
    skipReasons['method-override'] = 'No API endpoints or sensitive paths found';
  }

  // Email injection: when email-sending forms detected
  const emailFormReDefault = /\/(contact|feedback|support|help|enquiry|inquiry|message|send-?mail|mail|email|subscribe|newsletter|invite|referral|share|report|notify)/i;
  const hasEmailFormsDefault = allForms.some((f) =>
    /^post$/i.test(f.method ?? 'get') &&
    (emailFormReDefault.test(f.action) || emailFormReDefault.test(f.pageUrl ?? '')) &&
    f.inputs.some((i) => /^(email|e-?mail|from|subject|message|body|content)$/i.test(i.name ?? '')),
  );
  if (hasEmailFormsDefault) {
    checks.push({
      name: 'email-injection',
      priority: priority++,
      reason: 'Email-sending forms detected — test SMTP header injection',
    });
  } else {
    skipReasons['email-injection'] = 'No email-sending forms found';
  }

  // BFLA: when API endpoints exist (function enumeration needs API paths)
  if (apiEndpoints.length > 0) {
    checks.push({
      name: 'bfla',
      priority: priority++,
      reason: `${apiEndpoints.length} API endpoints — enumerate admin functions and test function-level auth`,
    });
  } else {
    skipReasons['bfla'] = 'No API endpoints found for function-level auth testing';
  }

  // Clickjacking: when pages exist (active frame detection)
  if (pages.length > 0) {
    checks.push({
      name: 'clickjacking',
      priority: priority++,
      reason: `${pages.length} pages — active iframe frameability testing (goes beyond passive header check)`,
    });
  } else {
    skipReasons['clickjacking'] = 'No pages found for clickjacking testing';
  }

  // Timing attack: when login forms or auth endpoints exist
  const hasPasswordForms = allForms.some((f) => f.inputs.some((i) => i.type === 'password'));
  const hasAuthUrls = pages.some((p) =>
    /\/(login|signin|auth|authenticate|forgot|reset|recover|password)/i.test(p.url),
  );
  if (hasPasswordForms || hasAuthUrls) {
    checks.push({
      name: 'timing-attack',
      priority: priority++,
      reason: `Auth endpoints detected — test for timing side-channels in username validation`,
    });
  } else {
    skipReasons['timing-attack'] = 'No login forms or auth endpoints found for timing analysis';
  }

  // Verbose errors: always when pages exist (every app can leak error details)
  if (pages.length > 0) {
    checks.push({
      name: 'verbose-errors',
      priority: priority++,
      reason: `${pages.length} pages — trigger error conditions to detect stack traces, debug pages, and sensitive info`,
    });
  } else {
    skipReasons['verbose-errors'] = 'No pages found for error disclosure testing';
  }

  // XPath injection: when parameterized URLs or forms exist
  if (urlsWithParams.length > 0 || allForms.length > 0) {
    checks.push({
      name: 'xpath-injection',
      priority: priority++,
      reason: `${urlsWithParams.length} parameterized URLs + ${allForms.length} forms — test for XPath query injection`,
    });
  } else {
    skipReasons['xpath-injection'] = 'No parameterized URLs or forms for XPath injection testing';
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

  // Limit by profile — each check is individually gated, so the limit is a speed budget
  // Quick: top 6 (fast scan). Standard: all gated checks. Deep: all gated checks.
  const maxChecks = profile === 'quick' ? 6 : checks.length;
  const limited = checks.slice(0, maxChecks);

  return {
    recommendedChecks: limited,
    reasoning: `Default plan: ${limited.length} checks based on available targets` +
      (learningContext?.techProfile ? ' (adjusted by learning data)' : ''),
    skipReasons,
  };
}

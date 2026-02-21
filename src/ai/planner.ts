import type { ReconResult, CrawledPage, AttackPlan, ScanProfile } from '../scanner/types.js';
import { askClaude, parseJsonResponse } from './client.js';
import { buildPlannerPrompt, buildPlannerUserPrompt } from './prompts.js';
import type { PlannerCheckType } from './prompts.js';
import { log } from '../utils/logger.js';

const CHECK_NAMES = ['xss', 'sqli', 'cors', 'redirect', 'traversal', 'ssrf', 'ssti', 'cmdi', 'idor', 'tls', 'sri'] as const;

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
): Promise<AttackPlan> {
  log.info('AI planning attack strategy...');

  const relevantChecks = determineRelevantChecks(url, recon, pages);
  log.info(`Relevant checks for target: ${relevantChecks.join(', ')} (${relevantChecks.length}/${CHECK_NAMES.length})`);

  const systemPrompt = buildPlannerPrompt(relevantChecks);
  const userPrompt = buildPlannerUserPrompt(url, recon, pages, profile);
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
      return parsed;
    }
    log.warn('AI planner returned invalid JSON — using default plan');
  } else {
    log.info('AI unavailable — using default attack plan');
  }

  return buildDefaultPlan(recon, pages, profile);
}

function buildDefaultPlan(
  recon: ReconResult,
  pages: CrawledPage[],
  profile: ScanProfile,
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

  // Limit by profile
  const maxChecks = profile === 'quick' ? 3 : profile === 'standard' ? 6 : checks.length;
  const limited = checks.slice(0, maxChecks);

  return {
    recommendedChecks: limited,
    reasoning: `Default plan: ${limited.length} checks based on available targets`,
    skipReasons,
  };
}

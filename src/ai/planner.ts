import type { ReconResult, CrawledPage, AttackPlan, ScanProfile } from '../scanner/types.js';
import { askClaude, parseJsonResponse } from './client.js';
import { PLANNER_SYSTEM_PROMPT, buildPlannerUserPrompt } from './prompts.js';
import { log } from '../utils/logger.js';

const CHECK_NAMES = ['xss', 'sqli', 'cors', 'redirect', 'traversal'] as const;

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

  const userPrompt = buildPlannerUserPrompt(url, recon, pages, profile);
  const response = await askClaude(PLANNER_SYSTEM_PROMPT, userPrompt);

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

  const checks: AttackPlan['recommendedChecks'] = [];
  const skipReasons: Record<string, string> = {};
  let priority = 1;

  // CORS is always worth checking (low cost)
  checks.push({
    name: 'cors',
    priority: priority++,
    reason: 'Low-cost check with high-value findings',
  });

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
  const maxChecks = profile === 'quick' ? 2 : profile === 'standard' ? 4 : checks.length;
  const limited = checks.slice(0, maxChecks);

  return {
    recommendedChecks: limited,
    reasoning: `Default plan: ${limited.length} checks based on available targets`,
    skipReasons,
  };
}

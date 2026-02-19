import type { BrowserContext } from 'playwright';
import type {
  RawFinding,
  ScanConfig,
  CrawledPage,
  FormInfo,
  AttackPlan,
  CheckCategory,
} from '../types.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import { xssCheck } from './xss.js';
import { sqliCheck } from './sqli.js';
import { corsCheck } from './cors.js';
import { redirectCheck } from './redirect.js';
import { traversalCheck } from './traversal.js';
import { log } from '../../utils/logger.js';

export interface ScanTargets {
  pages: string[];
  forms: FormInfo[];
  urlsWithParams: string[];
  apiEndpoints: string[];
  redirectUrls: string[];
}

export interface ActiveCheck {
  name: string;
  category: CheckCategory;
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
];

/** Build scan targets from crawled pages */
export function buildTargets(pages: CrawledPage[]): ScanTargets {
  const allForms = pages.flatMap((p) => p.forms);
  const urlsWithParams = pages.map((p) => p.url).filter((u) => u.includes('?'));
  const apiEndpoints = pages.map((p) => p.url).filter((u) => /\/api\//i.test(u));
  const redirectUrls = pages
    .flatMap((p) => p.links)
    .filter((l) => /[?&](url|redirect|next|return|goto|dest)=/i.test(l));

  return {
    pages: pages.map((p) => p.url),
    forms: allForms,
    urlsWithParams,
    apiEndpoints,
    redirectUrls,
  };
}

/**
 * Run active security checks.
 * If an attack plan is provided, only run recommended checks in priority order.
 * Otherwise, run all checks (except traversal on non-deep profiles).
 */
export async function runActiveChecks(
  context: BrowserContext,
  pages: CrawledPage[],
  config: ScanConfig,
  attackPlan?: AttackPlan,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  if (config.profile === 'quick' && !attackPlan) {
    log.info('Quick profile — skipping active checks');
    return [];
  }

  const targets = buildTargets(pages);
  const findings: RawFinding[] = [];

  let checksToRun: ActiveCheck[];

  if (attackPlan) {
    // Run only recommended checks in priority order
    const sorted = [...attackPlan.recommendedChecks].sort((a, b) => a.priority - b.priority);
    checksToRun = sorted
      .map((rec) => CHECK_REGISTRY.find((c) => c.name === rec.name))
      .filter((c): c is ActiveCheck => c !== undefined);

    log.info(`Running ${checksToRun.length} AI-recommended checks: ${checksToRun.map((c) => c.name).join(', ')}`);
  } else {
    // Run all checks (filter traversal for non-deep)
    checksToRun = CHECK_REGISTRY.filter((c) => {
      if (c.name === 'traversal' && config.profile !== 'deep') return false;
      return true;
    });
    log.info(`Running ${checksToRun.length} active checks: ${checksToRun.map((c) => c.name).join(', ')}`);
  }

  for (const check of checksToRun) {
    try {
      const checkFindings = await check.run(context, targets, config, requestLogger);
      findings.push(...checkFindings);
    } catch (err) {
      log.warn(`Active check "${check.name}" failed: ${(err as Error).message}`);
    }
  }

  log.info(`Active scan: ${findings.length} raw findings`);
  return findings;
}

import type { BrowserContext } from 'playwright';
import type {
  RawFinding,
  ScanConfig,
  CrawledPage,
  FormInfo,
  AttackPlan,
  CheckCategory,
  ScanScope,
} from '../types.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import { isInScope } from '../../utils/scope.js';
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
  fileParams: string[]; // URLs with file-like parameters (path, file, doc, image, etc.)
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

/** Regex for redirect-related parameter names */
const REDIRECT_PARAM_RE = /[?&](url|redirect|next|return|goto|dest|callback|redir|forward|ref|out|continue|target|path|link|returnUrl|redirectUrl|returnTo|return_to|redirect_uri|redirect_url)=/i;

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

/** Build scan targets from crawled pages, filtering by scope */
export function buildTargets(pages: CrawledPage[], targetUrl: string, scope?: ScanScope): ScanTargets {
  const inScope = (url: string) => isInScope(url, targetUrl, scope);

  const scopedPages = pages.filter((p) => inScope(p.url));
  const allForms = scopedPages.flatMap((p) => p.forms).filter((f) => {
    try { return inScope(new URL(f.action, f.pageUrl).href); } catch (err) { log.debug(`Scope check: ${(err as Error).message}`); return true; }
  });
  const urlsWithParams = scopedPages.map((p) => p.url).filter((u) => u.includes('?'));
  const apiEndpoints = scopedPages.map((p) => p.url).filter((u) => /\/api\//i.test(u));
  const redirectUrls = scopedPages
    .flatMap((p) => p.links)
    .filter((l) => REDIRECT_PARAM_RE.test(l))
    .filter(inScope);

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
    urlsWithParams,
    apiEndpoints,
    redirectUrls,
    fileParams: [...new Set(fileParams)],
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

  const targets = buildTargets(pages, config.targetUrl, config.scope);
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

  for (let i = 0; i < checksToRun.length; i++) {
    const check = checksToRun[i];
    try {
      const checkFindings = await check.run(context, targets, config, requestLogger);
      findings.push(...checkFindings);
    } catch (err) {
      log.warn(`Active check "${check.name}" failed: ${(err as Error).message}`);
    }
    // Rate limit between checks
    if (i < checksToRun.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, config.requestDelay));
    }
  }

  log.info(`Active scan: ${findings.length} raw findings`);
  return findings;
}

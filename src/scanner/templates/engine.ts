import { FastEngine, type FastResponse } from '../fast-engine.js';
import { log } from '../../utils/logger.js';
import { loadTemplatesFromDir } from './yaml-loader.js';
import type { RawFinding, CheckCategory, Severity, Confidence } from '../types.js';

// ─── Template Types ──────────────────────────────────────────────

export interface VulnTemplate {
  id: string;
  info: {
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;
    tags: string[];
    reference?: string[];
    cwe?: string;
  };
  match?: {
    tech?: string[]; // only run if tech detected (e.g., ['wordpress', 'php'])
  };
  requests: Array<{
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD';
    path: string;
    headers?: Record<string, string>;
    body?: string;
    matchers: Array<{
      type: 'status' | 'body' | 'header' | 'regex';
      status?: number[];
      words?: string[];
      header?: string;
      value?: string;
      regex?: string;
      negative?: boolean; // true = must NOT match
    }>;
    matchCondition?: 'and' | 'or'; // default 'and'
  }>;
}

// ─── Matcher Logic ───────────────────────────────────────────────

function evaluateSingleMatcher(
  resp: FastResponse,
  matcher: VulnTemplate['requests'][0]['matchers'][0],
): boolean {
  let matched = false;

  switch (matcher.type) {
    case 'status':
      if (matcher.status && matcher.status.length > 0) {
        matched = matcher.status.includes(resp.status);
      }
      break;

    case 'body':
      if (matcher.words && matcher.words.length > 0) {
        const bodyLower = resp.body.toLowerCase();
        matched = matcher.words.every(w => bodyLower.includes(w.toLowerCase()));
      }
      break;

    case 'header': {
      if (matcher.header) {
        const headerKey = matcher.header.toLowerCase();
        const headerVal = resp.headers[headerKey];
        if (matcher.value) {
          matched = headerVal !== undefined &&
            headerVal.toLowerCase().includes(matcher.value.toLowerCase());
        } else {
          // Just check header existence
          matched = headerVal !== undefined;
        }
      }
      break;
    }

    case 'regex':
      if (matcher.regex) {
        try {
          const re = new RegExp(matcher.regex, 'is');
          matched = re.test(resp.body);
        } catch {
          log.debug(`template-engine: invalid regex "${matcher.regex}"`);
          matched = false;
        }
      }
      break;
  }

  // Negative matcher: invert the result
  return matcher.negative ? !matched : matched;
}

/**
 * Check whether a response matches a set of matchers under the given condition.
 */
export function matchResponse(
  resp: FastResponse,
  matchers: VulnTemplate['requests'][0]['matchers'],
  condition: 'and' | 'or' = 'and',
): boolean {
  if (matchers.length === 0) return false;

  if (condition === 'and') {
    return matchers.every(m => evaluateSingleMatcher(resp, m));
  }
  // 'or' — at least one matcher must succeed
  return matchers.some(m => evaluateSingleMatcher(resp, m));
}

// ─── Category Mapping ────────────────────────────────────────────

const TAG_TO_CATEGORY: Record<string, CheckCategory> = {
  'xss': 'xss',
  'sqli': 'sqli',
  'ssrf': 'ssrf',
  'ssti': 'ssti',
  'rce': 'command-injection',
  'redirect': 'open-redirect',
  'traversal': 'directory-traversal',
  'cors': 'cors-misconfiguration',
  'csrf': 'csrf',
  'idor': 'idor',
  'xxe': 'xxe',
  'jwt': 'jwt',
  'crlf': 'crlf-injection',
  'misconfig': 'info-disclosure',
  'exposure': 'info-disclosure',
  'panel': 'info-disclosure',
  'config': 'info-disclosure',
  'debug': 'info-disclosure',
  'default-login': 'broken-access-control',
  'default-credentials': 'broken-access-control',
  'auth-bypass': 'broken-access-control',
  'disclosure': 'info-disclosure',
  'devtools': 'info-disclosure',
  'cve': 'info-disclosure',
  'headers': 'info-disclosure',
  'listing': 'info-disclosure',
};

function inferCategory(template: VulnTemplate): CheckCategory {
  for (const tag of template.info.tags) {
    const cat = TAG_TO_CATEGORY[tag.toLowerCase()];
    if (cat) return cat;
  }
  return 'info-disclosure';
}

function inferConfidence(template: VulnTemplate): Confidence {
  // Templates with multiple matchers using 'and' condition are high confidence
  const totalMatchers = template.requests.reduce((sum, r) => sum + r.matchers.length, 0);
  if (totalMatchers >= 3) return 'high';
  if (totalMatchers >= 2) return 'medium';
  return 'low';
}

// ─── Template Runner ─────────────────────────────────────────────

/**
 * Run a single template against a target. Returns a RawFinding if all
 * requests in the template match, null otherwise.
 */
export async function runTemplate(
  template: VulnTemplate,
  baseUrl: string,
  engine: FastEngine,
): Promise<RawFinding | null> {
  // Strip trailing slash from baseUrl for clean path joining
  const base = baseUrl.replace(/\/+$/, '');

  for (const req of template.requests) {
    const url = `${base}${req.path}`;
    let resp: FastResponse;

    try {
      resp = await engine.request(url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        timeout: 10000,
      });
    } catch {
      // Request failed (network error, timeout) — template doesn't match
      return null;
    }

    const condition = req.matchCondition ?? 'and';
    if (!matchResponse(resp, req.matchers, condition)) {
      return null;
    }
  }

  // All requests matched — build finding
  const category = inferCategory(template);
  const firstReq = template.requests[0];
  const fullUrl = `${base}${firstReq.path}`;

  return {
    id: `template-${template.id}-${Date.now()}`,
    category,
    severity: template.info.severity as Severity,
    title: template.info.name,
    description: template.info.description,
    url: fullUrl,
    evidence: `Template ${template.id} matched: ${template.info.name}`,
    request: {
      method: firstReq.method,
      url: fullUrl,
      headers: firstReq.headers,
      body: firstReq.body,
    },
    timestamp: new Date().toISOString(),
    confidence: inferConfidence(template),
    evidencePack: {
      detectionMethod: 'template-scan',
      responseIndicators: template.info.tags,
    },
  };
}

/**
 * Run multiple templates against a target, filtering by tech stack.
 * Returns all confirmed findings.
 */
export async function runTemplates(
  templates: VulnTemplate[],
  baseUrl: string,
  engine: FastEngine,
  detectedTech?: string[],
): Promise<RawFinding[]> {
  const normalizedTech = (detectedTech ?? []).map(t => t.toLowerCase());

  // Filter templates by tech match
  const applicable = templates.filter(t => {
    if (!t.match?.tech || t.match.tech.length === 0) return true;
    // Template requires specific tech — at least one must be detected
    return t.match.tech.some(required =>
      normalizedTech.some(detected => detected.includes(required.toLowerCase())),
    );
  });

  log.info(`Template scan: ${applicable.length}/${templates.length} templates applicable (${normalizedTech.length} tech tags detected)`);

  const findings: RawFinding[] = [];
  let completed = 0;

  for (const template of applicable) {
    try {
      const finding = await runTemplate(template, baseUrl, engine);
      if (finding) {
        findings.push(finding);
        log.finding(finding.severity, `[template] ${finding.title}`);
      }
    } catch (err) {
      log.debug(`template-engine: error running ${template.id}: ${err}`);
    }
    completed++;
    if (completed % 10 === 0) {
      log.debug(`Template scan progress: ${completed}/${applicable.length}`);
    }
  }

  log.info(`Template scan complete: ${findings.length} finding(s) from ${applicable.length} templates`);
  return findings;
}

/**
 * Load YAML templates from one or more directories and merge with built-in templates.
 * Deduplicates by template ID (built-in templates take priority).
 */
export function mergeWithYamlTemplates(
  builtinTemplates: VulnTemplate[],
  ...dirs: string[]
): VulnTemplate[] {
  const builtinIds = new Set(builtinTemplates.map(t => t.id));
  const merged = [...builtinTemplates];

  for (const dir of dirs) {
    const yamlTemplates = loadTemplatesFromDir(dir);
    for (const t of yamlTemplates) {
      if (!builtinIds.has(t.id)) {
        merged.push(t);
        builtinIds.add(t.id);
      } else {
        log.debug(`template-engine: skipping duplicate YAML template "${t.id}" (built-in takes priority)`);
      }
    }
  }

  return merged;
}

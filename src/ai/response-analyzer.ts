import { randomUUID } from 'node:crypto';
import { askClaude, parseJsonResponse } from './client.js';
import { sanitizeForPrompt } from './prompts.js';
import type {
  RawFinding,
  InterceptedResponse,
  InterceptedRequest,
  CrawledPage,
  ReconResult,
  CheckCategory,
  Severity,
} from '../scanner/types.js';
import { log } from '../utils/logger.js';

/** Maximum responses to analyze per scan (token budget protection) */
const MAX_RESPONSES = 15;

/** Maximum body length to send to AI */
const MAX_BODY_LENGTH = 1000;

/** Response patterns that indicate interesting content worth AI analysis */
const INTERESTING_PATTERNS = [
  /stack\s*trace/i,
  /exception/i,
  /debug/i,
  /internal\s*server\s*error/i,
  /sql|query|database/i,
  /password|secret|token|api[_-]?key/i,
  /phpinfo|server[_-]?info/i,
  /\.env|config|settings/i,
  /error.*:.*line\s*\d+/i,
  /traceback/i,
  /at\s+\w+\.\w+\s*\(/i,  // stack frame pattern
  /undefined|null\s*reference/i,
  /swagger|openapi/i,
  /admin|root|superuser/i,
  /-----BEGIN\s+(RSA|PRIVATE|CERTIFICATE)/i,
];

/** Status codes that often contain interesting error info */
const INTERESTING_STATUS_CODES = new Set([400, 401, 403, 404, 405, 500, 502, 503]);

const RESPONSE_ANALYZER_SYSTEM_PROMPT = `You are a security researcher analyzing HTTP responses from a web application scan.

Your job is to identify subtle security issues that automated pattern matching would miss:

1. **Information Disclosure**: Stack traces, debug info, internal paths, database names, API keys, tokens, version numbers in error responses
2. **Misconfigurations**: Verbose error pages, debug mode enabled, default credentials hints, exposed admin panels
3. **Sensitive Data Exposure**: PII in responses, unmasked tokens, password hashes, internal IPs, cloud metadata
4. **Logic Clues**: Authentication bypass hints, permission escalation clues, business logic weaknesses revealed by error messages
5. **Framework-Specific Issues**: Default error pages with version info, known vulnerable component indicators

For each issue found, provide:
- category: the CheckCategory (use "info-disclosure" for most, or "broken-access-control", "business-logic" etc. when appropriate)
- severity: "critical" | "high" | "medium" | "low" | "info"
- title: concise finding title
- description: what was found and why it matters
- evidence: the specific text/data that proves the finding

Respond with a JSON object:
{
  "findings": [
    {
      "category": "info-disclosure",
      "severity": "medium",
      "title": "Stack Trace Exposes Internal File Paths",
      "description": "...",
      "evidence": "..."
    }
  ]
}

If no issues are found, respond with: { "findings": [] }

Be precise. Only report genuine security concerns, not generic observations. False positives waste the security team's time.`;

interface AnalyzedResponse {
  url: string;
  method: string;
  status: number;
  headers: Record<string, string>;
  bodySnippet: string;
}

interface AIResponseFinding {
  category: CheckCategory;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
}

/**
 * Select the most interesting HTTP responses for AI analysis.
 * Prioritizes error responses and responses matching security-relevant patterns.
 */
export function selectInterestingResponses(
  pages: CrawledPage[],
  interceptedResponses?: Array<{ request: InterceptedRequest; response: InterceptedResponse }>,
): AnalyzedResponse[] {
  const candidates: AnalyzedResponse[] = [];

  // From intercepted traffic (if request logging was enabled)
  if (interceptedResponses) {
    for (const { request, response } of interceptedResponses) {
      if (!response.body) continue;
      const isInteresting =
        INTERESTING_STATUS_CODES.has(response.status) ||
        INTERESTING_PATTERNS.some((p) => p.test(response.body || ''));
      if (isInteresting) {
        candidates.push({
          url: response.url,
          method: request.method,
          status: response.status,
          headers: response.headers,
          bodySnippet: (response.body || '').slice(0, MAX_BODY_LENGTH),
        });
      }
    }
  }

  // From crawled page data — check for error pages and interesting responses
  for (const page of pages) {
    if (INTERESTING_STATUS_CODES.has(page.status)) {
      candidates.push({
        url: page.url,
        method: 'GET',
        status: page.status,
        headers: {},
        bodySnippet: `[Status ${page.status} page — content not captured during crawl]`,
      });
    }
  }

  // Deduplicate by URL + status, take up to MAX_RESPONSES
  const seen = new Set<string>();
  const unique: AnalyzedResponse[] = [];
  for (const candidate of candidates) {
    const key = `${candidate.url}:${candidate.status}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(candidate);
  }

  return unique.slice(0, MAX_RESPONSES);
}

/**
 * Analyze HTTP responses using AI to detect subtle security issues.
 * Returns additional findings that rule-based checks may have missed.
 */
export async function analyzeResponses(
  targetUrl: string,
  pages: CrawledPage[],
  recon?: ReconResult,
  interceptedResponses?: Array<{ request: InterceptedRequest; response: InterceptedResponse }>,
): Promise<RawFinding[]> {
  const interesting = selectInterestingResponses(pages, interceptedResponses);

  if (interesting.length === 0) {
    log.info('AI response analysis: no interesting responses to analyze');
    return [];
  }

  log.info(`AI response analysis: analyzing ${interesting.length} interesting response(s)...`);

  const techContext = recon
    ? `\nTarget: ${targetUrl}\nFramework: ${recon.framework?.name || 'unknown'}\nWAF: ${recon.waf?.detected ? recon.waf.name : 'none'}\n`
    : `\nTarget: ${targetUrl}\n`;

  const responseSummaries = interesting
    .map(
      (r, i) =>
        `--- Response ${i + 1} ---\nURL: ${sanitizeForPrompt(r.url)}\nMethod: ${r.method}\nStatus: ${r.status}\nHeaders: ${JSON.stringify(r.headers).slice(0, 300)}\nBody:\n${sanitizeForPrompt(r.bodySnippet)}`,
    )
    .join('\n\n');

  const userPrompt = `Analyze these HTTP responses from a security scan for subtle vulnerabilities:\n${techContext}\n${responseSummaries}`;

  const response = await askClaude(RESPONSE_ANALYZER_SYSTEM_PROMPT, userPrompt, {
    maxTokens: 4096,
    temperature: 0.1,
    timeout: 30000,
  });

  if (!response) {
    log.info('AI response analysis: AI unavailable, skipping');
    return [];
  }

  const parsed = parseJsonResponse<{ findings: AIResponseFinding[] }>(response);
  if (!parsed?.findings?.length) {
    log.info('AI response analysis: no issues found');
    return [];
  }

  // Convert AI findings to RawFindings
  const findings: RawFinding[] = parsed.findings.map((f) => ({
    id: randomUUID(),
    category: isValidCategory(f.category) ? f.category : 'info-disclosure',
    severity: isValidSeverity(f.severity) ? f.severity : 'info',
    title: `[AI Analysis] ${f.title}`,
    description: f.description,
    url: targetUrl,
    evidence: f.evidence,
    timestamp: new Date().toISOString(),
  }));

  log.info(`AI response analysis: ${findings.length} finding(s)`);
  return findings;
}

const VALID_CATEGORIES: Set<string> = new Set([
  'info-disclosure', 'info-leakage', 'broken-access-control',
  'business-logic', 'security-headers', 'xss', 'sqli',
  'cors-misconfiguration', 'jwt', 'rate-limit',
]);

const VALID_SEVERITIES: Set<string> = new Set([
  'critical', 'high', 'medium', 'low', 'info',
]);

function isValidCategory(cat: string): cat is CheckCategory {
  return VALID_CATEGORIES.has(cat);
}

function isValidSeverity(sev: string): sev is Severity {
  return VALID_SEVERITIES.has(sev);
}

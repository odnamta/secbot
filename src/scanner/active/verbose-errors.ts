import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/**
 * CWE-209: Generation of Error Message Containing Sensitive Information
 * CWE-215: Insertion of Sensitive Information Into Debugging Code
 * OWASP A05:2021 — Security Misconfiguration
 *
 * Actively triggers error conditions to detect verbose error messages,
 * stack traces, debug pages, and framework-specific error disclosures.
 *
 * Phases:
 *  1. Force 404/500 errors via malformed URLs
 *  2. Trigger type errors via invalid parameter values
 *  3. Detect framework debug pages (Django, Rails, Laravel, Express, Flask)
 *  4. Check for stack traces and internal paths in error responses
 */

/** Patterns indicating verbose error information */
const STACK_TRACE_PATTERNS = [
  // Generic stack traces
  /at\s+\S+\s+\([\\/][^\)]+:\d+:\d+\)/i,           // JavaScript/Node.js: at func (/path:line:col)
  /File\s+"[^"]+",\s+line\s+\d+/i,                  // Python: File "path", line N
  /\.py",?\s+line\s+\d+/i,                           // Python .py files
  /\.rb:\d+:in\s+`/i,                                // Ruby: file.rb:N:in `method`
  /\.java:\d+\)/,                                     // Java: File.java:N)
  /\.php:\d+/,                                        // PHP: file.php:N
  /\.cs:\d+/,                                         // C#: file.cs:N
  /Traceback\s+\(most\s+recent\s+call\s+last\)/i,    // Python traceback
  /Exception\s+in\s+thread\s+"main"/i,                // Java
  /at\s+[\w\.$]+\([\w]+\.java:\d+\)/,                // Java stack trace
];

/** Framework-specific debug page indicators */
const DEBUG_PAGE_PATTERNS = [
  // Django
  { pattern: /You're seeing this error because you have <code>DEBUG = True<\/code>/i, framework: 'Django' },
  { pattern: /django\.core\./i, framework: 'Django' },
  { pattern: /DJANGO_SETTINGS_MODULE/i, framework: 'Django' },
  // Rails
  { pattern: /Action\s*Controller::RoutingError/i, framework: 'Rails' },
  { pattern: /Rails\.root/i, framework: 'Rails' },
  { pattern: /active_support|action_dispatch/i, framework: 'Rails' },
  // Laravel
  { pattern: /Whoops!.*There was an error/i, framework: 'Laravel' },
  { pattern: /Illuminate\\[A-Z]/i, framework: 'Laravel' },
  { pattern: /laravel_session/i, framework: 'Laravel' },
  // Express/Node
  { pattern: /Cannot\s+(GET|POST|PUT|DELETE|PATCH)\s+\//i, framework: 'Express' },
  { pattern: /node_modules\//i, framework: 'Node.js' },
  // Flask
  { pattern: /werkzeug\.exceptions/i, framework: 'Flask' },
  { pattern: /flask\.app/i, framework: 'Flask' },
  // Spring
  { pattern: /Whitelabel Error Page/i, framework: 'Spring Boot' },
  { pattern: /org\.springframework\./i, framework: 'Spring' },
  // ASP.NET
  { pattern: /Server Error in '\/' Application/i, framework: 'ASP.NET' },
  { pattern: /System\.Web\.HttpException/i, framework: 'ASP.NET' },
  { pattern: /X-AspNet-Version/i, framework: 'ASP.NET' },
];

/** Sensitive information patterns in error responses */
const SENSITIVE_INFO_PATTERNS = [
  { pattern: /(?:\/home\/|\/var\/|\/usr\/|\/opt\/|C:\\Users\\|C:\\Windows\\)[^\s<"']+/i, type: 'Internal file paths' },
  { pattern: /(?:mysql|postgres|sqlite|oracle|mssql|mongodb).*(?:error|exception|failed)/i, type: 'Database error details' },
  { pattern: /(?:password|secret|token|api.key|credentials)\s*[:=]\s*["'][^"']{3,}/i, type: 'Credential leak' },
  { pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*FROM\s+\w+/i, type: 'SQL query exposed' },
  { pattern: /(?:connection.string|dsn|jdbc:)/i, type: 'Database connection string' },
  { pattern: /(?:SQLSTATE|ORA-\d{5}|MySQL server version)/i, type: 'Database version/error code' },
  { pattern: /(?:127\.0\.0\.1|localhost|0\.0\.0\.0):\d{4,5}/i, type: 'Internal network addresses' },
  { pattern: /(?:BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY)/i, type: 'Private key exposure' },
];

/** URLs designed to trigger errors */
function getErrorTriggerPaths(baseUrl: string): Array<{ url: string; description: string }> {
  const base = baseUrl.replace(/\/$/, '');
  return [
    { url: `${base}/<%=7*7%>`, description: 'Template injection error trigger' },
    { url: `${base}/..%00/etc/passwd`, description: 'Null byte path error trigger' },
    { url: `${base}/undefined`, description: 'Non-existent route error trigger' },
    { url: `${base}/'OR'1'='1`, description: 'SQL-like error trigger' },
    { url: `${base}/%00`, description: 'Null byte error trigger' },
    { url: `${base}/\x00`, description: 'Raw null byte error trigger' },
  ];
}

/** Max paths to test per profile */
const PROFILE_LIMITS: Record<string, number> = {
  quick: 2,
  standard: 4,
  deep: 6,
  stealth: 2,
};

export const verboseErrorsCheck: ActiveCheck = {
  name: 'verbose-errors',
  category: 'info-disclosure',
  parallel: true, // read-only requests

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const profile = config.profile ?? 'standard';
    const limit = PROFILE_LIMITS[profile] ?? 4;

    // Get base URLs from crawled pages
    const baseUrls = [...new Set(
      (targets.pages?.map((p) => {
        try {
          const u = new URL(p);
          return `${u.protocol}//${u.host}`;
        } catch {
          return null;
        }
      }) ?? []).filter(Boolean) as string[],
    )];

    if (baseUrls.length === 0) {
      log.debug('[verbose-errors] No pages to test');
      return findings;
    }

    log.info(`[verbose-errors] Testing ${baseUrls.length} base URL(s) for verbose error disclosure`);

    // Deduplicate: track which patterns we've already reported per base URL
    const reported = new Set<string>();

    for (const baseUrl of baseUrls.slice(0, 2)) {
      const errorPaths = getErrorTriggerPaths(baseUrl).slice(0, limit);

      for (const { url, description } of errorPaths) {
        try {
          const page = await context.newPage();
          try {
            const response = await page.goto(url, {
              waitUntil: 'domcontentloaded',
              timeout: 10000,
            });

            if (!response) continue;

            const status = response.status();
            const body = await page.content();
            const headers = response.headers();

            // Skip small responses (likely custom error pages)
            if (body.length < 100) continue;

            // Check for stack traces
            for (const pattern of STACK_TRACE_PATTERNS) {
              const match = body.match(pattern);
              if (match) {
                const key = `stack-trace-${baseUrl}`;
                if (reported.has(key)) continue;
                reported.add(key);

                findings.push({
                  id: randomUUID(),
                  title: 'Verbose Error — Stack Trace Exposed',
                  description:
                    `Error response at ${url} contains a stack trace: "${match[0].slice(0, 100)}". ` +
                    `Stack traces reveal internal file paths, technology versions, and code structure to attackers.`,
                  category: 'info-disclosure',
                  severity: 'medium',
                  confidence: 'high',
                  url,
                  evidence: JSON.stringify({
                    payloadUsed: description,
                    responseIndicators: [`Stack trace pattern: ${match[0].slice(0, 200)}`],
                    httpExchange: {
                      request: { method: 'GET', url },
                      response: {
                        status,
                        headers: { 'content-type': headers['content-type'] ?? '' },
                        bodySnippet: match[0].slice(0, 300),
                      },
                    },
                  }),
                  timestamp: new Date().toISOString(),
                });
                break;
              }
            }

            // Check for framework debug pages
            for (const { pattern, framework } of DEBUG_PAGE_PATTERNS) {
              if (pattern.test(body)) {
                const key = `debug-page-${baseUrl}-${framework}`;
                if (reported.has(key)) continue;
                reported.add(key);

                findings.push({
                  id: randomUUID(),
                  title: `Verbose Error — ${framework} Debug Page Exposed`,
                  description:
                    `Error response at ${url} reveals a ${framework} debug/error page. ` +
                    `Debug pages expose internal application structure, configuration, and sometimes source code.`,
                  category: 'info-disclosure',
                  severity: 'medium',
                  confidence: 'high',
                  url,
                  evidence: JSON.stringify({
                    payloadUsed: description,
                    responseIndicators: [`${framework} debug page detected`],
                    httpExchange: {
                      request: { method: 'GET', url },
                      response: {
                        status,
                        headers: { 'content-type': headers['content-type'] ?? '' },
                        bodySnippet: body.slice(0, 300),
                      },
                    },
                  }),
                  timestamp: new Date().toISOString(),
                });
                break;
              }
            }

            // Check for sensitive information in error responses
            if (status >= 400) {
              for (const { pattern, type } of SENSITIVE_INFO_PATTERNS) {
                const match = body.match(pattern);
                if (match) {
                  const key = `sensitive-${baseUrl}-${type}`;
                  if (reported.has(key)) continue;
                  reported.add(key);

                  findings.push({
                    id: randomUUID(),
                    title: `Verbose Error — ${type}`,
                    description:
                      `Error response at ${url} exposes sensitive information: ${type}. ` +
                      `Pattern matched: "${match[0].slice(0, 100)}".`,
                    category: 'info-disclosure',
                    severity: type.includes('Credential') || type.includes('Private key') ? 'high' : 'medium',
                    confidence: 'high',
                    url,
                    evidence: JSON.stringify({
                      payloadUsed: description,
                      responseIndicators: [`${type}: ${match[0].slice(0, 200)}`],
                      httpExchange: {
                        request: { method: 'GET', url },
                        response: {
                          status,
                          headers: {},
                          bodySnippet: match[0].slice(0, 300),
                        },
                      },
                    }),
                    timestamp: new Date().toISOString(),
                  });
                }
              }
            }

            if (requestLogger) {
              requestLogger.log({
                timestamp: new Date().toISOString(),
                method: 'GET',
                url,
                responseStatus: status,
                phase: 'verbose-errors',
              });
            }
          } finally {
            await page.close();
          }
        } catch (err) {
          log.debug(`[verbose-errors] Error testing ${url}: ${(err as Error).message}`);
        }
      }
    }

    return findings;
  },
};

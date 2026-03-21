import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import type { RequestLogger } from '../../utils/request-logger.js';

/**
 * Patterns that indicate a sensitive path in robots.txt Disallow directives.
 */
const SENSITIVE_ROBOTS_PATTERNS = /\b(admin|api|internal|dashboard|secret|private|debug|staging)\b/i;

/**
 * High-confidence secret patterns in JavaScript files.
 * Each pattern uses a definitive prefix/format that identifies the secret type.
 * Generic patterns (api_key=, password=) are intentionally excluded to avoid FPs in minified JS.
 */
interface JsSecretPattern {
  name: string;
  re: RegExp;
  severity: 'high' | 'medium';
  /** If true, the matched value must be at least this long to be considered a real secret */
  minLength?: number;
}

const JS_SECRET_PATTERNS: JsSecretPattern[] = [
  // AWS — AKIA prefix is definitive for access keys
  { name: 'AWS Access Key', re: /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, severity: 'high' },
  // Google Cloud / Firebase — AIza prefix is definitive
  { name: 'Google API Key', re: /AIza[0-9A-Za-z_-]{35}/g, severity: 'medium' },
  // Stripe — sk_live_ is a live secret key (sk_test_ is test, lower risk)
  { name: 'Stripe Secret Key', re: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'high' },
  // GitHub personal/org/user/repo tokens
  { name: 'GitHub Token', re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'high' },
  // Slack bot/user/app tokens
  { name: 'Slack Token', re: /xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+/g, severity: 'high' },
  // Slack webhooks
  { name: 'Slack Webhook URL', re: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, severity: 'medium' },
  // Private keys (PEM format)
  { name: 'Private Key (PEM)', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'high' },
  // SendGrid — SG. prefix is definitive
  { name: 'SendGrid API Key', re: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'high' },
  // Twilio — SK prefix + 32 hex chars
  { name: 'Twilio API Key', re: /SK[0-9a-fA-F]{32}/g, severity: 'high', minLength: 34 },
  // Mailchimp — 32 hex chars + -us region suffix
  { name: 'Mailchimp API Key', re: /[0-9a-f]{32}-us\d{1,2}/g, severity: 'medium' },
  // Shopify — shppa_/shpat_ prefix
  { name: 'Shopify Token', re: /shp(?:pa|at|ca|ss)_[a-fA-F0-9]{32,}/g, severity: 'high' },
  // Square — sq0[ac]sp- prefix
  { name: 'Square Access Token', re: /sq0[ac]sp-[0-9A-Za-z_-]{22,}/g, severity: 'high' },
  // Internal IP addresses in URLs — reveals infrastructure
  { name: 'Internal IP Address', re: /https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[:/])/g, severity: 'medium' },
  // Hardcoded Bearer tokens in fetch/axios calls
  { name: 'Hardcoded Bearer Token', re: /["']Bearer\s+[A-Za-z0-9_-]{20,}["']/g, severity: 'high' },
];

/**
 * Context around a match to help with false positive analysis.
 */
function extractMatchContext(content: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 40);
  const end = Math.min(content.length, matchIndex + matchLength + 40);
  return content.slice(start, end).replace(/\n/g, ' ');
}

/**
 * Scan JavaScript content for hardcoded secrets.
 * Returns an array of found secrets with context.
 */
export function scanJsForSecrets(content: string, sourceUrl: string): Array<{
  name: string;
  severity: 'high' | 'medium';
  match: string;
  context: string;
}> {
  const results: Array<{ name: string; severity: 'high' | 'medium'; match: string; context: string }> = [];
  const seen = new Set<string>();

  for (const pattern of JS_SECRET_PATTERNS) {
    // Reset regex state
    pattern.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.re.exec(content)) !== null) {
      const matched = m[0];
      // Skip if too short
      if (pattern.minLength && matched.length < pattern.minLength) continue;
      // Deduplicate
      const key = `${pattern.name}:${matched}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const context = extractMatchContext(content, m.index, matched.length);
      results.push({
        name: pattern.name,
        severity: pattern.severity,
        match: matched.length > 60 ? matched.slice(0, 60) + '...' : matched,
        context,
      });
    }
  }
  return results;
}

/**
 * Env file key=value pattern. Lines like KEY=value, DB_HOST=localhost, etc.
 * Requires at least a simple alphanumeric key and some value after '='.
 */
const ENV_LINE_RE = /^[A-Z_][A-Z0-9_]*=.+/m;

/**
 * Probes for exposed sensitive files and paths.
 */
interface Probe {
  path: string;
  label: string;
  severity: 'high' | 'medium' | 'low';
  /** Return true if the response body confirms real exposure (not just 200 OK). */
  matches: (body: string) => boolean;
  description: string;
  /** HTTP method override (default: GET). */
  method?: 'GET' | 'POST';
  /** Request body for POST probes (sent as application/json). */
  requestBody?: string;
}

/** Static file probes — checked against the target origin root. */
const FILE_PROBES: Probe[] = [
  {
    path: '/.git/config',
    label: 'Exposed .git/config',
    severity: 'high',
    matches: (body) => body.includes('[core]') || body.includes('[remote'),
    description:
      'The .git/config file is publicly accessible. An attacker can reconstruct the repository history, extract source code, credentials, and internal URLs.',
  },
  {
    path: '/.git/HEAD',
    label: 'Exposed .git/HEAD',
    severity: 'high',
    matches: (body) => /^ref:\s*refs\//.test(body.trim()),
    description:
      'The .git/HEAD file is publicly accessible. Combined with other .git files, an attacker can clone the entire repository.',
  },
  {
    path: '/.env',
    label: 'Exposed .env file',
    severity: 'high',
    matches: (body) => {
      const lines = body.split('\n').filter((l) => ENV_LINE_RE.test(l.trim()));
      return lines.length >= 2;
    },
    description:
      'The .env file is publicly accessible and contains environment variables that likely include secrets such as API keys, database credentials, and tokens.',
  },
  {
    path: '/.env.local',
    label: 'Exposed .env.local file',
    severity: 'high',
    matches: (body) => {
      const lines = body.split('\n').filter((l) => ENV_LINE_RE.test(l.trim()));
      return lines.length >= 2;
    },
    description:
      'The .env.local file is publicly accessible and contains local environment variables that likely include secrets.',
  },
  {
    path: '/.env.production',
    label: 'Exposed .env.production file',
    severity: 'high',
    matches: (body) => {
      const lines = body.split('\n').filter((l) => ENV_LINE_RE.test(l.trim()));
      return lines.length >= 2;
    },
    description:
      'The .env.production file is publicly accessible and contains production environment variables — likely the most sensitive configuration file.',
  },
  {
    path: '/.env.development',
    label: 'Exposed .env.development file',
    severity: 'high',
    matches: (body) => {
      const lines = body.split('\n').filter((l) => ENV_LINE_RE.test(l.trim()));
      return lines.length >= 2;
    },
    description:
      'The .env.development file is publicly accessible and contains development environment variables that may include internal service URLs and credentials.',
  },
  {
    path: '/backup.sql',
    label: 'Exposed database backup (backup.sql)',
    severity: 'high',
    matches: (body) =>
      /^(--|CREATE\s|INSERT\s|DROP\s)/im.test(body.trim()),
    description:
      'A SQL database backup is publicly accessible. This may contain the entire database schema and data including user credentials.',
  },
  {
    path: '/dump.sql',
    label: 'Exposed database dump (dump.sql)',
    severity: 'high',
    matches: (body) =>
      /^(--|CREATE\s|INSERT\s|DROP\s)/im.test(body.trim()),
    description:
      'A SQL database dump is publicly accessible. This may contain the entire database schema and data including user credentials.',
  },
  {
    path: '/db.sql',
    label: 'Exposed database file (db.sql)',
    severity: 'high',
    matches: (body) =>
      /^(--|CREATE\s|INSERT\s|DROP\s)/im.test(body.trim()),
    description:
      'A SQL database file is publicly accessible. This may contain the entire database schema and data.',
  },
  {
    path: '/wp-config.php.bak',
    label: 'Exposed WordPress config backup',
    severity: 'high',
    matches: (body) =>
      body.includes('DB_NAME') || body.includes('DB_PASSWORD') || body.includes('DB_HOST'),
    description:
      'A WordPress configuration backup file is publicly accessible. It typically contains database credentials, auth keys, and salts.',
  },
  {
    path: '/config.php.bak',
    label: 'Exposed PHP config backup',
    severity: 'high',
    matches: (body) =>
      body.includes('<?php') || body.includes('$db') || body.includes('$config'),
    description:
      'A PHP configuration backup file is publicly accessible. It may contain database credentials and application secrets.',
  },
  {
    path: '/.htaccess',
    label: 'Exposed .htaccess file',
    severity: 'medium',
    matches: (body) =>
      /^(RewriteEngine|RewriteRule|RewriteCond|AuthType|Require|Deny|Allow|Order)/im.test(body.trim()),
    description:
      'The .htaccess file is publicly accessible. It reveals server configuration, URL rewriting rules, and access control settings that can help an attacker map internal routes.',
  },
  {
    path: '/server-status',
    label: 'Exposed Apache server-status',
    severity: 'medium',
    matches: (body) =>
      body.includes('Apache Server Status') || body.includes('Server Version:'),
    description:
      'The Apache server-status page is publicly accessible. It reveals active connections, request details, server uptime, and configuration — valuable for reconnaissance.',
  },
  {
    path: '/ftp/',
    label: 'Exposed FTP directory listing',
    severity: 'high',
    matches: (body) =>
      matchesDirectoryListing(body),
    description:
      'An FTP directory is publicly accessible and exposes file listings. Attackers can download sensitive files such as backups, credentials, or internal documents.',
  },
  {
    path: '/api/',
    label: 'Exposed API root',
    severity: 'medium',
    matches: (body) =>
      matchesApiDocumentation(body),
    description:
      'The API root endpoint is publicly accessible and exposes documentation or endpoint listings. This reveals internal API structure that aids targeted attacks.',
  },
  {
    path: '/swagger.json',
    label: 'Exposed Swagger/OpenAPI spec',
    severity: 'medium',
    matches: (body) =>
      matchesSwaggerSpec(body),
    description:
      'A Swagger/OpenAPI specification file is publicly accessible. It reveals every API endpoint, parameter, and data model — a comprehensive attack surface map.',
  },
  {
    path: '/swagger-ui.html',
    label: 'Exposed Swagger UI',
    severity: 'medium',
    matches: (body) =>
      body.includes('swagger-ui') || body.includes('Swagger UI'),
    description:
      'The Swagger UI page is publicly accessible. It provides an interactive interface to explore and test all API endpoints.',
  },
  {
    path: '/api-docs',
    label: 'Exposed API documentation',
    severity: 'medium',
    matches: (body) =>
      matchesSwaggerSpec(body) || matchesApiDocumentation(body),
    description:
      'An API documentation endpoint is publicly accessible. It reveals API structure, endpoints, and parameters useful for targeted attacks.',
  },
  {
    path: '/graphql',
    label: 'GraphQL introspection enabled',
    severity: 'medium',
    method: 'POST',
    requestBody: '{"query":"{__schema{types{name}}}"}',
    matches: (body) =>
      matchesGraphQLIntrospection(body),
    description:
      'The GraphQL endpoint has introspection enabled. Attackers can query the full schema to discover all types, queries, mutations, and fields — exposing the entire API surface.',
  },
  {
    path: '/.DS_Store',
    label: 'Exposed .DS_Store file',
    severity: 'high',
    matches: (body) =>
      matchesDSStore(body),
    description:
      'A macOS .DS_Store metadata file is publicly accessible. It reveals directory contents and filenames, allowing attackers to discover hidden files and directories.',
  },
  {
    path: '/debug',
    label: 'Exposed debug endpoint',
    severity: 'medium',
    matches: (body) =>
      matchesDebugEndpoint(body),
    description:
      'A debug endpoint is publicly accessible. It may expose internal application state, environment variables, stack traces, or runtime configuration.',
  },
  {
    path: '/debug/vars',
    label: 'Exposed debug variables',
    severity: 'medium',
    matches: (body) =>
      matchesDebugEndpoint(body),
    description:
      'The debug/vars endpoint is publicly accessible. It exposes internal runtime variables including memory statistics, goroutine counts, and application metrics.',
  },
  {
    path: '/actuator',
    label: 'Exposed Spring Boot actuator',
    severity: 'medium',
    matches: (body) =>
      matchesActuatorEndpoint(body),
    description:
      'A Spring Boot actuator endpoint is publicly accessible. Actuator endpoints expose application health, configuration, environment variables, and metrics.',
  },
  {
    path: '/actuator/health',
    label: 'Exposed Spring Boot health endpoint',
    severity: 'medium',
    matches: (body) =>
      matchesActuatorEndpoint(body),
    description:
      'The Spring Boot actuator health endpoint is publicly accessible. It confirms the application framework and may reveal database and service connectivity details.',
  },
  {
    path: '/wp-login.php',
    label: 'WordPress login page detected',
    severity: 'low',
    matches: (body) =>
      body.includes('wp-login') || body.includes('wp-admin'),
    description:
      'A WordPress login page is publicly accessible. This confirms the CMS in use and provides a target for brute-force or credential-stuffing attacks.',
  },
  {
    path: '/phpinfo.php',
    label: 'Exposed phpinfo() page',
    severity: 'high',
    matches: (body) =>
      body.includes('phpinfo()') || body.includes('PHP Version'),
    description:
      'A phpinfo() page is publicly accessible. It exposes the full PHP configuration including server paths, loaded modules, environment variables, and potentially credentials.',
  },
  // ── Additional probes for bounty-grade coverage ──
  {
    path: '/openapi.json',
    label: 'Exposed OpenAPI spec',
    severity: 'medium',
    matches: (body) =>
      matchesSwaggerSpec(body),
    description:
      'An OpenAPI specification is publicly accessible at /openapi.json. It maps every API endpoint, parameter, and data model.',
  },
  {
    path: '/v3/api-docs',
    label: 'Exposed Spring Boot 3 API docs',
    severity: 'medium',
    matches: (body) =>
      matchesSwaggerSpec(body),
    description:
      'Spring Boot 3 API documentation is publicly accessible. It reveals the full API schema including internal endpoints.',
  },
  {
    path: '/actuator/env',
    label: 'Exposed Spring Boot env',
    severity: 'high',
    matches: (body) => {
      try {
        const obj = JSON.parse(body);
        return obj?.propertySources !== undefined || obj?.activeProfiles !== undefined;
      } catch {
        return false;
      }
    },
    description:
      'The Spring Boot actuator /env endpoint is publicly accessible and exposes ALL environment variables including database credentials, API keys, and secret keys.',
  },
  {
    path: '/actuator/heapdump',
    label: 'Exposed Spring Boot heapdump',
    severity: 'high',
    matches: (body) =>
      body.startsWith('JAVA PROFILE') || body.charCodeAt(0) === 0x4a,
    description:
      'The Spring Boot actuator /heapdump endpoint is publicly accessible. Heap dumps contain in-memory secrets, session tokens, and credentials in cleartext.',
  },
  {
    path: '/actuator/configprops',
    label: 'Exposed Spring Boot config properties',
    severity: 'high',
    matches: (body) => {
      try {
        const obj = JSON.parse(body);
        return obj?.contexts !== undefined || obj?.beans !== undefined;
      } catch {
        return false;
      }
    },
    description:
      'The Spring Boot actuator /configprops endpoint is publicly accessible. It reveals all configuration properties, potentially including credentials masked with ******.',
  },
  {
    path: '/debug/pprof/',
    label: 'Exposed Go pprof profiler',
    severity: 'medium',
    matches: (body) =>
      body.includes('/debug/pprof/') && (body.includes('goroutine') || body.includes('heap') || body.includes('profile')),
    description:
      'The Go pprof debug endpoint is publicly accessible. It exposes CPU/memory profiling data, goroutine dumps, and heap analysis — useful for DoS planning and information gathering.',
  },
  {
    path: '/elmah.axd',
    label: 'Exposed ELMAH error log',
    severity: 'high',
    matches: (body) =>
      body.includes('Error Log for') || body.includes('ELMAH') || body.includes('errorLog'),
    description:
      'The ELMAH (Error Logging Modules and Handlers) page is publicly accessible. It exposes application error logs including stack traces, SQL queries, internal paths, and potentially credentials.',
  },
  {
    path: '/trace.axd',
    label: 'Exposed ASP.NET trace',
    severity: 'high',
    matches: (body) =>
      body.includes('Application Trace') || body.includes('Request Details'),
    description:
      'The ASP.NET trace endpoint is publicly accessible. It exposes request/response details, session state, cookies, form data, and server variables for recent requests.',
  },
  {
    path: '/web.config',
    label: 'Exposed web.config (IIS)',
    severity: 'high',
    matches: (body) =>
      body.includes('<configuration>') && (body.includes('connectionStrings') || body.includes('appSettings')),
    description:
      'The IIS web.config file is publicly accessible. It typically contains database connection strings, authentication settings, and application secrets.',
  },
  {
    path: '/crossdomain.xml',
    label: 'Permissive crossdomain.xml',
    severity: 'medium',
    matches: (body) =>
      body.includes('<cross-domain-policy') && body.includes('domain="*"'),
    description:
      'A Flash crossdomain.xml policy allows any domain (domain="*"). Although Flash is deprecated, this indicates a lax cross-origin security posture that may extend to CORS configuration.',
  },
  {
    path: '/.well-known/openid-configuration',
    label: 'OpenID Connect discovery endpoint',
    severity: 'low',
    matches: (body) => {
      try {
        const obj = JSON.parse(body);
        return obj?.issuer !== undefined && obj?.authorization_endpoint !== undefined;
      } catch {
        return false;
      }
    },
    description:
      'The OpenID Connect discovery endpoint reveals the authentication infrastructure: issuer, token endpoint, supported scopes, and signing algorithms. Useful for planning OAuth attacks.',
  },
  {
    path: '/.well-known/jwks.json',
    label: 'JWKS endpoint exposed',
    severity: 'low',
    matches: (body) => {
      try {
        const obj = JSON.parse(body);
        return obj?.keys !== undefined && Array.isArray(obj.keys);
      } catch {
        return false;
      }
    },
    description:
      'The JSON Web Key Set endpoint is exposed. While public by design, it reveals key algorithms, key IDs, and signing methods — useful for JWT attack planning.',
  },
];

/**
 * Parse robots.txt and extract Disallow paths that look sensitive.
 */
export function parseSensitiveRobotsPaths(body: string): string[] {
  const sensitive: string[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.toLowerCase().startsWith('disallow:')) continue;
    const path = trimmed.slice('disallow:'.length).trim();
    if (path && SENSITIVE_ROBOTS_PATTERNS.test(path)) {
      sensitive.push(path);
    }
  }
  return sensitive;
}

/**
 * Check if a response body matches env file patterns.
 * Exported for testing.
 */
export function matchesEnvFile(body: string): boolean {
  const lines = body.split('\n').filter((l) => ENV_LINE_RE.test(l.trim()));
  return lines.length >= 2;
}

/**
 * Check if a response body matches git config patterns.
 * Exported for testing.
 */
export function matchesGitConfig(body: string): boolean {
  return body.includes('[core]') || body.includes('[remote');
}

/**
 * Check if a response body matches git HEAD patterns.
 * Exported for testing.
 */
export function matchesGitHead(body: string): boolean {
  return /^ref:\s*refs\//.test(body.trim());
}

/**
 * Check if a response looks like a valid source map (JSON with "sources" key).
 * Exported for testing.
 */
export function isValidSourceMap(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    return typeof parsed === 'object' && parsed !== null && 'sources' in parsed;
  } catch {
    return false;
  }
}

/**
 * Extract sourceMappingURL references from JavaScript content.
 * Handles both relative and absolute URLs, inline data URIs are skipped.
 * Exported for testing.
 */
export function extractSourceMappingURLs(jsContent: string, baseUrl: string): string[] {
  const urls: string[] = [];
  // Match //# sourceMappingURL=<url> or //@ sourceMappingURL=<url> (legacy)
  const re = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(jsContent)) !== null) {
    const raw = match[1];
    // Skip inline data URIs — they don't expose a fetchable file
    if (raw.startsWith('data:')) continue;
    try {
      const resolved = new URL(raw, baseUrl).href;
      urls.push(resolved);
    } catch {
      // Malformed URL — skip
    }
  }
  return urls;
}

/**
 * Analyze source map JSON for severity-relevant content.
 * Returns metadata about the source map: source count, whether sourcesContent is present,
 * and whether any secrets were found inside sourcesContent.
 * Exported for testing.
 */
export function analyzeSourceMapContent(body: string): {
  valid: boolean;
  sourceCount: number;
  hasSourcesContent: boolean;
  secretsFound: string[];
} {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed !== 'object' || parsed === null || !('sources' in parsed)) {
      return { valid: false, sourceCount: 0, hasSourcesContent: false, secretsFound: [] };
    }
    const sources: string[] = Array.isArray(parsed.sources) ? parsed.sources : [];
    const sourcesContent: string[] = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];
    const hasSourcesContent = sourcesContent.some((s) => typeof s === 'string' && s.length > 0);

    // Scan sourcesContent for secrets
    const secretsFound: string[] = [];
    if (hasSourcesContent) {
      const combined = sourcesContent.filter((s) => typeof s === 'string').join('\n').slice(0, 500_000);
      for (const pattern of JS_SECRET_PATTERNS) {
        pattern.re.lastIndex = 0;
        if (pattern.re.test(combined)) {
          secretsFound.push(pattern.name);
          pattern.re.lastIndex = 0; // reset after test
        }
      }
    }

    return { valid: true, sourceCount: sources.length, hasSourcesContent, secretsFound };
  } catch {
    return { valid: false, sourceCount: 0, hasSourcesContent: false, secretsFound: [] };
  }
}

/**
 * Check if a response matches SQL dump patterns.
 * Exported for testing.
 */
export function matchesSqlDump(body: string): boolean {
  return /^(--|CREATE\s|INSERT\s|DROP\s)/im.test(body.trim());
}

/**
 * Check if a response looks like a directory listing.
 * Handles Apache, Nginx, IIS, Node.js (Express/serve), and custom directory listings.
 * Exported for testing.
 */
export function matchesDirectoryListing(body: string): boolean {
  // Apache "Index of" page
  if (/Index of\s/i.test(body)) return true;
  // Apache / generic "Parent Directory" link
  if (body.includes('Parent Directory')) return true;
  // Nginx autoindex: "Directory listing for" or sorted file table
  if (/Directory listing for\s/i.test(body)) return true;
  // IIS directory browsing: "Directory Listing" title
  if (/<title>[^<]*directory\s+listing/i.test(body)) return true;

  // Multiple links to files with common extensions — strong signal
  const fileExtRe = /href=["'][^"']*\.(txt|pdf|zip|gz|tar|bak|sql|log|csv|xml|json|doc|xls|md|conf|bkp|old)["']/gi;
  const fileExtCount = (body.match(fileExtRe) ?? []).length;
  if (fileExtCount >= 3) return true;

  // Multiple links pointing to relative paths (e.g., href="filename" or href="dir/")
  const linkCount = (body.match(/<a\s+href=/gi) ?? []).length;
  // Heuristic: 3+ links inside table/pre/ul is likely a directory listing
  if (linkCount >= 3 && /<table|<pre|<ul/i.test(body)) return true;
  // Heuristic: 5+ links with file size patterns (bytes, KB, MB)
  const sizePatterns = (body.match(/\b\d+(\.\d+)?\s*(bytes?|[KMGT]B|[kmgt]b)\b/g) ?? []).length;
  if (linkCount >= 3 && sizePatterns >= 2) return true;

  // JSON directory listing (e.g., express serve-index, custom apps)
  try {
    const parsed = JSON.parse(body);
    if (Array.isArray(parsed) && parsed.length >= 3) {
      // Array of objects with name/size/type fields = directory listing
      const hasNameField = parsed.every((item) => typeof item === 'object' && item !== null && ('name' in item || 'filename' in item));
      if (hasNameField) return true;
      // Array of strings (filenames)
      const allStrings = parsed.every((item) => typeof item === 'string');
      if (allStrings) return true;
    }
  } catch {
    // Not JSON — that's fine
  }

  return false;
}

/**
 * Check if a response looks like API documentation or endpoint listing.
 * Exported for testing.
 */
export function matchesApiDocumentation(body: string): boolean {
  // JSON responses with endpoint/route keys
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === 'object' && parsed !== null) {
      const keys = Object.keys(parsed).map((k) => k.toLowerCase());
      if (keys.some((k) => ['endpoints', 'routes', 'swagger', 'paths'].includes(k))) return true;
    }
  } catch {
    // Not JSON — check HTML
  }
  // HTML containing API documentation clues
  if (/api/i.test(body) && /documentation|endpoints?|routes?/i.test(body)) return true;
  return false;
}

/**
 * Check if a response looks like a Swagger/OpenAPI spec.
 * Exported for testing.
 */
export function matchesSwaggerSpec(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === 'object' && parsed !== null) {
      return 'openapi' in parsed || 'swagger' in parsed;
    }
  } catch {
    // Not valid JSON
  }
  return false;
}

/**
 * Check if a GraphQL introspection response contains schema data.
 * Exported for testing.
 */
export function matchesGraphQLIntrospection(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === 'object' && parsed !== null) {
      // Standard response: { data: { __schema: { types: [...] } } }
      return parsed?.data?.__schema != null;
    }
  } catch {
    // Not valid JSON
  }
  return false;
}

/**
 * Check if a response looks like a macOS .DS_Store file (binary magic bytes).
 * The DS_Store format starts with 0x00000001 followed by "Bud1".
 * Exported for testing.
 */
export function matchesDSStore(body: string): boolean {
  // Check for the Bud1 magic marker (bytes 4-7 of the file)
  return body.includes('Bud1');
}

/**
 * Check if a response looks like a debug endpoint (expvar, debug info, stack traces).
 * Exported for testing.
 */
export function matchesDebugEndpoint(body: string): boolean {
  // Go expvar style: JSON with memstats, cmdline, etc.
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === 'object' && parsed !== null) {
      const keys = Object.keys(parsed).map((k) => k.toLowerCase());
      if (keys.some((k) => ['memstats', 'cmdline', 'goroutines'].includes(k))) return true;
      // "debug" key alone is a strong signal
      if (keys.includes('debug') && keys.length > 1) return true;
    }
  } catch {
    // Not JSON
  }
  // HTML/text debug pages with stack traces or env vars
  if (/stack\s*trace|debug\s*info|environment\s*variables/i.test(body)) return true;
  return false;
}

/**
 * Check if a response looks like a Spring Boot actuator endpoint.
 * Exported for testing.
 */
export function matchesActuatorEndpoint(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === 'object' && parsed !== null) {
      // /actuator/health returns { "status": "UP" }
      if ('status' in parsed) return true;
      // /actuator root returns { "_links": { ... } }
      if ('_links' in parsed) return true;
    }
  } catch {
    // Not valid JSON
  }
  return false;
}

/** Max source map URLs to probe per scan */
const SOURCE_MAP_LIMIT = 10;

/**
 * Detect exposed source maps by:
 * 1. Fetching JS files and extracting //# sourceMappingURL= references
 * 2. Falling back to .js.map suffix probing for JS files without an explicit reference
 * 3. Analyzing source map content for severity (sourcesContent presence, embedded secrets)
 */
async function checkSourceMapExposure(
  context: BrowserContext,
  targets: ScanTargets,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const seenMapUrls = new Set<string>();

  // Collect candidate source map URLs from up to 3 pages
  const pagesToScan = targets.pages.slice(0, 3);
  for (const pageUrl of pagesToScan) {
    if (seenMapUrls.size >= SOURCE_MAP_LIMIT) break;
    try {
      const page = await context.newPage();
      try {
        await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: config.timeout });

        // Gather JS script URLs from the page
        const jsUrls: string[] = await page.evaluate(() => {
          const urls: string[] = [];
          const scripts = document.querySelectorAll('script[src]');
          for (const el of scripts) {
            const src = el.getAttribute('src');
            if (src) {
              try {
                const resolved = new URL(src, window.location.href);
                if (resolved.pathname.endsWith('.js')) {
                  urls.push(resolved.href);
                }
              } catch {
                // skip invalid
              }
            }
          }
          return urls;
        });

        // For each JS file, fetch the last 500 bytes (where sourceMappingURL lives) or full content
        // Then extract sourceMappingURL or fall back to .js.map
        for (const jsUrl of jsUrls.slice(0, 20)) {
          if (seenMapUrls.size >= SOURCE_MAP_LIMIT) break;

          try {
            // Fetch the JS file content (last portion where sourceMappingURL typically appears)
            let jsContent: string | null = null;
            try {
              const jsResp = await page.request.fetch(jsUrl, { timeout: 10000 });
              if (jsResp.status() >= 200 && jsResp.status() < 300) {
                const text = await jsResp.text();
                // sourceMappingURL is always at the end of the file — only need last 500 chars
                jsContent = text.slice(-500);
              }
            } catch {
              jsContent = null;
            }

            if (jsContent) {
              const mappingUrls = extractSourceMappingURLs(jsContent, jsUrl);
              if (mappingUrls.length > 0) {
                for (const mapUrl of mappingUrls) {
                  if (!seenMapUrls.has(mapUrl) && seenMapUrls.size < SOURCE_MAP_LIMIT) {
                    seenMapUrls.add(mapUrl);
                  }
                }
              } else {
                // No explicit sourceMappingURL — try .js.map suffix
                const fallbackMapUrl = `${jsUrl}.map`;
                if (!seenMapUrls.has(fallbackMapUrl) && seenMapUrls.size < SOURCE_MAP_LIMIT) {
                  seenMapUrls.add(fallbackMapUrl);
                }
              }
            }
          } catch (err) {
            log.debug(`Source map discovery: failed to fetch JS ${jsUrl}: ${(err as Error).message}`);
          }
        }

        // Also check inline scripts for sourceMappingURL references
        const inlineMappings: string[] = await page.evaluate(() => {
          const results: string[] = [];
          const scripts = document.querySelectorAll('script:not([src])');
          const re = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
          for (const el of scripts) {
            const text = el.textContent ?? '';
            // Only check end of inline scripts
            const tail = text.slice(-500);
            let m: RegExpExecArray | null;
            re.lastIndex = 0;
            while ((m = re.exec(tail)) !== null) {
              const raw = m[1];
              if (raw.startsWith('data:')) continue;
              try {
                results.push(new URL(raw, window.location.href).href);
              } catch {
                // skip
              }
            }
          }
          return results;
        });

        for (const mapUrl of inlineMappings) {
          if (!seenMapUrls.has(mapUrl) && seenMapUrls.size < SOURCE_MAP_LIMIT) {
            seenMapUrls.add(mapUrl);
          }
        }
      } finally {
        await page.close();
      }
    } catch (err) {
      log.debug(`Source map discovery: failed to scan page ${pageUrl}: ${(err as Error).message}`);
    }
  }

  if (seenMapUrls.size === 0) return findings;

  log.info(`Source map exposure: probing ${seenMapUrls.size} candidate source map URL(s)...`);

  // Probe each candidate source map URL
  try {
    const page = await context.newPage();
    try {
      for (const mapUrl of seenMapUrls) {
        try {
          // HEAD request first for efficiency — check if the resource exists
          const headResp = await page.request.fetch(mapUrl, { method: 'HEAD', timeout: 10000 });
          const headStatus = headResp.status();
          const headCt = headResp.headers()['content-type'] ?? '';

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'HEAD',
            url: mapUrl,
            responseStatus: headStatus,
            phase: 'active-info-disclosure',
          });

          if (headStatus !== 200) continue;

          // HEAD succeeded with 200 — now GET the content to validate
          const getResp = await page.request.fetch(mapUrl, { timeout: 10000 });
          const getStatus = getResp.status();
          if (getStatus < 200 || getStatus >= 300) continue;
          const getBody = (await getResp.text()).slice(0, 100_000);
          const getCt = getResp.headers()['content-type'] ?? '';
          const getResult = { status: getStatus, body: getBody, contentType: getCt };

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: mapUrl,
            responseStatus: getStatus,
            phase: 'active-info-disclosure',
          });

          if (!getResult) continue;

          // Validate: must be JSON with "sources" key, OR content-type application/json + starts with {"version":
          const isJsonCt = getResult.contentType.includes('application/json') || getResult.contentType.includes('application/octet-stream');
          const startsLikeSourceMap = getResult.body.trimStart().startsWith('{"version":');
          if (!isValidSourceMap(getResult.body) && !(isJsonCt && startsLikeSourceMap)) continue;

          // Analyze source map content
          const analysis = analyzeSourceMapContent(getResult.body);
          if (!analysis.valid) continue;

          // Determine severity: high if secrets found in sourcesContent, medium otherwise
          const hasSecrets = analysis.secretsFound.length > 0;
          const severity = hasSecrets ? 'high' as const : 'medium' as const;

          // Build evidence details
          const evidenceParts: string[] = [
            `Source map URL: ${mapUrl}`,
            `Source files exposed: ${analysis.sourceCount}`,
            `sourcesContent present: ${analysis.hasSourcesContent ? 'YES — full original source code accessible' : 'no (mappings only)'}`,
          ];
          if (hasSecrets) {
            evidenceParts.push(`Secrets found in source: ${analysis.secretsFound.join(', ')}`);
          }

          const title = analysis.hasSourcesContent
            ? 'Source Map Exposure — Original Source Code Accessible'
            : 'Source Map Exposure — File Structure Revealed';

          const description = analysis.hasSourcesContent
            ? `A JavaScript source map at ${mapUrl} is publicly accessible and contains the original source code of ${analysis.sourceCount} file(s) via the sourcesContent field. ` +
              'Attackers can reconstruct the entire application source, review business logic, find hardcoded secrets, and identify vulnerabilities without needing to deobfuscate minified code.' +
              (hasSecrets ? ` Additionally, embedded secrets were detected: ${analysis.secretsFound.join(', ')}.` : '')
            : `A JavaScript source map at ${mapUrl} is publicly accessible and reveals the file structure of ${analysis.sourceCount} source file(s). ` +
              'While the original source code is not directly included, the file paths expose internal architecture, technology choices, and potential attack vectors.';

          findings.push({
            id: randomUUID(),
            category: 'info-disclosure',
            severity,
            title,
            description,
            url: mapUrl,
            evidence: evidenceParts.join('\n'),
            response: {
              status: getResult.status,
              headers: { 'content-type': getResult.contentType },
              bodySnippet: getResult.body.slice(0, 200),
            },
            timestamp: new Date().toISOString(),
            confidence: analysis.hasSourcesContent ? 'high' : 'medium',
            evidencePack: {
              curlCommand: `curl -s '${mapUrl}' | head -c 500`,
              detectionMethod: 'source-map-probe',
              responseIndicators: [
                ...(analysis.hasSourcesContent ? ['"sourcesContent" field present'] : []),
                `${analysis.sourceCount} source files listed`,
                ...(hasSecrets ? analysis.secretsFound.map((s) => `Secret: ${s}`) : []),
              ],
            },
          });
        } catch (err) {
          log.debug(`Source map probe: failed for ${mapUrl}: ${(err as Error).message}`);
        }
      }
    } finally {
      await page.close();
    }
  } catch (err) {
    log.debug(`Source map exposure check: page context error: ${(err as Error).message}`);
  }

  if (findings.length > 0) {
    log.info(`Source map exposure: ${findings.length} exposed source map(s) found`);
  }

  return findings;
}

/**
 * Information Disclosure check.
 *
 * Scans for exposed sensitive files and paths that should never be publicly accessible:
 * - .git/config, .git/HEAD — repository exposure
 * - .env, .env.local, .env.production, .env.development — environment variable files
 * - Source maps (.js.map) — full source code exposure via sourceMappingURL + suffix probing
 * - robots.txt — sensitive disallowed paths
 * - Common backup/config files — database dumps, config backups
 */
export const infoDisclosureCheck: ActiveCheck = {
  parallel: true,
  name: 'info-disclosure',
  category: 'info-disclosure',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];
    const origin = new URL(config.targetUrl).origin;

    log.info(`Info disclosure check: probing ${FILE_PROBES.length} sensitive paths + source maps + robots.txt...`);

    // ── 1. Static file probes ──
    for (const probe of FILE_PROBES) {
      const probeUrl = `${origin}${probe.path}`;
      const probeMethod = probe.method ?? 'GET';
      const probeBody = probe.requestBody ?? null;
      try {
        const page = await context.newPage();
        try {
          const fetchOpts: Record<string, unknown> = { timeout: 10000 };
          if (probeMethod !== 'GET') fetchOpts.method = probeMethod;
          if (probeBody) {
            fetchOpts.headers = { 'Content-Type': 'application/json' };
            fetchOpts.data = probeBody;
          }
          const resp = await page.request.fetch(probeUrl, fetchOpts);
          const status = resp.status();
          const body = status >= 200 && status < 300 ? (await resp.text()).slice(0, 5000) : '';
          const result = status >= 200 && status < 300 ? { status, body } : null;

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: probeMethod,
            url: probeUrl,
            responseStatus: status,
            phase: 'active-info-disclosure',
          });

          if (result && probe.matches(result.body)) {
            findings.push({
              id: randomUUID(),
              category: 'info-disclosure',
              severity: probe.severity,
              title: probe.label,
              description: probe.description,
              url: probeUrl,
              evidence: `Response (${result.status}): ${result.body.slice(0, 500)}`,
              response: {
                status: result.status,
                bodySnippet: result.body.slice(0, 200),
              },
              timestamp: new Date().toISOString(),
              confidence: probe.severity === 'high' ? 'high' : probe.severity === 'medium' ? 'medium' : 'low',
              evidencePack: { detectionMethod: 'file-probe' },
            });
          }
        } finally {
          await page.close();
        }
      } catch (err) {
        log.debug(`Info disclosure: failed to probe ${probeUrl}: ${(err as Error).message}`);
      }
    }

    // ── 2. Source map exposure detection ──
    // Discovers source maps via sourceMappingURL comments in JS files AND .js.map suffix probing.
    // Analyzes source map content for severity (sourcesContent, embedded secrets).
    if (targets.pages.length > 0) {
      const sourceMapFindings = await checkSourceMapExposure(context, targets, config, requestLogger);
      findings.push(...sourceMapFindings);
    }

    // ── 3. robots.txt sensitive paths ──
    const robotsUrl = `${origin}/robots.txt`;
    try {
      const page = await context.newPage();
      try {
        const robotsResp = await page.request.fetch(robotsUrl, { timeout: 10000 });
        const robotsStatus = robotsResp.status();
        const robotsResult = robotsStatus >= 200 && robotsStatus < 300
          ? { status: robotsStatus, body: await robotsResp.text() }
          : null;

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: robotsUrl,
          responseStatus: robotsStatus,
          phase: 'active-info-disclosure',
        });

        if (robotsResult) {
          const sensitivePaths = parseSensitiveRobotsPaths(robotsResult.body);
          if (sensitivePaths.length > 0) {
            findings.push({
              id: randomUUID(),
              category: 'info-disclosure',
              severity: 'low',
              title: 'Sensitive Paths in robots.txt',
              description:
                'The robots.txt file contains Disallow entries referencing sensitive paths. ' +
                'While robots.txt does not enforce access control, it reveals the existence of admin panels, APIs, or internal endpoints that attackers can target directly.',
              url: robotsUrl,
              evidence: `Sensitive Disallow paths:\n${sensitivePaths.join('\n')}`,
              response: {
                status: robotsResult.status,
                bodySnippet: robotsResult.body.slice(0, 500),
              },
              timestamp: new Date().toISOString(),
              affectedUrls: sensitivePaths.map((p) => `${origin}${p}`),
              confidence: 'low',
              evidencePack: { detectionMethod: 'file-probe' },
            });
          }
        }
      } finally {
        await page.close();
      }
    } catch (err) {
      log.debug(`Info disclosure: failed to probe robots.txt: ${(err as Error).message}`);
    }

    // ── 4. JS secret scanning ──
    // Download JS files from the first page and scan for hardcoded secrets
    if (targets.pages.length > 0) {
      const firstPage = targets.pages[0];
      try {
        const page = await context.newPage();
        try {
          await page.goto(firstPage, {
            waitUntil: 'domcontentloaded',
            timeout: config.timeout,
          });

          // Get all JS URLs from the page
          const jsUrls: string[] = await page.evaluate(() => {
            const urls: string[] = [];
            const scripts = document.querySelectorAll('script[src]');
            for (const el of scripts) {
              const src = el.getAttribute('src');
              if (src) {
                try {
                  const resolved = new URL(src, window.location.href);
                  if (resolved.pathname.endsWith('.js')) {
                    urls.push(resolved.href);
                  }
                } catch {
                  // skip invalid
                }
              }
            }
            return urls;
          });

          // Also check inline scripts
          const inlineScripts: string[] = await page.evaluate(() => {
            const scripts = document.querySelectorAll('script:not([src])');
            return Array.from(scripts).map((s) => s.textContent ?? '').filter((t) => t.length > 50);
          });

          // Scan inline scripts
          for (const script of inlineScripts.slice(0, 10)) {
            const secrets = scanJsForSecrets(script, firstPage);
            for (const secret of secrets) {
              findings.push({
                id: randomUUID(),
                category: 'info-disclosure',
                severity: secret.severity,
                title: `Hardcoded ${secret.name} in Inline Script`,
                description:
                  `A ${secret.name} was found hardcoded in an inline JavaScript block on ${firstPage}. ` +
                  'Hardcoded secrets in client-side JavaScript are accessible to any visitor and should be rotated immediately.',
                url: firstPage,
                evidence: `Pattern: ${secret.name}\nMatch: ${secret.match}\nContext: ...${secret.context}...`,
                timestamp: new Date().toISOString(),
                confidence: 'high',
                evidencePack: { detectionMethod: 'js-secret-scan' },
              });
            }
          }

          // Scan external JS files (limit to 15 to control scan time)
          let jsSecretsFound = 0;
          for (const jsUrl of jsUrls.slice(0, 15)) {
            try {
              let jsResult: string | null = null;
              try {
                const jsResp = await page.request.fetch(jsUrl, { timeout: 10000 });
                if (jsResp.status() >= 200 && jsResp.status() < 300) {
                  const text = await jsResp.text();
                  // Cap at 1MB to avoid scanning massive bundles
                  jsResult = text.slice(0, 1_000_000);
                }
              } catch {
                jsResult = null;
              }

              if (jsResult) {
                const secrets = scanJsForSecrets(jsResult, jsUrl);
                for (const secret of secrets) {
                  jsSecretsFound++;
                  findings.push({
                    id: randomUUID(),
                    category: 'info-disclosure',
                    severity: secret.severity,
                    title: `Hardcoded ${secret.name} in JavaScript`,
                    description:
                      `A ${secret.name} was found hardcoded in the JavaScript file at ${jsUrl}. ` +
                      'Secrets embedded in client-side JavaScript are accessible to any visitor and can be extracted trivially.',
                    url: jsUrl,
                    evidence: `Pattern: ${secret.name}\nMatch: ${secret.match}\nContext: ...${secret.context}...`,
                    timestamp: new Date().toISOString(),
                    confidence: 'high',
                    evidencePack: { detectionMethod: 'js-secret-scan' },
                  });
                }
              }
            } catch (err) {
              log.debug(`JS secret scan: failed to fetch ${jsUrl}: ${(err as Error).message}`);
            }
          }

          if (jsSecretsFound > 0) {
            log.info(`JS secret scan: found ${jsSecretsFound} hardcoded secret(s) in external JS files`);
          }
        } finally {
          await page.close();
        }
      } catch (err) {
        log.debug(`JS secret scan: failed: ${(err as Error).message}`);
      }
    }

    log.info(`Info disclosure check: ${findings.length} finding(s)`);
    return findings;
  },
};

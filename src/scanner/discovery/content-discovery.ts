import { FastEngine, type FastResponse } from '../fast-engine.js';
import { log } from '../../utils/logger.js';

// Built-in wordlist of ~500 common paths (no external file dependency)
// Organized by category for tech-aware selection
const COMMON_PATHS: Record<string, string[]> = {
  admin: [
    '/admin', '/admin/', '/administrator', '/wp-admin', '/wp-admin/',
    '/manage', '/manager', '/dashboard', '/panel', '/cpanel',
    '/admin/login', '/admin/dashboard', '/backend', '/console',
    '/admin.php', '/login.php', '/user/login', '/accounts/login',
    '/webmaster', '/sysadmin', '/moderator', '/staff',
    '/portal', '/control', '/controlpanel', '/admin-console',
    '/admin/settings', '/admin/users', '/admin/config',
  ],
  api: [
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
    '/api/docs', '/api/swagger', '/api/spec', '/api/openapi',
    '/swagger.json', '/swagger.yaml', '/openapi.json',
    '/api-docs', '/docs/api', '/graphql', '/graphiql',
    '/api/health', '/api/status', '/api/version', '/api/info',
    '/api/config', '/api/debug', '/api/test',
    '/.well-known/openapi.yaml',
    '/swagger-ui.html', '/swagger-ui/', '/swagger-resources',
    '/v1', '/v2', '/v3',
    '/api/v1/docs', '/api/v2/docs',
    '/api/users', '/api/auth', '/api/login', '/api/register',
    '/api/admin', '/api/upload', '/api/files',
    '/api/graphql', '/api/search', '/api/export',
  ],
  debug: [
    '/debug', '/debug/', '/trace', '/phpinfo.php', '/info.php',
    '/server-info', '/server-status', '/_debug', '/__debug',
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
    '/actuator/configprops', '/actuator/mappings', '/actuator/metrics',
    '/actuator/info', '/actuator/loggers', '/actuator/threaddump',
    '/_profiler', '/_profiler/latest',
    '/elmah.axd', '/trace.axd',
    '/rails/info', '/rails/info/routes',
    '/_ignition/health-check',
    '/telescope', '/horizon',
    '/__inspect', '/__diagnostics', '/__health',
    '/debug/vars', '/debug/pprof', '/debug/requests',
    '/metrics', '/prometheus',
    '/health', '/healthz', '/healthcheck', '/ready', '/readyz',
    '/status', '/ping', '/info',
  ],
  config: [
    '/.env', '/.env.local', '/.env.production', '/.env.staging',
    '/.env.backup', '/.env.old', '/.env.dev', '/.env.development',
    '/config.json', '/config.yaml', '/config.yml', '/config.xml',
    '/settings.json', '/settings.yaml',
    '/web.config', '/wp-config.php', '/wp-config.php.bak',
    '/composer.json', '/package.json', '/Gemfile',
    '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/.dockerenv',
    '/application.properties', '/application.yml',
    '/appsettings.json', '/appsettings.Development.json',
    '/parameters.yml', '/database.yml',
    '/.htaccess', '/.htpasswd',
    '/nginx.conf', '/httpd.conf',
    '/firebase.json', '/now.json', '/vercel.json',
    '/netlify.toml', '/fly.toml',
  ],
  backup: [
    '/backup', '/backup/', '/backups', '/db.sql', '/dump.sql',
    '/database.sql', '/backup.sql', '/backup.zip', '/backup.tar.gz',
    '/site.zip', '/www.zip', '/htdocs.zip',
    '/.git', '/.git/HEAD', '/.git/config',
    '/.svn', '/.svn/entries',
    '/.hg',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/security.txt', '/.well-known/security.txt',
    '/humans.txt', '/readme.html', '/readme.txt', '/README.md',
    '/CHANGELOG.md', '/LICENSE',
    '/old', '/archive', '/temp', '/tmp',
    '/bak', '/copy', '/orig',
    '/.DS_Store', '/Thumbs.db',
    '/error_log', '/access_log',
    '/logs', '/log', '/logs/',
  ],
  sensitive: [
    '/.aws/credentials', '/.ssh/id_rsa', '/.ssh/authorized_keys',
    '/id_rsa', '/id_dsa', '/id_ecdsa',
    '/secrets.json', '/credentials.json',
    '/.npmrc', '/.yarnrc',
    '/.bash_history', '/.zsh_history',
    '/phpMyAdmin', '/phpmyadmin', '/pma',
    '/adminer', '/adminer.php',
    '/wp-config.php.bak', '/wp-config.php.old',
    '/.svn/wc.db', '/.git/objects/',
    '/server.key', '/server.pem', '/private.key',
  ],
  wordpress: [
    '/wp-login.php', '/wp-signup.php', '/xmlrpc.php',
    '/wp-json', '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts',
    '/wp-json/oembed/1.0/embed',
    '/wp-content/uploads/', '/wp-content/plugins/',
    '/wp-content/themes/', '/wp-includes/',
    '/wp-cron.php', '/wp-trackback.php',
    '/wp-content/debug.log',
    '/wp-admin/install.php', '/wp-admin/setup-config.php',
  ],
  rails: [
    '/rails/info', '/rails/info/properties', '/rails/info/routes',
    '/rails/mailers',
    '/sidekiq', '/sidekiq/stats',
    '/letter_opener',
  ],
  laravel: [
    '/_ignition/health-check', '/_ignition/execute-solution',
    '/telescope', '/horizon',
    '/storage/', '/storage/logs/',
    '/storage/framework/sessions/',
    '/.env.example',
  ],
  nextjs: [
    '/_next/data/', '/_next/static/',
    '/api/auth/session', '/api/auth/providers',
    '/api/auth/csrf', '/api/auth/signin',
    '/_next/image',
    '/api/trpc',
  ],
  django: [
    '/admin/', '/admin/login/',
    '/static/', '/media/',
    '/__debug__/', '/__debug__/sql/',
    '/api-auth/', '/api-auth/login/',
    '/django-admin/',
  ],
  spring: [
    '/actuator', '/actuator/health', '/actuator/env',
    '/actuator/beans', '/actuator/configprops',
    '/actuator/mappings', '/actuator/metrics',
    '/actuator/info', '/actuator/loggers',
    '/actuator/threaddump', '/actuator/heapdump',
    '/actuator/scheduledtasks', '/actuator/httptrace',
    '/h2-console', '/h2-console/',
    '/swagger-ui.html', '/swagger-ui/',
  ],
  dotnet: [
    '/elmah.axd', '/trace.axd',
    '/web.config', '/applicationhost.config',
    '/appsettings.json', '/appsettings.Development.json',
    '/_blazor',
    '/hangfire', '/hangfire/dashboard',
  ],
};

export interface ContentDiscoveryOptions {
  targetUrl: string;
  concurrency?: number; // default 20
  timeout?: number; // per-request timeout, default 5000
  requestDelay?: number; // ms between requests, default 50
  proxy?: string;
  userAgent?: string;
  detectedTech?: string[]; // tech stack for wordlist selection
  detectedFramework?: string; // framework name
  maxPaths?: number; // limit total paths to test, default 500
  extraHeaders?: Record<string, string>;
}

export interface DiscoveredEndpoint {
  url: string;
  status: number;
  contentType: string;
  contentLength: number;
  category: string; // which wordlist category matched
  interesting: boolean; // worth testing further
}

interface PathEntry {
  path: string;
  category: string;
}

/**
 * Select paths to test based on detected framework.
 * Always includes generic categories (admin, api, debug, config, backup, sensitive).
 * Adds framework-specific paths when a matching framework is detected.
 */
export function selectPaths(framework: string | undefined, maxPaths: number): PathEntry[] {
  const paths: PathEntry[] = [];

  // Always include common (non-framework-specific) paths
  const genericCategories = ['admin', 'api', 'debug', 'config', 'backup', 'sensitive'];
  for (const cat of genericCategories) {
    const catPaths = COMMON_PATHS[cat];
    if (catPaths) {
      for (const p of catPaths) paths.push({ path: p, category: cat });
    }
  }

  // Add framework-specific paths based on detection
  const fw = (framework ?? '').toLowerCase();

  const frameworkMapping: Array<{ keywords: string[]; category: string }> = [
    { keywords: ['wordpress', 'wp'], category: 'wordpress' },
    { keywords: ['rails', 'ruby'], category: 'rails' },
    { keywords: ['laravel', 'php'], category: 'laravel' },
    { keywords: ['next', 'nuxt'], category: 'nextjs' },
    { keywords: ['django', 'python'], category: 'django' },
    { keywords: ['spring', 'java'], category: 'spring' },
    { keywords: ['.net', 'asp', 'blazor', 'dotnet'], category: 'dotnet' },
  ];

  for (const mapping of frameworkMapping) {
    if (mapping.keywords.some(kw => fw.includes(kw))) {
      const catPaths = COMMON_PATHS[mapping.category];
      if (catPaths) {
        for (const p of catPaths) paths.push({ path: p, category: mapping.category });
      }
    }
  }

  // Deduplicate by path and limit
  const seen = new Set<string>();
  return paths.filter(p => {
    if (seen.has(p.path)) return false;
    seen.add(p.path);
    return true;
  }).slice(0, maxPaths);
}

/**
 * Determine if a response is "interesting" enough to report.
 * Interesting means the endpoint likely exists and has security relevance.
 */
export function isInteresting(resp: FastResponse, category: string): boolean {
  // 404 is never interesting
  if (resp.status === 404) return false;

  // 200 on sensitive paths is always interesting
  if (resp.status === 200) {
    if (['admin', 'debug', 'config', 'backup', 'sensitive'].includes(category)) return true;
    // API docs / endpoints with actual content are interesting
    if (category === 'api' && resp.body.length > 100) return true;
    // Framework-specific 200s are interesting
    if (['wordpress', 'rails', 'laravel', 'django', 'spring', 'dotnet'].includes(category)) return true;
  }

  // 403 on admin/debug/sensitive = exists but forbidden (worth noting)
  if (resp.status === 403 && ['admin', 'debug', 'sensitive'].includes(category)) return true;

  // 405 Method Not Allowed on API endpoints = endpoint exists
  if (resp.status === 405 && ['api'].includes(category)) return true;

  // Redirect to login from admin = endpoint exists behind auth
  if ((resp.status === 301 || resp.status === 302) && ['admin', 'debug'].includes(category)) return true;

  return false;
}

/**
 * Classify a discovered endpoint URL into the appropriate recon category.
 * Returns 'page' for HTML pages or 'api' for API/JSON endpoints.
 */
function classifyEndpoint(url: string, contentType: string, category: string): 'page' | 'api' {
  if (category === 'api') return 'api';
  if (/application\/json|application\/xml|application\/graphql/i.test(contentType)) return 'api';
  if (/\/api\//i.test(url) || /\/graphql/i.test(url)) return 'api';
  return 'page';
}

/**
 * Run content discovery against a target.
 * Returns discovered endpoints sorted by interest level.
 */
export async function discoverContent(
  options: ContentDiscoveryOptions,
): Promise<DiscoveredEndpoint[]> {
  const {
    targetUrl,
    concurrency = 20,
    timeout = 5000,
    requestDelay = 50,
    proxy,
    userAgent,
    detectedFramework,
    maxPaths = 500,
    extraHeaders,
  } = options;

  // Select paths based on detected tech
  const paths = selectPaths(detectedFramework, maxPaths);
  log.info(`Content discovery: testing ${paths.length} paths against ${targetUrl}`);

  const engine = new FastEngine({
    concurrency,
    requestDelay,
    proxy,
    userAgent: userAgent ?? 'Mozilla/5.0 (compatible; SecBot/2.0)',
    rateLimitRps: concurrency,
    defaultHeaders: extraHeaders,
  });

  // Build full URLs
  const base = targetUrl.replace(/\/$/, '');
  const urls = paths.map(p => `${base}${p.path}`);

  // Probe with HEAD first (fast) — accept 200, 201, 301, 302, 403, 405
  const headResults = await engine.probe(urls, [200, 201, 301, 302, 403, 405], 'HEAD');

  // For HEAD-discovered endpoints, do a GET to get body/content-type details
  const interestingUrls = headResults
    .filter(resp => {
      const pathObj = paths.find(p => resp.url.endsWith(p.path) || resp.url === `${base}${p.path}`);
      const category = pathObj?.category ?? 'unknown';
      return isInteresting(resp, category);
    })
    .map(resp => resp.url);

  // GET only the interesting ones for detailed analysis (body content, content-type)
  const getResults = interestingUrls.length > 0
    ? await engine.batch(interestingUrls, { method: 'GET', timeout })
    : [];

  // Build response map from GET results for enrichment
  const getResultMap = new Map<string, FastResponse>();
  for (const resp of getResults) {
    if (resp) getResultMap.set(resp.url, resp);
  }

  const discovered: DiscoveredEndpoint[] = [];

  for (const resp of headResults) {
    const pathObj = paths.find(p => resp.url.endsWith(p.path) || resp.url === `${base}${p.path}`);
    const category = pathObj?.category ?? 'unknown';

    // Use GET result if available for richer data, otherwise HEAD
    const enriched = getResultMap.get(resp.url);
    const contentType = (enriched ?? resp).headers['content-type'] ?? '';
    const contentLength = parseInt((enriched ?? resp).headers['content-length'] ?? '0', 10) || (enriched?.body.length ?? 0);

    const interesting = isInteresting(resp, category);

    discovered.push({
      url: resp.url,
      status: resp.status,
      contentType,
      contentLength,
      category,
      interesting,
    });
  }

  // Sort: interesting first, then by category priority
  discovered.sort((a, b) => {
    if (a.interesting !== b.interesting) return a.interesting ? -1 : 1;
    return a.status - b.status;
  });

  const stats = engine.getStats();
  log.info(
    `Content discovery: found ${discovered.length} endpoints ` +
    `(${discovered.filter(d => d.interesting).length} interesting) ` +
    `in ${stats.total} requests`,
  );

  return discovered;
}

/**
 * Merge content discovery results into existing recon EndpointMap.
 * Adds newly discovered pages and API routes that weren't found during crawling.
 */
export function mergeIntoEndpoints(
  discovered: DiscoveredEndpoint[],
  existingPages: string[],
  existingApiRoutes: string[],
): { newPages: string[]; newApiRoutes: string[] } {
  const existingPageSet = new Set(existingPages);
  const existingApiSet = new Set(existingApiRoutes);

  const newPages: string[] = [];
  const newApiRoutes: string[] = [];

  for (const endpoint of discovered) {
    if (!endpoint.interesting) continue;

    const kind = classifyEndpoint(endpoint.url, endpoint.contentType, endpoint.category);

    if (kind === 'api') {
      if (!existingApiSet.has(endpoint.url)) {
        newApiRoutes.push(endpoint.url);
        existingApiSet.add(endpoint.url);
      }
    } else {
      if (!existingPageSet.has(endpoint.url)) {
        newPages.push(endpoint.url);
        existingPageSet.add(endpoint.url);
      }
    }
  }

  return { newPages, newApiRoutes };
}

export { COMMON_PATHS };

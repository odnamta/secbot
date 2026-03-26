import dns from 'node:dns/promises';
import { log } from '../../utils/logger.js';
import { FastEngine, type FastResponse } from '../fast-engine.js';

export interface SubdomainResult {
  subdomain: string;
  ips: string[];
  cname?: string;
}

export interface HttpProbeResult {
  subdomain: string;
  url: string;
  status: number;
  /** Response time in milliseconds */
  timeMs: number;
  /** Server header value, if present */
  server?: string;
  /** Whether the probe followed a redirect */
  redirected: boolean;
  /** Final URL after redirects (if redirected) */
  finalUrl?: string;
  /** Page title extracted from HTML (first 200 chars) */
  title?: string;
}

export interface SubdomainEnumResult {
  /** All DNS-resolved subdomains */
  resolved: SubdomainResult[];
  /** HTTP-probed subdomains (only those that responded) */
  httpAlive: HttpProbeResult[];
}

/**
 * Comprehensive subdomain prefix wordlist (~550 entries).
 * Covers: infrastructure, dev/staging, services, databases, monitoring,
 * communication, auth/SSO, e-commerce, mobile, regional, numbered,
 * cloud/k8s, security, and miscellaneous patterns.
 */
export const COMMON_SUBDOMAINS: string[] = [
  // ─── Standard / Core ────────────────────────────────────────────
  'www', 'www2', 'www3', 'mail', 'mail2', 'ftp', 'smtp', 'pop', 'pop3',
  'imap', 'webmail', 'email', 'mx', 'mx1', 'mx2',

  // ─── Development / Staging ──────────────────────────────────────
  'dev', 'dev2', 'dev3', 'development', 'develop',
  'staging', 'stage', 'stg', 'stg2',
  'test', 'test2', 'test3', 'testing',
  'qa', 'qa2', 'uat', 'uat2',
  'sandbox', 'sandbox2', 'demo', 'demo2',
  'preview', 'beta', 'alpha',
  'canary', 'nightly', 'rc', 'release',
  'pre-prod', 'preprod', 'pre-production',
  'hotfix', 'feature', 'experiment',
  'int', 'integration',
  'perf', 'performance', 'load-test', 'loadtest',
  'review', 'pr', 'branch',

  // ─── Infrastructure / Core Services ─────────────────────────────
  'api', 'api2', 'api3', 'api-v2', 'api-v3',
  'api-staging', 'api-dev', 'api-test', 'api-prod',
  'api-internal', 'api-gateway', 'api-proxy',
  'app', 'app2', 'app3', 'application',
  'portal', 'portal2', 'gateway', 'gw',
  'admin', 'admin2', 'administrator', 'panel',
  'dashboard', 'dash',
  'manage', 'management', 'manager',
  'internal', 'internal2', 'intranet',
  'private', 'corp', 'corporate',
  'vpn', 'vpn2', 'remote', 'remote2',
  'citrix', 'rdp', 'ssh', 'bastion', 'jump',
  'extranet', 'partner', 'partners',

  // ─── CDN / Static Assets ────────────────────────────────────────
  'cdn', 'cdn2', 'cdn3',
  'static', 'static2', 'assets', 'asset',
  'media', 'media2', 'images', 'img', 'img2',
  'files', 'file',
  'upload', 'uploads', 'download', 'downloads',
  'content', 'resources', 'resource',
  'fonts', 'video', 'videos',

  // ─── Databases ──────────────────────────────────────────────────
  'db', 'db2', 'db3', 'database',
  'mysql', 'mysql2', 'postgres', 'postgresql', 'pgsql',
  'redis', 'redis2', 'mongo', 'mongodb',
  'elastic', 'elasticsearch', 'es',
  'cassandra', 'couchdb', 'dynamodb',
  'mariadb', 'mssql', 'sql',
  'memcached', 'memcache',
  'neo4j', 'influxdb',

  // ─── Search / Analytics ─────────────────────────────────────────
  'search', 'search2', 'solr',
  'kibana', 'grafana', 'grafana2',
  'analytics', 'stats', 'statistics',
  'tracking', 'track',
  'datadog', 'newrelic',

  // ─── CI/CD / DevOps ─────────────────────────────────────────────
  'jenkins', 'jenkins2', 'ci', 'cd',
  'build', 'builds', 'deploy', 'deployment',
  'gitlab', 'github', 'bitbucket',
  'drone', 'circleci', 'travis',
  'bamboo', 'teamcity', 'concourse',
  'argo', 'argocd', 'flux',
  'nexus', 'artifactory', 'artifacts',
  'sonar', 'sonarqube', 'codecov',
  'registry', 'registry2',
  'repo', 'repos', 'repository',
  'git', 'svn', 'hg',
  'packages', 'npm', 'pypi',

  // ─── Project Management / Collaboration ─────────────────────────
  'jira', 'jira2', 'confluence', 'confluence2',
  'wiki', 'wiki2', 'docs', 'docs2', 'documentation',
  'notion', 'asana', 'trello', 'basecamp',
  'redmine', 'trac', 'mantis', 'bugzilla',
  'projects', 'project', 'tasks', 'tickets',

  // ─── Monitoring / Observability ─────────────────────────────────
  'sentry', 'sentry2',
  'monitoring', 'monitor', 'mon',
  'metrics', 'prometheus', 'prom',
  'status', 'status2', 'statuspage',
  'health', 'healthcheck',
  'uptime', 'uptimerobot',
  'log', 'logs', 'logging', 'logger',
  'elk', 'splunk', 'graylog', 'logstash',
  'jaeger', 'zipkin', 'tempo',
  'alertmanager', 'alerts', 'alert',
  'pagerduty', 'opsgenie',
  'nagios', 'zabbix', 'icinga', 'cacti',

  // ─── Backup / Archive ──────────────────────────────────────────
  'backup', 'backup2', 'backups', 'bak',
  'archive', 'archives',
  'old', 'old2', 'legacy', 'deprecated',
  'temp', 'tmp', 'scratch',
  'snapshot', 'snapshots',

  // ─── Proxy / Load Balancer / Network ────────────────────────────
  'cache', 'cache2', 'varnish',
  'proxy', 'proxy2', 'reverse-proxy',
  'lb', 'lb2', 'loadbalancer', 'load-balancer',
  'nginx', 'apache', 'haproxy', 'traefik', 'envoy',
  'edge', 'edge2',
  'ns1', 'ns2', 'ns3', 'ns4',
  'dns', 'dns2',
  'ntp', 'time',
  'relay', 'relay2',
  'firewall', 'fw', 'waf',

  // ─── Communication / Messaging ──────────────────────────────────
  'chat', 'chat2', 'im', 'messenger',
  'slack', 'teams', 'mattermost', 'rocketchat',
  'meet', 'meeting', 'meetings',
  'zoom', 'webex', 'conference',
  'voip', 'sip', 'pbx', 'phone', 'tel',
  'irc', 'xmpp', 'jabber',

  // ─── Content / Marketing ────────────────────────────────────────
  'blog', 'blog2', 'news', 'press',
  'support', 'support2', 'help', 'helpdesk', 'help-desk',
  'kb', 'knowledgebase', 'knowledge',
  'faq', 'faqs',
  'forum', 'forums', 'community', 'communities',
  'social', 'feed', 'rss',
  'landing', 'lp', 'promo', 'campaign',
  'events', 'event', 'webinar', 'webinars',

  // ─── Auth / SSO / Identity ──────────────────────────────────────
  'auth', 'auth2', 'authentication',
  'sso', 'sso2', 'cas',
  'login', 'login2', 'signin', 'sign-in',
  'oauth', 'oauth2', 'oidc',
  'identity', 'id', 'idp',
  'accounts', 'account', 'myaccount', 'my',
  'register', 'signup', 'sign-up',
  'password', 'pwd', 'reset',
  'token', 'tokens',
  'saml', 'adfs', 'ldap',
  'keycloak', 'okta', 'auth0',
  'mfa', '2fa', 'otp',
  'directory', 'ad',

  // ─── E-commerce / Payments ──────────────────────────────────────
  'shop', 'shop2', 'store', 'store2',
  'checkout', 'cart', 'basket',
  'payment', 'payments', 'pay',
  'billing', 'billing2', 'invoice', 'invoices',
  'orders', 'order',
  'catalog', 'catalogue', 'products', 'product',
  'marketplace', 'market',
  'pricing', 'plans', 'subscription', 'subscriptions',
  'stripe', 'paypal',

  // ─── Mobile / API ──────────────────────────────────────────────
  'mobile', 'm', 'mobi',
  'api-mobile', 'mapi', 'm-api',
  'ios', 'android', 'app-api',
  'push', 'notifications', 'notify',
  'ws', 'wss', 'websocket', 'socket', 'realtime',

  // ─── Regional / Geo ─────────────────────────────────────────────
  'us', 'us-east', 'us-west',
  'eu', 'eu-west', 'eu-central',
  'asia', 'ap', 'ap-south', 'ap-southeast',
  'au', 'uk', 'de', 'fr', 'jp', 'cn', 'kr',
  'in', 'sg', 'th', 'vn', 'ph',
  'br', 'ca', 'ru', 'za',
  'global', 'local', 'geo',
  'na', 'sa', 'emea', 'apac', 'latam',

  // ─── Numbered / Server ──────────────────────────────────────────
  'web1', 'web2', 'web3', 'web4',
  'srv1', 'srv2', 'srv3',
  'server1', 'server2', 'server3',
  'node1', 'node2', 'node3',
  'worker1', 'worker2', 'worker3',
  'host1', 'host2', 'host3', 'host4',
  'dc1', 'dc2', 'dc3',
  'rack1', 'rack2',
  'vm1', 'vm2', 'vm3',
  'vps1', 'vps2',
  'box1', 'box2',

  // ─── Cloud / Containers / K8s ───────────────────────────────────
  'k8s', 'kubernetes', 'kube',
  'docker', 'container', 'containers',
  'cluster', 'cluster2',
  'aws', 'gcp', 'azure', 'cloud', 'cloud2',
  's3', 'storage', 'storage2', 'bucket', 'blobs',
  'lambda', 'functions', 'serverless',
  'fargate', 'ecs', 'eks', 'aks', 'gke',
  'terraform', 'pulumi', 'ansible',
  'consul', 'consul2', 'vault', 'vault2',
  'nomad', 'istio', 'linkerd',
  'rancher', 'openshift',
  'harbor', 'quay',

  // ─── Security / Compliance ──────────────────────────────────────
  'secure', 'security',
  'ssl', 'tls', 'https',
  'cert', 'certs', 'certificates', 'pki',
  'scan', 'scanner',
  'pentest', 'audit',
  'compliance', 'gdpr', 'pci',
  'soc', 'siem',

  // ─── Message Queues / Streaming ─────────────────────────────────
  'rabbitmq', 'rabbit', 'rmq',
  'kafka', 'kafka2',
  'activemq', 'artemis',
  'nats', 'pulsar',
  'queue', 'queues', 'mq',
  'stream', 'streaming',
  'celery', 'sidekiq',

  // ─── CMS / Web Frameworks ──────────────────────────────────────
  'cms', 'cms2',
  'wordpress', 'wp', 'wp2',
  'drupal', 'joomla', 'magento',
  'ghost', 'strapi', 'contentful',
  'typo3', 'umbraco', 'sitecore',

  // ─── Business Tools / ERP / CRM ─────────────────────────────────
  'crm', 'crm2', 'erp', 'erp2',
  'hr', 'hrm', 'hris', 'payroll',
  'finance', 'accounting', 'ledger',
  'inventory', 'warehouse',
  'procurement', 'purchasing',
  'sales', 'marketing',
  'service', 'services',
  'operations', 'ops',

  // ─── API Protocols ──────────────────────────────────────────────
  'graphql', 'gql',
  'grpc', 'rest',
  'soap', 'wsdl', 'xml-rpc',

  // ─── Miscellaneous ──────────────────────────────────────────────
  'data', 'data2',
  'report', 'reports', 'reporting',
  'export', 'import',
  'batch', 'jobs', 'cron', 'scheduler',
  'worker', 'workers',
  'hook', 'hooks', 'webhook', 'webhooks',
  'callback', 'callbacks',
  'redirect', 'link', 'links', 'go', 'r',
  'share', 'shared',
  'public', 'pub',
  'origin', 'src', 'source',
  'home', 'main', 'default',
  'new', 'v2', 'v3', 'next',
  'lab', 'labs',
  'space', 'spaces',
  'office', 'o365',
];

/**
 * Resolve a single subdomain, returning its A records and optional CNAME.
 * Returns null if the subdomain does not resolve.
 */
async function resolveSubdomain(fqdn: string): Promise<SubdomainResult | null> {
  let ips: string[] = [];
  let cname: string | undefined;

  try {
    ips = await dns.resolve4(fqdn);
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'SERVFAIL' || code === 'ETIMEOUT') {
      return null;
    }
    // Unknown DNS error — treat as not found
    return null;
  }

  // Try to get CNAME (optional, non-blocking)
  try {
    const cnames = await dns.resolveCname(fqdn);
    if (cnames.length > 0) {
      cname = cnames[0];
    }
  } catch {
    // CNAME not found or error — that's fine, most records won't have one
  }

  return { subdomain: fqdn, ips, cname };
}

/**
 * Enumerate subdomains of a domain via DNS brute-force.
 *
 * Tries common subdomain prefixes against the target domain using DNS resolution.
 * Runs concurrently with a configurable concurrency limit (default: 10).
 *
 * @param domain - The base domain to enumerate (e.g., "example.com")
 * @param concurrency - Max concurrent DNS lookups (default: 10)
 * @returns Array of resolved subdomains with their IPs and optional CNAME
 */
export async function enumerateSubdomains(
  domain: string,
  concurrency: number = 10,
): Promise<SubdomainResult[]> {
  const prefixes = COMMON_SUBDOMAINS;
  const results: SubdomainResult[] = [];

  log.info(`Checking ${prefixes.length} subdomains for ${domain}...`);

  // Process in batches to respect concurrency limit
  for (let i = 0; i < prefixes.length; i += concurrency) {
    const batch = prefixes.slice(i, i + concurrency);
    const promises = batch.map((prefix) => {
      const fqdn = `${prefix}.${domain}`;
      return resolveSubdomain(fqdn);
    });

    const batchResults = await Promise.all(promises);
    for (const result of batchResults) {
      if (result) {
        results.push(result);
        log.debug(`Found: ${result.subdomain} -> ${result.ips.join(', ')}${result.cname ? ` (CNAME: ${result.cname})` : ''}`);
      }
    }
  }

  log.info(`Subdomain enumeration complete: ${results.length} found out of ${prefixes.length} checked`);
  return results;
}

/**
 * Extract a title from an HTML body (first <title> tag, truncated to 200 chars).
 */
function extractTitle(body: string): string | undefined {
  const match = body.match(/<title[^>]*>([^<]*)<\/title>/i);
  if (!match) return undefined;
  const title = match[1].trim();
  return title.length > 200 ? title.slice(0, 200) + '...' : title;
}

/**
 * Probe discovered subdomains over HTTP/HTTPS to find live web services.
 *
 * For each subdomain, tries HTTPS first (preferred), then HTTP.
 * Uses the FastEngine for concurrent probing with configurable concurrency.
 *
 * @param subdomains - Array of SubdomainResult from DNS enumeration
 * @param options - Probing options (concurrency, timeout, etc.)
 * @returns Array of HttpProbeResult for subdomains that responded
 */
export async function probeSubdomains(
  subdomains: SubdomainResult[],
  options: {
    concurrency?: number;
    requestDelay?: number;
    timeout?: number;
    proxy?: string;
    userAgent?: string;
    /** Status codes to consider as "alive" (default: 200, 201, 301, 302, 307, 308, 401, 403, 405, 500) */
    acceptStatuses?: number[];
  } = {},
): Promise<HttpProbeResult[]> {
  if (subdomains.length === 0) {
    return [];
  }

  const concurrency = options.concurrency ?? 20;
  const requestDelay = options.requestDelay ?? 50;
  const timeout = options.timeout ?? 8000;
  const acceptStatuses = options.acceptStatuses ?? [
    200, 201, 301, 302, 307, 308, 401, 403, 405, 500,
  ];

  log.info(`HTTP-probing ${subdomains.length} subdomains (concurrency: ${concurrency})...`);

  const engine = new FastEngine({
    concurrency,
    requestDelay,
    proxy: options.proxy,
    userAgent: options.userAgent ?? 'Mozilla/5.0 (compatible; SecBot/2.0)',
  });

  // Build URL list: try HTTPS first for each subdomain
  const httpsUrls = subdomains.map(s => `https://${s.subdomain}`);
  const httpUrls = subdomains.map(s => `http://${s.subdomain}`);

  // Phase 1: Probe HTTPS
  const httpsResults = await engine.batch(httpsUrls, {
    method: 'GET',
    timeout,
  });

  // Collect alive HTTPS subdomains
  const alive = new Map<string, HttpProbeResult>();
  const needsHttp: string[] = [];

  for (let i = 0; i < subdomains.length; i++) {
    const resp = httpsResults[i];
    const sub = subdomains[i].subdomain;

    if (resp && acceptStatuses.includes(resp.status)) {
      alive.set(sub, {
        subdomain: sub,
        url: `https://${sub}`,
        status: resp.status,
        timeMs: resp.timeMs,
        server: resp.headers['server'],
        redirected: resp.redirected,
        finalUrl: resp.redirected ? resp.url : undefined,
        title: extractTitle(resp.body),
      });
    } else {
      // HTTPS failed or returned unacceptable status — try HTTP
      needsHttp.push(sub);
    }
  }

  // Phase 2: Probe HTTP for subdomains where HTTPS failed
  if (needsHttp.length > 0) {
    log.debug(`HTTPS probing found ${alive.size} alive; trying HTTP for ${needsHttp.length} remaining...`);

    const httpFallbackUrls = needsHttp.map(s => `http://${s}`);
    const httpResults = await engine.batch(httpFallbackUrls, {
      method: 'GET',
      timeout,
    });

    for (let i = 0; i < needsHttp.length; i++) {
      const resp = httpResults[i];
      const sub = needsHttp[i];

      if (resp && acceptStatuses.includes(resp.status)) {
        alive.set(sub, {
          subdomain: sub,
          url: `http://${sub}`,
          status: resp.status,
          timeMs: resp.timeMs,
          server: resp.headers['server'],
          redirected: resp.redirected,
          finalUrl: resp.redirected ? resp.url : undefined,
          title: extractTitle(resp.body),
        });
      }
    }
  }

  const results = Array.from(alive.values());
  const stats = engine.getStats();
  log.info(`HTTP probing complete: ${results.length} alive out of ${subdomains.length} (${stats.total} requests, ${stats.errors} errors)`);

  return results;
}

/**
 * Full subdomain enumeration pipeline: DNS brute-force + HTTP probing.
 *
 * 1. DNS brute-force with the built-in 550+ prefix wordlist
 * 2. HTTP probing to discover which subdomains serve web content
 *
 * @param domain - Base domain to enumerate (e.g., "example.com")
 * @param options - Configuration options
 * @returns Combined DNS resolution + HTTP probing results
 */
export async function enumerateAndProbeSubdomains(
  domain: string,
  options: {
    dnsConcurrency?: number;
    httpConcurrency?: number;
    requestDelay?: number;
    timeout?: number;
    proxy?: string;
    userAgent?: string;
  } = {},
): Promise<SubdomainEnumResult> {
  // Step 1: DNS brute-force
  const resolved = await enumerateSubdomains(domain, options.dnsConcurrency ?? 10);

  // Step 2: HTTP probing
  const httpAlive = await probeSubdomains(resolved, {
    concurrency: options.httpConcurrency ?? 20,
    requestDelay: options.requestDelay ?? 50,
    timeout: options.timeout ?? 8000,
    proxy: options.proxy,
    userAgent: options.userAgent,
  });

  return { resolved, httpAlive };
}

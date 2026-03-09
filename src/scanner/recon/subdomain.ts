import dns from 'node:dns/promises';
import { log } from '../../utils/logger.js';

export interface SubdomainResult {
  subdomain: string;
  ips: string[];
  cname?: string;
}

/**
 * Common subdomain prefixes to brute-force against a target domain.
 * Covers infrastructure, dev/staging, services, databases, monitoring, and business tools.
 */
export const COMMON_SUBDOMAINS: string[] = [
  'www', 'mail', 'api', 'dev', 'staging', 'admin', 'test', 'beta',
  'vpn', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'cdn',
  'app', 'portal', 'git', 'ci', 'jenkins', 'jira', 'confluence',
  'grafana', 'prometheus', 'kibana', 'elastic', 'redis', 'mongo',
  'mysql', 'postgres', 'rabbitmq', 'kafka', 'vault', 'consul',
  'docker', 'k8s', 'kubernetes', 'registry', 'nexus', 'sonar',
  'sentry', 'status', 'docs', 'wiki', 'blog', 'shop', 'store',
  'cms', 'crm', 'erp', 'hrm', 'sso', 'auth', 'login', 'oauth',
  'uat', 'qa', 'demo', 'sandbox', 'internal', 'intranet',
  'remote', 'proxy', 'webmail', 'mx', 'ns3', 'backup',
  'monitoring', 'logs', 'assets', 'static', 'media', 'img',
  'images', 'files', 'download', 'upload', 'secure', 'gateway',
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

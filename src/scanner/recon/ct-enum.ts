import dns from 'node:dns/promises';
import { log } from '../../utils/logger.js';
import type { SubdomainResult } from './subdomain.js';

/**
 * Response shape from crt.sh JSON API.
 */
interface CrtShEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  result_count: number;
}

/**
 * Query crt.sh Certificate Transparency API for subdomains of a domain.
 * Returns raw subdomain hostnames (not yet resolved).
 *
 * @param domain - Base domain to query (e.g., "example.com")
 * @param timeoutMs - Fetch timeout in milliseconds (default: 10000)
 * @returns Set of unique subdomain hostnames
 */
async function fetchCTSubdomains(domain: string, timeoutMs: number = 10000): Promise<Set<string>> {
  const url = `https://crt.sh/?q=%.${domain}&output=json`;
  const subdomains = new Set<string>();

  log.info(`Querying crt.sh for CT records of ${domain}...`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'SecBot/1.0 (security scanner)',
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      log.warn(`crt.sh returned HTTP ${response.status} for ${domain}`);
      return subdomains;
    }

    const data: CrtShEntry[] = await response.json() as CrtShEntry[];

    for (const entry of data) {
      // name_value can contain multiple hostnames separated by newlines
      const names = entry.name_value.split('\n');
      for (const name of names) {
        const cleaned = name.trim().toLowerCase();
        if (!cleaned) continue;

        // Skip wildcard entries (*.example.com) — not resolvable
        if (cleaned.startsWith('*.')) continue;

        // Must be a subdomain of the target domain
        if (cleaned === domain || cleaned.endsWith(`.${domain}`)) {
          subdomains.add(cleaned);
        }
      }
    }

    log.info(`crt.sh returned ${data.length} entries, ${subdomains.size} unique subdomains for ${domain}`);
  } catch (err: unknown) {
    if (err instanceof Error) {
      if (err.name === 'AbortError') {
        log.warn(`crt.sh request timed out after ${timeoutMs}ms for ${domain}`);
      } else {
        log.warn(`crt.sh query failed for ${domain}: ${err.message}`);
      }
    } else {
      log.warn(`crt.sh query failed for ${domain}: unknown error`);
    }
  } finally {
    clearTimeout(timeout);
  }

  return subdomains;
}

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
    return null;
  }

  // Try to get CNAME (optional, non-blocking)
  try {
    const cnames = await dns.resolveCname(fqdn);
    if (cnames.length > 0) {
      cname = cnames[0];
    }
  } catch {
    // CNAME not found — that's fine
  }

  return { subdomain: fqdn, ips, cname };
}

/**
 * Enumerate subdomains of a domain via Certificate Transparency logs (crt.sh).
 *
 * Queries the crt.sh API, extracts unique subdomain names, then resolves each
 * via DNS to get IP addresses.
 *
 * @param domain - The base domain to enumerate (e.g., "example.com")
 * @param concurrency - Max concurrent DNS lookups (default: 10)
 * @param timeoutMs - crt.sh API timeout in milliseconds (default: 10000)
 * @returns Array of resolved subdomains with their IPs and optional CNAME
 */
export async function enumerateSubdomainsCT(
  domain: string,
  concurrency: number = 10,
  timeoutMs: number = 10000,
): Promise<SubdomainResult[]> {
  const subdomainNames = await fetchCTSubdomains(domain, timeoutMs);
  const results: SubdomainResult[] = [];

  if (subdomainNames.size === 0) {
    log.info(`No CT subdomains found for ${domain}`);
    return results;
  }

  log.info(`Resolving ${subdomainNames.size} CT subdomains for ${domain}...`);

  const hostnames = Array.from(subdomainNames);

  // Process in batches to respect concurrency limit
  for (let i = 0; i < hostnames.length; i += concurrency) {
    const batch = hostnames.slice(i, i + concurrency);
    const promises = batch.map((hostname) => resolveSubdomain(hostname));

    const batchResults = await Promise.all(promises);
    for (const result of batchResults) {
      if (result) {
        results.push(result);
        log.debug(`CT found: ${result.subdomain} -> ${result.ips.join(', ')}${result.cname ? ` (CNAME: ${result.cname})` : ''}`);
      }
    }
  }

  log.info(`CT subdomain enumeration complete: ${results.length} resolved out of ${subdomainNames.size} discovered`);
  return results;
}

/**
 * Merge subdomain results from DNS brute-force and CT enumeration.
 * Deduplicates by hostname (subdomain field), preferring the entry with more data.
 *
 * @param dns - Results from DNS brute-force enumeration
 * @param ct - Results from Certificate Transparency enumeration
 * @returns Merged and deduplicated results
 */
export function mergeSubdomainResults(
  dnsResults: SubdomainResult[],
  ct: SubdomainResult[],
): SubdomainResult[] {
  const map = new Map<string, SubdomainResult>();

  // Add DNS results first
  for (const result of dnsResults) {
    map.set(result.subdomain.toLowerCase(), result);
  }

  // Add CT results — if duplicate, prefer the one with more IPs or a CNAME
  for (const result of ct) {
    const key = result.subdomain.toLowerCase();
    const existing = map.get(key);

    if (!existing) {
      map.set(key, result);
    } else {
      // Merge: keep the entry with more information
      const merged: SubdomainResult = {
        subdomain: existing.subdomain,
        ips: Array.from(new Set([...existing.ips, ...result.ips])),
        cname: existing.cname ?? result.cname,
      };
      map.set(key, merged);
    }
  }

  return Array.from(map.values());
}

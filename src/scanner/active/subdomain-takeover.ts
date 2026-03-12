import { randomUUID } from 'node:crypto';
import type { RawFinding } from '../types.js';
import { log } from '../../utils/logger.js';
import type { ActiveCheck } from './index.js';
import type { SubdomainResult } from '../recon/subdomain.js';
import { matchFingerprint } from './subdomain-takeover-fingerprints.js';

// ─── Fetcher interface ────────────────────────────────────────────────

export interface FetchResult {
  status: number;
  body: string;
}

export type SubdomainFetcher = (url: string) => Promise<FetchResult>;

/** Default fetcher — performs a real HTTP GET with a short timeout. */
async function defaultFetcher(url: string): Promise<FetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'SecBot/1.0 (security-research)',
      },
    });
    const body = await response.text();
    return { status: response.status, body: body.slice(0, 5_000) };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Core logic ──────────────────────────────────────────────────────

/**
 * Check a list of subdomains for dangling CNAME takeover opportunities.
 *
 * - Only checks subdomains that have a CNAME record (no CNAME = no takeover risk)
 * - Processes in batches with a concurrency limit
 * - Only reports exploitable services
 * - Injectable fetcher for testing
 *
 * @param subdomains    - SubdomainResult array from recon phase
 * @param targetDomain  - Base domain (e.g. "example.com") — for URL building
 * @param fetcher       - HTTP fetcher function (injectable for tests)
 * @param concurrency   - Max parallel HTTP requests (default: 5)
 */
export async function checkSubdomainTakeover(
  subdomains: SubdomainResult[],
  targetDomain: string,
  fetcher: SubdomainFetcher = defaultFetcher,
  concurrency: number = 5,
): Promise<RawFinding[]> {
  if (subdomains.length === 0) return [];

  // Filter to only subdomains with a CNAME
  const withCname = subdomains.filter((s) => s.cname);

  if (withCname.length === 0) {
    log.debug(`Subdomain takeover: no CNAMEs found among ${subdomains.length} subdomains`);
    return [];
  }

  log.info(`Subdomain takeover: checking ${withCname.length} subdomains with CNAMEs...`);

  const findings: RawFinding[] = [];

  // Process in batches to respect concurrency limit
  for (let i = 0; i < withCname.length; i += concurrency) {
    const batch = withCname.slice(i, i + concurrency);

    const batchResults = await Promise.allSettled(
      batch.map(async (sub) => {
        const url = `https://${sub.subdomain}`;

        let fetchResult: FetchResult;
        try {
          fetchResult = await fetcher(url);
        } catch (err) {
          log.debug(`Subdomain takeover: fetch failed for ${sub.subdomain}: ${(err as Error).message}`);
          return null;
        }

        const fp = matchFingerprint(
          sub.subdomain,
          fetchResult.body,
          fetchResult.status,
          sub.cname,
        );

        if (!fp) {
          log.debug(`Subdomain takeover: no match for ${sub.subdomain} (CNAME: ${sub.cname})`);
          return null;
        }

        if (!fp.exploitable) {
          log.debug(`Subdomain takeover: ${fp.service} detected on ${sub.subdomain} but not exploitable`);
          return null;
        }

        log.info(`Subdomain takeover: EXPLOITABLE ${fp.service} on ${sub.subdomain} (CNAME: ${sub.cname})`);

        // Determine body match evidence
        const bodyMatch = fp.bodyFingerprints.find((f) => fetchResult.body.includes(f));

        const evidenceParts: string[] = [
          `Service: ${fp.service}`,
          `CNAME: ${sub.cname}`,
          `HTTP Status: ${fetchResult.status}`,
        ];
        if (bodyMatch) {
          evidenceParts.push(`Body match: "${bodyMatch}"`);
        }

        const finding: RawFinding = {
          id: randomUUID(),
          category: 'subdomain-takeover',
          severity: 'high',
          title: `Subdomain Takeover — ${fp.service}`,
          description:
            `The subdomain ${sub.subdomain} has a dangling CNAME record pointing to ${sub.cname} ` +
            `(${fp.service}), which no longer resolves to a valid resource. ` +
            `An attacker can register this resource on ${fp.service} and serve malicious content ` +
            `from a trusted subdomain of ${targetDomain}.`,
          url,
          evidence: evidenceParts.join('\n'),
          response: {
            status: fetchResult.status,
            bodySnippet: fetchResult.body.slice(0, 300),
          },
          timestamp: new Date().toISOString(),
          affectedUrls: [url],
        };

        return finding;
      }),
    );

    for (const result of batchResults) {
      if (result.status === 'fulfilled' && result.value !== null) {
        findings.push(result.value);
      }
    }
  }

  log.info(`Subdomain takeover: ${findings.length} exploitable takeover(s) found`);
  return findings;
}

// ─── ActiveCheck implementation ──────────────────────────────────────

/**
 * Subdomain Takeover active check.
 *
 * Reads subdomainResults from config (populated by recon phase when
 * --subdomains flag is used) and checks each CNAME-bearing subdomain
 * for dangling takeover opportunities.
 *
 * Runs in parallel mode (read-only, no state mutation).
 */
export const subdomainTakeoverCheck: ActiveCheck = {
  name: 'subdomain-takeover',
  category: 'subdomain-takeover',
  parallel: true,

  async run(_context, _targets, config) {
    const subdomainResults = config.subdomainResults;

    if (!subdomainResults || subdomainResults.length === 0) {
      log.info('Subdomain takeover: no subdomain results available — run with --subdomains flag');
      return [];
    }

    log.info(`Subdomain takeover: processing ${subdomainResults.length} subdomains from recon...`);

    return checkSubdomainTakeover(
      subdomainResults,
      new URL(config.targetUrl).hostname,
      defaultFetcher,
      config.concurrency ?? 5,
    );
  },
};

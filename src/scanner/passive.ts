import { randomUUID } from 'node:crypto';
import type { CrawledPage, InterceptedResponse, RawFinding, ReconResult } from './types.js';
import { log } from '../utils/logger.js';
import { normalizeUrl } from '../utils/shared.js';

// Frameworks that require 'unsafe-inline' in CSP for their runtime to function
const FRAMEWORKS_REQUIRING_UNSAFE_INLINE = ['Next.js', 'Nuxt'];

// Headers that CDN platforms (Vercel, Cloudflare) typically inject at the edge,
// even when the application code doesn't set them explicitly.
const CDN_MANAGED_HEADERS = [
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
];

// Cookies that don't need HttpOnly — they're intentionally JS-readable
const SKIP_HTTPONLY_PATTERNS = [
  /^_ga/i, /^_gid/i, /^_gat/i, /^_fbp/i, /^_gcl/i,    // Google Analytics / FB Pixel
  /csrf/i, /xsrf/i,                                         // CSRF tokens (any position — e.g. __Host-js_csrf)
  /^locale$/i, /^lang$/i, /^theme$/i, /^i18n/i,           // preferences
  /country/i, /^timezone$/i, /^region$/i,                   // geo preferences (e.g. twitch.lohp.countryCode)
  /^unique_id$/i,                                            // tracking identifiers
  /^experiment/i, /^variant/i, /^ab_/i,                     // A/B test overrides
  /^__utm/i,                                                // UTM tracking
  /^FPLC$/i, /^FPID$/i,                                     // Google First-Party Linker / ID
  /^OptanonConsent$/i, /^OptanonAlertBoxClosed$/i,           // OneTrust consent
  /^g_state$/i,                                               // Google Sign-In
  /^_sp_id/i, /^_sp_ses/i,                                   // Snowplow
  /^_hjSession/i, /^_hj/i,                                   // Hotjar
  /^loglevel/i,                                               // LogLevel debug
  /^notice_/i, /^consent/i, /^cookie_?consent/i,              // GDPR consent banners
  /^TAsessionID$/i, /^TA_/i,                                  // ThunderAnalytics
  /^_lo_/i, /^_lorid$/i,                                      // LuckyOrange
  /^drift/i, /^driftt_/i,                                       // Drift chat
  /^_gd_/i,                                                      // GoDaddy/analytics
  /^_an_uid$/i,                                                   // Analytics UID
  /^pxcts$/i, /^_pxvid$/i,                                          // PerimeterX bot detection
  /^datadome$/i,                                                     // DataDome bot detection
  /^__zlcmid$/i,                                                     // Zendesk Live Chat
];

// Third-party analytics/marketing cookies — lower severity, group instead of individual findings
const THIRD_PARTY_COOKIE_PATTERNS = [
  /^_ga/i, /^_gid/i, /^_gat/i, /^_gcl/i,                 // Google Analytics
  /^_fbp$/i, /^_fbc$/i,                                    // Facebook Pixel
  /^__utm/i,                                                // Google UTM
  /^_mkto_/i, /^_biz/i, /^mto_/i,                           // Marketo
  /^_vwo/i, /^_vis_opt/i,                                  // VWO (Visual Website Optimizer)
  /^__adroll/i, /^__ar_v/i,                                // AdRoll
  /^_rdt_uuid/i,                                            // Reddit Pixel
  /^_uet/i,                                                 // Microsoft UET
  /^_twpid/i,                                               // Twitter Pixel
  /^ajs_/i, /^analytics/i,                                  // Segment
  /^cb_/i,                                                   // Chartbeat
  /^sa-user-id/i,                                            // StackAdapt
  /^signals-sdk/i,                                           // Signals
  /^_pf_/i,                                                  // Pathfactory
  /^__q_state/i,                                             // Qualified
  /^vid$/i,                                                   // Various video trackers
  /^_zitok/i,                                                // ZoomInfo
  /^datagrail/i,                                             // DataGrail consent
  /^hubspot/i, /^__hs/i, /^__hstc/i,                        // HubSpot
  /^_clck$/i, /^_clsk$/i,                                   // Microsoft Clarity
  /^intercom/i,                                              // Intercom
  /^optimizely/i,                                            // Optimizely
  /^_sp_id/i, /^_sp_ses/i,                                  // Snowplow Analytics
  /^OptanonConsent$/i, /^OptanonAlertBoxClosed$/i,          // OneTrust cookie consent
  /^g_state$/i,                                              // Google Sign-In state
  /^__cf_bm$/i, /^cf_clearance$/i,                          // Cloudflare
  /^FPLC$/i, /^FPID$/i,                                     // Google First-Party Linker / ID
  /^_tt_/i,                                                   // TikTok Pixel
  /^li_/i, /^bcookie$/i, /^bscookie$/i,                      // LinkedIn
  /^NID$/i, /^APISID$/i, /^SAPISID$/i, /^SSID$/i,           // Google auth/ads (first-party set)
  /^_pin_/i,                                                   // Pinterest
  /^_hp2_/i,                                                   // Heap Analytics
  /^mp_/i,                                                     // Mixpanel
  /^amplitude/i,                                               // Amplitude
  /^fs_uid/i, /^fs_lua/i,                                     // FullStory
  /^loglevel/i,                                                // LogLevel (debug cookie, JS-readable)
  /^ab\./i, /^ab_/i,                                          // A/B testing
  /^_hjSession/i, /^_hj/i,                                    // Hotjar
  /^unique_id$/i,                                              // Tracking identifier
  /^experiment/i, /^variant/i,                                 // A/B testing
  /^notice_/i, /^consent/i, /^cookie_?consent/i,               // GDPR consent banners
  /^TAsessionID$/i, /^TA_/i,                                   // ThunderAnalytics
  /^_lo_/i, /^_lorid$/i,                                       // LuckyOrange
  /^drift/i, /^driftt_/i,                                       // Drift chat
  /^_gd_/i,                                                      // GoDaddy/analytics
  /^_an_uid$/i,                                                   // Analytics UID
  /^country$/i, /^timezone$/i, /^region$/i,                        // Locale preference
  /^language$/i, /^locale$/i, /^lang$/i,                           // Language preference
  /^_dc_/i, /^__dc/i,                                              // DoubleClick
  /^_parsely/i,                                                     // Parse.ly analytics
  /^__cfduid$/i,                                                    // Cloudflare (deprecated)
  /^_pk_/i,                                                          // Matomo/Piwik
  /^sc_anonymous/i,                                                  // Sitecore analytics
  /^_ce\./i,                                                         // Crazy Egg
  /^__hssc$/i, /^__hssrc$/i,                                        // HubSpot session
  /^_stid/i,                                                         // ShareThis
  /^_derived_epik$/i,                                                // Pinterest enhanced match
  /^pxcts$/i, /^_pxvid$/i,                                          // PerimeterX bot detection
  /^datadome$/i,                                                     // DataDome bot detection
  /^__zlcmid$/i,                                                     // Zendesk Live Chat
  /^_uetsid$/i, /^_uetvid$/i,                                       // Microsoft Ads
  /^_scid$/i, /^_sctr$/i,                                            // Snapchat Pixel
  /^lastExternalReferrer/i, /^lastExternalReferrerTime/i,           // Facebook SDK
];

function isThirdPartyCookie(name: string): boolean {
  return THIRD_PARTY_COOKIE_PATTERNS.some(p => p.test(name));
}

/**
 * Check if a specific CSP directive contains a given value.
 * Handles multi-policy CSPs (comma-separated) and correctly
 * parses directive boundaries (semicolon-separated).
 */
function cspDirectiveContains(csp: string, directive: string, value: string): boolean {
  // CSP can have multiple policies separated by commas
  const policies = csp.split(',');
  for (const policy of policies) {
    // Each policy has directives separated by semicolons
    const directives = policy.split(';').map(d => d.trim());
    for (const d of directives) {
      if (d.toLowerCase().startsWith(directive)) {
        if (d.toLowerCase().includes(value.toLowerCase())) {
          return true;
        }
      }
    }
  }
  return false;
}

export function shouldCheckHttpOnly(cookieName: string): boolean {
  return !SKIP_HTTPONLY_PATTERNS.some(p => p.test(cookieName));
}

export function runPassiveChecks(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
  recon?: ReconResult,
): RawFinding[] {
  const findings: RawFinding[] = [];

  // Track reported missing headers across all pages for dedup
  const reportedHeaders = new Map<string, RawFinding>();

  const detectedFramework = recon?.framework?.name;

  // Determine the target origin from the first page — skip external pages
  let targetOrigin: string | undefined;
  if (pages.length > 0) {
    try {
      targetOrigin = new URL(pages[0].url).origin;
    } catch { /* ignore */ }
  }

  for (const page of pages) {
    // Skip external pages (e.g., links followed to github.com) — they're out of scope
    if (targetOrigin) {
      try {
        if (new URL(page.url).origin !== targetOrigin) continue;
      } catch { /* check anyway if URL parse fails */ }
    }
    findings.push(...checkSecurityHeaders(page, reportedHeaders, detectedFramework, recon));
    findings.push(...checkCookieFlags(page));
    findings.push(...checkInfoLeakage(page, responses));
    findings.push(...checkMixedContent(page, responses));
    findings.push(...checkSensitiveUrlData(page));
  }

  log.info(`Passive scan: ${findings.length} raw findings`);
  return findings;
}

function checkSecurityHeaders(
  page: CrawledPage,
  reportedHeaders: Map<string, RawFinding>,
  detectedFramework?: string,
  recon?: ReconResult,
): RawFinding[] {
  const findings: RawFinding[] = [];
  const headers = page.headers;

  // Detect CDN platform from response headers or recon tech stack
  const isVercel = headers['server']?.includes('Vercel') ||
    headers['x-vercel-id'] !== undefined ||
    recon?.techStack?.cdn?.toLowerCase().includes('vercel');
  const isCloudflare = headers['server']?.includes('cloudflare') ||
    headers['cf-ray'] !== undefined ||
    recon?.techStack?.cdn?.toLowerCase().includes('cloudflare');
  const isCdnManaged = isVercel || isCloudflare;
  const cdnName = isVercel ? 'Vercel' : isCloudflare ? 'Cloudflare' : undefined;

  const requiredHeaders: {
    name: string;
    title: string;
    description: string;
    severity: RawFinding['severity'];
    confidence: RawFinding['confidence'];
  }[] = [
    {
      name: 'strict-transport-security',
      title: 'Missing HSTS Header',
      description:
        'The Strict-Transport-Security header is missing. This allows downgrade attacks and cookie hijacking.',
      severity: 'high',
      confidence: 'medium',
    },
    {
      name: 'content-security-policy',
      title: 'Missing Content-Security-Policy Header',
      description:
        'No CSP header found. This makes the application more susceptible to XSS attacks.',
      severity: 'high',
      confidence: 'medium',
    },
    {
      name: 'x-frame-options',
      title: 'Missing X-Frame-Options Header',
      description:
        'The X-Frame-Options header is missing, potentially allowing clickjacking attacks.',
      severity: 'medium',
      confidence: 'low',
    },
    {
      name: 'x-content-type-options',
      title: 'Missing X-Content-Type-Options Header',
      description:
        'Missing X-Content-Type-Options: nosniff header. Browsers may MIME-sniff responses.',
      severity: 'low',
      confidence: 'low',
    },
    {
      name: 'referrer-policy',
      title: 'Missing Referrer-Policy Header',
      description:
        'No Referrer-Policy set. Sensitive data in URLs may leak via the Referer header.',
      severity: 'low',
      confidence: 'low',
    },
    {
      name: 'permissions-policy',
      title: 'Missing Permissions-Policy Header',
      description:
        'No Permissions-Policy header. Browser features like camera/microphone are not explicitly restricted.',
      severity: 'info',
      confidence: 'low',
    },
  ];

  for (const req of requiredHeaders) {
    if (!headers[req.name]) {
      // Dedup: if this header was already reported, just add URL to affectedUrls
      const existing = reportedHeaders.get(req.name);
      if (existing) {
        if (!existing.affectedUrls) existing.affectedUrls = [existing.url];
        if (!existing.affectedUrls.includes(page.url)) {
          existing.affectedUrls.push(page.url);
        }
        continue;
      }

      // For CDN-managed targets, downgrade headers that the platform injects at the edge
      const cdnDowngrade = isCdnManaged && CDN_MANAGED_HEADERS.includes(req.name);

      const finding: RawFinding = {
        id: randomUUID(),
        category: 'security-headers',
        severity: cdnDowngrade ? 'info' : req.severity,
        confidence: req.confidence,
        title: req.title,
        description: cdnDowngrade
          ? req.description + ` Note: Target uses ${cdnName} which may inject this header at the platform level.`
          : req.description,
        url: page.url,
        evidence: `Header "${req.name}" not present in response`,
        response: {
          status: page.status,
          headers: page.headers,
        },
        affectedUrls: [page.url],
        timestamp: new Date().toISOString(),
      };
      reportedHeaders.set(req.name, finding);
      findings.push(finding);
    }
  }

  // Check for weak CSP
  const csp = headers['content-security-policy'];
  if (csp) {
    // Parse which directives contain 'unsafe-inline' and 'unsafe-eval'
    const scriptUnsafeInline = cspDirectiveContains(csp, 'script-src', "'unsafe-inline'");
    const defaultUnsafeInline = cspDirectiveContains(csp, 'default-src', "'unsafe-inline'");
    const styleOnlyUnsafeInline = cspDirectiveContains(csp, 'style-src', "'unsafe-inline'")
      && !scriptUnsafeInline && !defaultUnsafeInline;

    // script-src or default-src with unsafe-inline = real XSS risk
    if (scriptUnsafeInline || defaultUnsafeInline) {
      const frameworkRequiresUnsafeInline = detectedFramework
        ? FRAMEWORKS_REQUIRING_UNSAFE_INLINE.includes(detectedFramework)
        : false;

      const description = frameworkRequiresUnsafeInline
        ? `Next.js uses 'unsafe-inline' alongside nonce-based CSP as its standard security model. ` +
          `The nonce ensures only legitimate scripts execute. This is the correct pattern for ${detectedFramework} and is not an exploitable weakness.`
        : "The Content-Security-Policy includes 'unsafe-inline' in script-src, which weakens XSS protection.";

      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: frameworkRequiresUnsafeInline ? 'low' : 'medium',
        confidence: 'medium',
        title: 'CSP Allows Unsafe Inline Scripts',
        description,
        url: page.url,
        evidence: `CSP: ${csp}`,
        response: { status: page.status, headers: page.headers },
        timestamp: new Date().toISOString(),
      });
    } else if (styleOnlyUnsafeInline) {
      // style-src only unsafe-inline = low risk, very common, not bounty-worthy
      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: 'info',
        confidence: 'low',
        title: 'CSP Allows Unsafe Inline Styles',
        description:
          "The Content-Security-Policy includes 'unsafe-inline' in style-src only. " +
          "While this weakens style injection protections, it is common practice and has minimal XSS impact when script-src is properly restricted.",
        url: page.url,
        evidence: `CSP: ${csp}`,
        response: { status: page.status, headers: page.headers },
        timestamp: new Date().toISOString(),
      });
    }

    const scriptUnsafeEval = cspDirectiveContains(csp, 'script-src', "'unsafe-eval'");
    const defaultUnsafeEval = cspDirectiveContains(csp, 'default-src', "'unsafe-eval'");
    if (scriptUnsafeEval || defaultUnsafeEval) {
      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: 'medium',
        confidence: 'medium',
        title: 'CSP Allows Unsafe Eval',
        description:
          "The Content-Security-Policy includes 'unsafe-eval' in script-src, allowing dynamic code execution.",
        url: page.url,
        evidence: `CSP: ${csp}`,
        response: { status: page.status, headers: page.headers },
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Cross-origin isolation headers (COOP, COEP, CORP)
  const crossOriginHeaders: {
    name: string;
    title: string;
    description: string;
    validValues: string[];
  }[] = [
    {
      name: 'cross-origin-opener-policy',
      title: 'Missing Cross-Origin-Opener-Policy Header',
      description:
        'The Cross-Origin-Opener-Policy header is missing. This header isolates the browsing context, preventing cross-origin attacks like Spectre.',
      validValues: ['same-origin'],
    },
    {
      name: 'cross-origin-embedder-policy',
      title: 'Missing Cross-Origin-Embedder-Policy Header',
      description:
        'The Cross-Origin-Embedder-Policy header is missing. This header ensures all cross-origin resources are loaded with CORS or CORP, enabling cross-origin isolation.',
      validValues: ['require-corp'],
    },
    {
      name: 'cross-origin-resource-policy',
      title: 'Missing Cross-Origin-Resource-Policy Header',
      description:
        'The Cross-Origin-Resource-Policy header is missing. This header prevents other origins from loading this resource, mitigating side-channel attacks.',
      validValues: ['same-origin', 'same-site'],
    },
  ];

  for (const coHeader of crossOriginHeaders) {
    const value = headers[coHeader.name];
    if (!value || !coHeader.validValues.includes(value)) {
      const existing = reportedHeaders.get(coHeader.name);
      if (existing) {
        if (!existing.affectedUrls) existing.affectedUrls = [existing.url];
        if (!existing.affectedUrls.includes(page.url)) {
          existing.affectedUrls.push(page.url);
        }
        continue;
      }

      const evidence = value
        ? `Header "${coHeader.name}" has value "${value}" (expected: ${coHeader.validValues.join(' or ')})`
        : `Header "${coHeader.name}" not present in response`;

      const finding: RawFinding = {
        id: randomUUID(),
        category: 'cross-origin-policy',
        severity: 'low',
        confidence: 'low',
        title: value
          ? coHeader.title.replace('Missing ', 'Weak ')
          : coHeader.title,
        description: coHeader.description,
        url: page.url,
        evidence,
        response: {
          status: page.status,
          headers: page.headers,
        },
        affectedUrls: [page.url],
        timestamp: new Date().toISOString(),
      };
      reportedHeaders.set(coHeader.name, finding);
      findings.push(finding);
    }
  }

  // Check for overly permissive Permissions-Policy
  const permissionsPolicy = headers['permissions-policy'];
  if (permissionsPolicy) {
    const dangerousFeatures = ['camera', 'microphone', 'geolocation'];
    const permissive: string[] = [];
    for (const feature of dangerousFeatures) {
      // Match patterns like camera=*, camera=(*), or camera=(*)
      const pattern = new RegExp(`${feature}\\s*=\\s*\\(?\\s*\\*\\s*\\)?`, 'i');
      if (pattern.test(permissionsPolicy)) {
        permissive.push(feature);
      }
    }
    if (permissive.length > 0) {
      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: 'medium',
        confidence: 'medium',
        title: 'Overly Permissive Permissions-Policy',
        description: `The Permissions-Policy header allows wildcard access to sensitive features: ${permissive.join(', ')}. These should be restricted to specific origins or disabled.`,
        url: page.url,
        evidence: `Permissions-Policy: ${permissionsPolicy}`,
        response: { status: page.status, headers: page.headers },
        timestamp: new Date().toISOString(),
      });
    }
  }

  return findings;
}

function checkCookieFlags(page: CrawledPage): RawFinding[] {
  const findings: RawFinding[] = [];

  // Separate first-party (app) cookies from third-party (analytics/marketing) cookies
  const appCookies = page.cookies.filter(c => !isThirdPartyCookie(c.name));
  const thirdPartyCookies = page.cookies.filter(c => isThirdPartyCookie(c.name));

  // Report individual findings for first-party app cookies (these matter for security)
  for (const cookie of appCookies) {
    if (!cookie.httpOnly && shouldCheckHttpOnly(cookie.name)) {
      findings.push({
        id: randomUUID(),
        category: 'cookie-flags',
        severity: 'medium',
        confidence: 'medium',
        title: `Cookie "${cookie.name}" Missing HttpOnly Flag`,
        description: `The cookie "${cookie.name}" is accessible via JavaScript, increasing XSS impact.`,
        url: page.url,
        evidence: `Cookie: ${cookie.name}; HttpOnly=false`,
        timestamp: new Date().toISOString(),
      });
    }

    if (!cookie.secure && page.url.startsWith('https://')) {
      findings.push({
        id: randomUUID(),
        category: 'cookie-flags',
        severity: 'medium',
        confidence: 'medium',
        title: `Cookie "${cookie.name}" Missing Secure Flag`,
        description: `The cookie "${cookie.name}" can be transmitted over unencrypted connections.`,
        url: page.url,
        evidence: `Cookie: ${cookie.name}; Secure=false`,
        timestamp: new Date().toISOString(),
      });
    }

    if (cookie.sameSite === 'None' || cookie.sameSite === '') {
      findings.push({
        id: randomUUID(),
        category: 'cookie-flags',
        severity: 'low',
        confidence: 'low',
        title: `Cookie "${cookie.name}" Weak SameSite Setting`,
        description: `The cookie "${cookie.name}" has SameSite=${cookie.sameSite || 'not set'}, allowing cross-site usage.`,
        url: page.url,
        evidence: `Cookie: ${cookie.name}; SameSite=${cookie.sameSite || 'not set'}`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Group third-party analytics cookies into a SINGLE low-severity finding per issue type
  if (thirdPartyCookies.length > 0) {
    const missingHttpOnly = thirdPartyCookies.filter(c => !c.httpOnly && shouldCheckHttpOnly(c.name));
    const missingSecure = thirdPartyCookies.filter(c => !c.secure && page.url.startsWith('https://'));

    if (missingHttpOnly.length > 0) {
      const names = missingHttpOnly.map(c => c.name).join(', ');
      findings.push({
        id: randomUUID(),
        category: 'cookie-flags',
        severity: 'low',
        confidence: 'low',
        title: `${missingHttpOnly.length} Third-Party Cookies Missing HttpOnly`,
        description: `${missingHttpOnly.length} analytics/marketing cookies are accessible via JavaScript. These are third-party tracking cookies with limited security impact.`,
        url: page.url,
        evidence: `Cookies: ${names}`,
        timestamp: new Date().toISOString(),
      });
    }

    if (missingSecure.length > 0) {
      const names = missingSecure.map(c => c.name).join(', ');
      findings.push({
        id: randomUUID(),
        category: 'cookie-flags',
        severity: 'low',
        confidence: 'low',
        title: `${missingSecure.length} Third-Party Cookies Missing Secure Flag`,
        description: `${missingSecure.length} analytics/marketing cookies can be transmitted over unencrypted connections. These are third-party tracking cookies with limited security impact.`,
        url: page.url,
        evidence: `Cookies: ${names}`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return findings;
}

function checkInfoLeakage(
  page: CrawledPage,
  responses: InterceptedResponse[],
): RawFinding[] {
  const findings: RawFinding[] = [];
  const headers = page.headers;

  // Server version disclosure
  const serverHeader = headers['server'];
  if (serverHeader && /[\d.]/.test(serverHeader)) {
    findings.push({
      id: randomUUID(),
      category: 'info-leakage',
      severity: 'low',
      confidence: 'low',
      title: 'Server Version Disclosure',
      description: `The Server header discloses version information: "${serverHeader}". This helps attackers identify known vulnerabilities.`,
      url: page.url,
      evidence: `Server: ${serverHeader}`,
      response: { status: page.status, headers },
      timestamp: new Date().toISOString(),
    });
  }

  // X-Powered-By disclosure
  const poweredBy = headers['x-powered-by'];
  if (poweredBy) {
    findings.push({
      id: randomUUID(),
      category: 'info-leakage',
      severity: 'low',
      confidence: 'low',
      title: 'Technology Stack Disclosure',
      description: `The X-Powered-By header reveals: "${poweredBy}". This helps attackers target known framework vulnerabilities.`,
      url: page.url,
      evidence: `X-Powered-By: ${poweredBy}`,
      response: { status: page.status, headers },
      timestamp: new Date().toISOString(),
    });
  }

  // Check for stack traces / verbose errors in HTML responses
  // Match responses by normalized URL or hostname to handle redirects
  const pageHostname = (() => { try { return new URL(page.url).hostname; } catch { return ''; } })();
  const normalizedPageUrl = normalizeUrl(page.url);
  const pageResponses = responses.filter((r) => {
    if (!r.body) return false;
    if (normalizeUrl(r.url) === normalizedPageUrl) return true;
    // Also check responses from same hostname (catches redirects)
    try { return new URL(r.url).hostname === pageHostname && r.status >= 200 && r.status < 300; } catch { return false; }
  });
  for (const resp of pageResponses) {
    if (!resp.body) continue;

    const errorPatterns = [
      { pattern: /Traceback \(most recent call last\)/i, name: 'Python stack trace' },
      { pattern: /at\s+\w+\s+\(.*?:\d+:\d+\)/m, name: 'JavaScript stack trace' },
      { pattern: /java\.lang\.\w+Exception/i, name: 'Java exception' },
      { pattern: /Fatal error:.*?in\s+\/\w+/i, name: 'PHP fatal error' },
      { pattern: /Microsoft\.AspNetCore/i, name: '.NET stack trace' },
      { pattern: /SQLSTATE\[/i, name: 'SQL error disclosure' },
    ];

    for (const { pattern, name } of errorPatterns) {
      const match = resp.body.match(pattern);
      if (match) {
        findings.push({
          id: randomUUID(),
          category: 'info-leakage',
          severity: 'medium',
          confidence: 'medium',
          title: `Verbose Error Disclosure (${name})`,
          description: `The page exposes a ${name} which could reveal internal implementation details.`,
          url: page.url,
          evidence: match[0].slice(0, 200),
          response: { status: resp.status, headers: resp.headers },
          timestamp: new Date().toISOString(),
        });
        break; // One finding per response
      }
    }

    // Check for sensitive information in HTML comments
    // Only check HTML responses (text/html content type or bodies starting with <!DOCTYPE/html tags)
    const contentType = resp.headers['content-type'] ?? '';
    if (contentType.includes('html') || resp.body.trimStart().startsWith('<!') || resp.body.trimStart().startsWith('<html')) {
      const sensitiveComments = extractSensitiveComments(resp.body);
      if (sensitiveComments.length > 0) {
        findings.push({
          id: randomUUID(),
          category: 'info-leakage',
          severity: 'medium',
          confidence: 'medium',
          title: 'Sensitive Information in HTML Comments',
          description:
            `${sensitiveComments.length} HTML comment(s) contain potentially sensitive information (credentials, internal URLs, debug flags, or TODO notes with security context). ` +
            'HTML comments are visible to any user viewing page source.',
          url: page.url,
          evidence: sensitiveComments.slice(0, 5).map(c => c.snippet).join('\n---\n'),
          response: { status: resp.status, headers: resp.headers },
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  return findings;
}

/** Patterns that indicate sensitive content in HTML comments */
const SENSITIVE_COMMENT_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /password\s*[:=]\s*\S+/i, label: 'password' },
  { re: /api[_-]?key\s*[:=]\s*['"]?\w{10,}/i, label: 'API key' },
  { re: /secret\s*[:=]\s*['"]?\w{10,}/i, label: 'secret' },
  { re: /token\s*[:=]\s*['"]?\w{10,}/i, label: 'token' },
  { re: /(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[:/])/g, label: 'internal IP' },
  { re: /(?:admin|root|debug|staging|internal)(?:\s+url|_url|_host|_server)\s*[:=]/i, label: 'internal URL' },
  { re: /TODO[:\s].*(?:fix|remove|delete|disable).*(?:auth|password|token|key|secret|credential)/i, label: 'security TODO' },
  { re: /FIXME[:\s].*(?:auth|password|token|key|secret|vuln|bypass)/i, label: 'security FIXME' },
  { re: /DEBUG\s*[:=]\s*true/i, label: 'debug flag' },
];

/**
 * Extract HTML comments that contain potentially sensitive information.
 * Filters out common benign comments (build stamps, license headers, conditional IE comments).
 */
export function extractSensitiveComments(html: string): Array<{ snippet: string; label: string }> {
  const results: Array<{ snippet: string; label: string }> = [];
  // Match HTML comments (non-greedy, up to 2000 chars per comment)
  const commentRe = /<!--([\s\S]*?)-->/g;
  let m: RegExpExecArray | null;
  while ((m = commentRe.exec(html)) !== null) {
    const comment = m[1].trim();
    // Skip very short or very long comments (build stamps vs. license blocks)
    if (comment.length < 10 || comment.length > 2000) continue;
    // Skip benign patterns
    if (/^\[if\s/i.test(comment)) continue; // IE conditional comments
    if (/^(copyright|license|generated|built)/i.test(comment)) continue;

    for (const { re, label } of SENSITIVE_COMMENT_PATTERNS) {
      re.lastIndex = 0;
      if (re.test(comment)) {
        results.push({
          snippet: comment.length > 200 ? comment.slice(0, 200) + '...' : comment,
          label,
        });
        break; // One label per comment
      }
    }
  }
  return results;
}

function checkMixedContent(
  page: CrawledPage,
  responses: InterceptedResponse[],
): RawFinding[] {
  const findings: RawFinding[] = [];

  if (!page.url.startsWith('https://')) return findings;

  // Check for HTTP resources loaded on HTTPS page
  const mixedHostname = (() => { try { return new URL(page.url).hostname; } catch { return ''; } })();
  const pageResponses = responses.filter((r) => {
    try {
      // Match by referer or by same hostname
      const referer = r.headers['referer'] ?? '';
      if (referer.includes(mixedHostname)) return true;
      return new URL(r.url).hostname === mixedHostname;
    } catch {
      return false;
    }
  });

  for (const resp of pageResponses) {
    if (resp.url.startsWith('http://')) {
      findings.push({
        id: randomUUID(),
        category: 'mixed-content',
        severity: 'medium',
        confidence: 'medium',
        title: 'Mixed Content (HTTP Resource on HTTPS Page)',
        description: `An HTTP resource is loaded on the HTTPS page, potentially allowing MitM attacks.`,
        url: page.url,
        evidence: `HTTP resource: ${resp.url}`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return findings;
}

function checkSensitiveUrlData(page: CrawledPage): RawFinding[] {
  const findings: RawFinding[] = [];

  const sensitivePatterns = [
    { pattern: /[?&](password|passwd|pwd|secret|token|api[_-]?key)=/i, name: 'password/secret' },
    { pattern: /[?&](ssn|social[_-]?security|credit[_-]?card|cc[_-]?num)=/i, name: 'PII' },
    { pattern: /[?&](session[_-]?id|sess|sid)=[a-f0-9]{16,}/i, name: 'session ID' },
  ];

  const allUrls = [page.url, ...page.links];

  for (const url of allUrls) {
    for (const { pattern, name } of sensitivePatterns) {
      if (pattern.test(url)) {
        findings.push({
          id: randomUUID(),
          category: 'sensitive-url-data',
          severity: 'high',
          confidence: 'high',
          title: `Sensitive Data in URL (${name})`,
          description: `A URL contains what appears to be ${name} data as a query parameter. This data may be logged in server logs, browser history, and proxy caches.`,
          url: page.url,
          evidence: url.replace(/([?&](?:password|passwd|pwd|secret|token|api[_-]?key|ssn)=)[^&]+/gi, '$1[REDACTED]'),
          timestamp: new Date().toISOString(),
        });
        break;
      }
    }
  }

  return findings;
}

import { randomUUID } from 'node:crypto';
import type { CrawledPage, InterceptedResponse, RawFinding } from './types.js';
import { log } from '../utils/logger.js';

export function runPassiveChecks(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const page of pages) {
    findings.push(...checkSecurityHeaders(page));
    findings.push(...checkCookieFlags(page));
    findings.push(...checkInfoLeakage(page, responses));
    findings.push(...checkMixedContent(page, responses));
    findings.push(...checkSensitiveUrlData(page));
  }

  log.info(`Passive scan: ${findings.length} raw findings`);
  return findings;
}

function checkSecurityHeaders(page: CrawledPage): RawFinding[] {
  const findings: RawFinding[] = [];
  const headers = page.headers;

  const requiredHeaders: {
    name: string;
    title: string;
    description: string;
    severity: RawFinding['severity'];
  }[] = [
    {
      name: 'strict-transport-security',
      title: 'Missing HSTS Header',
      description:
        'The Strict-Transport-Security header is missing. This allows downgrade attacks and cookie hijacking.',
      severity: 'high',
    },
    {
      name: 'content-security-policy',
      title: 'Missing Content-Security-Policy Header',
      description:
        'No CSP header found. This makes the application more susceptible to XSS attacks.',
      severity: 'high',
    },
    {
      name: 'x-frame-options',
      title: 'Missing X-Frame-Options Header',
      description:
        'The X-Frame-Options header is missing, potentially allowing clickjacking attacks.',
      severity: 'medium',
    },
    {
      name: 'x-content-type-options',
      title: 'Missing X-Content-Type-Options Header',
      description:
        'Missing X-Content-Type-Options: nosniff header. Browsers may MIME-sniff responses.',
      severity: 'low',
    },
    {
      name: 'referrer-policy',
      title: 'Missing Referrer-Policy Header',
      description:
        'No Referrer-Policy set. Sensitive data in URLs may leak via the Referer header.',
      severity: 'low',
    },
    {
      name: 'permissions-policy',
      title: 'Missing Permissions-Policy Header',
      description:
        'No Permissions-Policy header. Browser features like camera/microphone are not explicitly restricted.',
      severity: 'info',
    },
  ];

  for (const req of requiredHeaders) {
    if (!headers[req.name]) {
      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: req.severity,
        title: req.title,
        description: req.description,
        url: page.url,
        evidence: `Header "${req.name}" not present in response`,
        response: {
          status: page.status,
          headers: page.headers,
        },
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Check for weak CSP
  const csp = headers['content-security-policy'];
  if (csp) {
    if (csp.includes("'unsafe-inline'")) {
      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: 'medium',
        title: 'CSP Allows Unsafe Inline Scripts',
        description:
          "The Content-Security-Policy includes 'unsafe-inline', which weakens XSS protection.",
        url: page.url,
        evidence: `CSP: ${csp}`,
        response: { status: page.status, headers: page.headers },
        timestamp: new Date().toISOString(),
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        id: randomUUID(),
        category: 'security-headers',
        severity: 'medium',
        title: 'CSP Allows Unsafe Eval',
        description:
          "The Content-Security-Policy includes 'unsafe-eval', allowing dynamic code execution.",
        url: page.url,
        evidence: `CSP: ${csp}`,
        response: { status: page.status, headers: page.headers },
        timestamp: new Date().toISOString(),
      });
    }
  }

  return findings;
}

function checkCookieFlags(page: CrawledPage): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const cookie of page.cookies) {
    if (!cookie.httpOnly) {
      findings.push({
        id: randomUUID(),
        category: 'cookie-flags',
        severity: 'medium',
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
        title: `Cookie "${cookie.name}" Weak SameSite Setting`,
        description: `The cookie "${cookie.name}" has SameSite=${cookie.sameSite || 'not set'}, allowing cross-site usage.`,
        url: page.url,
        evidence: `Cookie: ${cookie.name}; SameSite=${cookie.sameSite || 'not set'}`,
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
  const normalizedPageUrl = normalizePassiveUrl(page.url);
  const pageResponses = responses.filter((r) => {
    if (!r.body) return false;
    if (normalizePassiveUrl(r.url) === normalizedPageUrl) return true;
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
  }

  return findings;
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

function normalizePassiveUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    let path = u.pathname;
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
    u.pathname = path;
    return u.href;
  } catch {
    return url;
  }
}

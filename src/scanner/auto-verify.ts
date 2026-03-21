import type { BrowserContext } from 'playwright';
import type { RawFinding, Confidence } from './types.js';
import { log } from '../utils/logger.js';
import { scanJsForSecrets } from './active/info-disclosure.js';

export function upgradeConfidence(current: Confidence, verified: boolean): Confidence {
  if (verified) return current === 'low' ? 'medium' : 'high';
  return current === 'high' ? 'medium' : 'low';
}

export async function verifyFinding(finding: RawFinding, context: BrowserContext): Promise<RawFinding> {
  try {
    switch (finding.category) {
      case 'xss':
        return { ...finding, confidence: (await verifyXss(finding, context)) ? 'high' : 'low' };
      case 'sqli':
        return { ...finding, confidence: (await verifySqli(finding)) ? 'high' : 'low' };
      case 'subdomain-takeover':
        return { ...finding, confidence: (await verifySubdomainTakeover(finding)) ? 'high' : 'low' };
      case 'cors-misconfiguration':
        return { ...finding, confidence: (await verifyCors(finding)) ? 'high' : 'low' };
      case 'open-redirect':
        return { ...finding, confidence: (await verifyOpenRedirect(finding)) ? 'high' : 'low' };
      case 'crlf-injection':
        return { ...finding, confidence: (await verifyCrlf(finding)) ? 'high' : 'low' };
      case 'host-header':
        return { ...finding, confidence: (await verifyHostHeader(finding)) ? 'high' : 'low' };
      case 'security-headers':
        return { ...finding, confidence: (await verifyMissingHeader(finding)) ? 'high' : 'medium' };
      case 'csrf':
        return { ...finding, confidence: (await verifyCsrf(finding)) ? 'high' : 'medium' };
      case 'sri':
        return { ...finding, confidence: (await verifySri(finding, context)) ? 'high' : 'medium' };
      case 'cookie-flags':
        return { ...finding, confidence: (await verifyCookieFlags(finding)) ? 'high' : 'medium' };
      case 'info-disclosure':
        return { ...finding, confidence: (await verifyInfoDisclosure(finding)) ? 'high' : 'medium' };
      default:
        return finding;
    }
  } catch (err) {
    log.debug(`Auto-verify failed for ${finding.category}: ${(err as Error).message}`);
    return finding;
  }
}

export async function verifyXss(finding: RawFinding, context: BrowserContext): Promise<boolean> {
  try {
    const page = await context.newPage();
    let dialogFired = false;
    page.on('dialog', async d => { dialogFired = true; await d.dismiss(); });
    await page.goto(finding.url, { timeout: 10000, waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    await page.close();
    return dialogFired;
  } catch { return false; }
}

export async function verifySqli(finding: RawFinding): Promise<boolean> {
  if (!finding.request?.url) return false;
  try {
    const url = new URL(finding.request.url);
    for (const [key, value] of url.searchParams) {
      if (value.includes("'") || value.includes('OR')) {
        url.searchParams.set(key, "' OR 2=2--");
        const resp = await fetch(url.toString(), { signal: AbortSignal.timeout(10000) });
        const body = await resp.text();
        const errorPatterns = ['SQL', 'mysql', 'syntax error', 'ORA-', 'PostgreSQL', 'sqlite'];
        return errorPatterns.some(p => body.toLowerCase().includes(p.toLowerCase()));
      }
    }
    return false;
  } catch { return false; }
}

export async function verifySubdomainTakeover(finding: RawFinding): Promise<boolean> {
  try {
    const resp = await fetch(finding.url, { signal: AbortSignal.timeout(10000) });
    const body = await resp.text();
    return resp.status === 404 || body.includes("There isn't a GitHub Pages site here") || body.includes('NoSuchBucket');
  } catch { return false; }
}

/**
 * Verify CORS misconfiguration by re-sending a request with an attacker-controlled Origin.
 * Confirms if the server reflects arbitrary origins in Access-Control-Allow-Origin.
 */
export async function verifyCors(finding: RawFinding): Promise<boolean> {
  const targetUrl = finding.request?.url ?? finding.url;
  if (!targetUrl) return false;
  try {
    const evilOrigin = 'https://evil.secbot-verify.com';
    const resp = await fetch(targetUrl, {
      headers: { 'Origin': evilOrigin },
      signal: AbortSignal.timeout(10000),
    });
    const acao = resp.headers.get('access-control-allow-origin');
    if (!acao) return false;
    // Reflects our evil origin exactly — confirmed misconfiguration
    if (acao === evilOrigin) return true;
    // Wildcard with credentials is also a confirmed issue
    if (acao === '*' && resp.headers.get('access-control-allow-credentials') === 'true') return true;
    return false;
  } catch { return false; }
}

/**
 * Verify open redirect by following the redirect chain.
 * Confirms if the server actually redirects to an external domain.
 */
export async function verifyOpenRedirect(finding: RawFinding): Promise<boolean> {
  const targetUrl = finding.request?.url ?? finding.url;
  if (!targetUrl) return false;
  try {
    const resp = await fetch(targetUrl, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
    if (resp.status >= 300 && resp.status < 400) {
      const location = resp.headers.get('location') ?? '';
      try {
        const redirectUrl = new URL(location, targetUrl);
        const originalUrl = new URL(targetUrl);
        // Redirect goes to a different domain — confirmed
        return redirectUrl.hostname !== originalUrl.hostname;
      } catch { return false; }
    }
    return false;
  } catch { return false; }
}

/**
 * Verify CRLF injection by re-sending the payload and checking
 * if injected headers appear in the response.
 */
export async function verifyCrlf(finding: RawFinding): Promise<boolean> {
  const targetUrl = finding.request?.url ?? finding.url;
  if (!targetUrl) return false;
  try {
    const resp = await fetch(targetUrl, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
    // Check if our injected header appears in the response
    const injectedHeader = resp.headers.get('x-secbot-crlf');
    if (injectedHeader) return true;
    // Check for Set-Cookie injection pattern
    const allHeaders = [...resp.headers.entries()];
    return allHeaders.some(([, v]) => v.includes('secbot'));
  } catch { return false; }
}

/**
 * Verify host header injection by re-sending with a canary Host header.
 * Confirms if the server reflects the injected host in the response.
 */
export async function verifyHostHeader(finding: RawFinding): Promise<boolean> {
  const targetUrl = finding.request?.url ?? finding.url;
  if (!targetUrl) return false;
  try {
    const canary = 'verify.secbot-test.com';
    const resp = await fetch(targetUrl, {
      headers: { 'X-Forwarded-Host': canary },
      signal: AbortSignal.timeout(10000),
    });
    const body = await resp.text();
    // Check if canary appears in response body or headers
    if (body.includes(canary)) return true;
    const locationHeader = resp.headers.get('location') ?? '';
    return locationHeader.includes(canary);
  } catch { return false; }
}

/**
 * Verify a missing security header is genuinely absent (not cached/transient).
 * Re-fetches the page and confirms the header is still missing.
 */
export async function verifyMissingHeader(finding: RawFinding): Promise<boolean> {
  try {
    const resp = await fetch(finding.url, {
      signal: AbortSignal.timeout(10000),
    });
    const ev = finding.evidence.toLowerCase();
    if (ev.includes('strict-transport-security')) return !resp.headers.has('strict-transport-security');
    if (ev.includes('x-frame-options')) return !resp.headers.has('x-frame-options');
    if (ev.includes('x-content-type-options')) return !resp.headers.has('x-content-type-options');
    if (ev.includes('content-security-policy')) return !resp.headers.has('content-security-policy');
    // Default: can't verify specific header, assume valid
    return true;
  } catch { return false; }
}

/**
 * Verify CSRF by re-submitting the form action with a cross-origin Origin header.
 * Confirms if the server accepts the request without CSRF token.
 */
export async function verifyCsrf(finding: RawFinding): Promise<boolean> {
  // Extract the form action URL from evidence
  const actionMatch = finding.evidence.match(/Action:\s*(https?:\/\/\S+)/);
  const targetUrl = actionMatch?.[1] ?? finding.url;
  if (!targetUrl) return false;
  try {
    const resp = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://evil.secbot-verify.com',
      },
      body: 'test=1',
      signal: AbortSignal.timeout(10000),
    });
    // Server accepted the cross-origin POST (not 403/401/419)
    return resp.status >= 200 && resp.status < 400;
  } catch { return false; }
}

/**
 * Verify SRI finding by re-fetching the page and confirming external resources
 * still lack integrity attributes. Filters out same-origin CDN resources.
 */
export async function verifySri(finding: RawFinding, context: BrowserContext): Promise<boolean> {
  try {
    const page = await context.newPage();
    await page.goto(finding.url, { timeout: 15000, waitUntil: 'domcontentloaded' });
    const pageHost = new URL(finding.url).hostname.replace(/^www\./, '');

    // Find external scripts/links without integrity
    const noSri = await page.evaluate((host) => {
      const elements = [
        ...document.querySelectorAll('script[src]'),
        ...document.querySelectorAll('link[rel="stylesheet"][href]'),
      ];
      return elements.filter(el => {
        const src = el.getAttribute('src') || el.getAttribute('href') || '';
        if (!src.startsWith('http')) return false;
        if (el.hasAttribute('integrity')) return false;
        try {
          const srcHost = new URL(src).hostname;
          // Skip same-org CDN (e.g., cdn.example.com for example.com)
          if (srcHost.endsWith(host) || host.endsWith(srcHost.replace(/^cdn\./, ''))) return false;
        } catch { /* keep it */ }
        return true;
      }).length;
    }, pageHost);

    await page.close();
    // Only confirmed if truly external resources lack SRI
    return noSri > 0;
  } catch { return false; }
}

/**
 * Verify cookie flag finding by re-fetching and confirming the cookie
 * is a session/auth cookie (not analytics/tracking).
 */
export async function verifyCookieFlags(finding: RawFinding): Promise<boolean> {
  // Extract cookie name from title/evidence
  const nameMatch = finding.title.match(/cookie\s+"([^"]+)"/i)
    || finding.evidence.match(/cookie:\s*(\S+)/i);
  if (!nameMatch) return false;
  const cookieName = nameMatch[1];

  // Known analytics/marketing cookies — not worth reporting
  const ANALYTICS_RE = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|__utm|_mkto_|mto_|_biz|_vwo|_vis_opt|_sp_id|_sp_ses|OptanonConsent|g_state|FPLC|FPID|_hj|_clck|_clsk|hubspot|__hs|intercom|amplitude|mp_|fs_uid|loglevel|_tt_|li_|bcookie|NID|_pin_|_hp2_|ab\.|datagrail)/i;

  if (ANALYTICS_RE.test(cookieName)) return false;

  // Re-fetch to confirm cookie is still set without the flag
  try {
    const resp = await fetch(finding.url, { signal: AbortSignal.timeout(10000) });
    const setCookies = resp.headers.getSetCookie?.() ?? [];
    for (const sc of setCookies) {
      if (sc.startsWith(cookieName + '=')) {
        const lower = sc.toLowerCase();
        if (finding.title.toLowerCase().includes('httponly') && !lower.includes('httponly')) return true;
        if (finding.title.toLowerCase().includes('secure') && !lower.includes('secure')) return true;
      }
    }
    return false;
  } catch { return false; }
}

/**
 * Verify info-disclosure finding by re-fetching the resource.
 * For JS secrets: re-download the JS file and confirm the secret is still present.
 * For file probes: re-fetch and confirm the response still matches.
 */
export async function verifyInfoDisclosure(finding: RawFinding): Promise<boolean> {
  try {
    // JS secret findings: re-fetch the JS file and re-scan
    if (finding.title.startsWith('Hardcoded ')) {
      const matchLine = finding.evidence.match(/Match:\s*(.+)/);
      if (!matchLine) return false;
      const expectedMatch = matchLine[1].replace(/\.\.\.$/, ''); // Remove truncation indicator
      const resp = await fetch(finding.url, { signal: AbortSignal.timeout(10000) });
      if (!resp.ok) return false;
      const body = await resp.text();
      // Confirm the secret is still present in the content
      return body.includes(expectedMatch);
    }

    // File probe findings: re-fetch and confirm non-404
    const resp = await fetch(finding.url, {
      signal: AbortSignal.timeout(10000),
      redirect: 'follow',
    });
    return resp.ok;
  } catch { return false; }
}

export async function verifyFindings(findings: RawFinding[], context: BrowserContext): Promise<RawFinding[]> {
  const results: RawFinding[] = [];
  for (const f of findings) {
    // Verify both medium and high confidence findings — high-confidence from active
    // checks can still be FPs (e.g., XSS markers in error pages, SQLi timing noise).
    // Low-confidence findings are already marked for dropping by pre-filter.
    if (f.confidence === 'medium' || f.confidence === 'high') {
      results.push(await verifyFinding(f, context));
    } else {
      results.push(f);
    }
  }
  return results;
}

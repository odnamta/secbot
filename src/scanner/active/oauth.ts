import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { randomUUID } from 'node:crypto';
import type { RequestLogger } from '../../utils/request-logger.js';

// OAuth endpoint patterns
const OAUTH_PATTERNS = [
  /\/oauth\//i, /\/authorize/i, /\/auth\/callback/i, /\/login\/oauth/i,
  /\/api\/auth/i, /\/connect\/authorize/i, /\.well-known\/openid/i,
  /\/token$/i, /\/oauth2\//i,
];

// Detect OAuth-related URLs from crawled pages
export function findOAuthEndpoints(pages: string[], apiEndpoints: string[]): string[] {
  const all = [...pages, ...apiEndpoints];
  return all.filter(url => OAUTH_PATTERNS.some(p => p.test(url)));
}

async function testMissingState(url: string, config: ScanConfig): Promise<RawFinding | null> {
  // Check if authorize endpoint works without state parameter
  try {
    const parsed = new URL(url);
    // Remove state param if present
    parsed.searchParams.delete('state');
    // Add required OAuth params if missing
    if (!parsed.searchParams.has('response_type')) parsed.searchParams.set('response_type', 'code');
    if (!parsed.searchParams.has('client_id')) parsed.searchParams.set('client_id', 'test');
    if (!parsed.searchParams.has('redirect_uri')) parsed.searchParams.set('redirect_uri', parsed.origin + '/callback');

    const resp = await fetch(parsed.toString(), {
      redirect: 'manual',
      signal: AbortSignal.timeout(config.timeout || 10000),
    });

    // If the endpoint doesn't reject missing state (200 or 302 without error)
    const location = resp.headers.get('location') ?? '';
    if ((resp.status === 200 || resp.status === 302) && !location.includes('error=')) {
      return {
        id: randomUUID(),
        category: 'oauth',
        severity: 'medium',
        title: `OAuth missing state parameter on ${parsed.pathname}`,
        description: 'OAuth authorization endpoint accepts requests without a state parameter, enabling CSRF attacks on the OAuth flow.',
        url: parsed.toString(),
        evidence: `Endpoint responded with ${resp.status} without requiring state parameter`,
        request: { method: 'GET', url: parsed.toString() },
        response: { status: resp.status, headers: Object.fromEntries(resp.headers) },
        timestamp: new Date().toISOString(),
        confidence: resp.status === 302 ? 'high' : 'medium',
      };
    }
  } catch { /* endpoint not reachable */ }
  return null;
}

async function testRedirectUriManipulation(url: string, config: ScanConfig): Promise<RawFinding | null> {
  try {
    const parsed = new URL(url);
    // Try to set redirect_uri to an external domain
    const maliciousRedirect = 'https://evil.secbot-test.example.com/callback';
    parsed.searchParams.set('redirect_uri', maliciousRedirect);
    if (!parsed.searchParams.has('response_type')) parsed.searchParams.set('response_type', 'code');
    if (!parsed.searchParams.has('client_id')) parsed.searchParams.set('client_id', 'test');

    const resp = await fetch(parsed.toString(), {
      redirect: 'manual',
      signal: AbortSignal.timeout(config.timeout || 10000),
    });

    const location = resp.headers.get('location') ?? '';
    // If redirect_uri was accepted and redirects to our evil domain
    if (resp.status === 302 && location.includes('evil.secbot-test')) {
      return {
        id: randomUUID(),
        category: 'oauth',
        severity: 'high',
        title: `OAuth redirect_uri bypass on ${parsed.pathname}`,
        description: 'OAuth authorization endpoint accepts arbitrary redirect_uri values, allowing an attacker to steal authorization codes.',
        url: parsed.toString(),
        evidence: `Redirect accepted to external domain: ${location}`,
        request: { method: 'GET', url: parsed.toString() },
        response: { status: resp.status, headers: Object.fromEntries(resp.headers) },
        timestamp: new Date().toISOString(),
        confidence: 'high',
      };
    }
  } catch { /* endpoint not reachable */ }
  return null;
}

async function testTokenInFragment(pages: string[]): Promise<RawFinding | null> {
  // Check if any page URL has token/access_token in the URL fragment or query
  for (const page of pages) {
    try {
      const url = new URL(page);
      const hasToken = url.searchParams.has('access_token') ||
                       url.searchParams.has('token') ||
                       url.hash.includes('access_token=');
      if (hasToken) {
        return {
          id: randomUUID(),
          category: 'oauth',
          severity: 'medium',
          title: 'OAuth token exposed in URL',
          description: 'Access token found in URL parameters or fragment. Tokens in URLs can leak via Referer headers, browser history, and server logs.',
          url: page,
          evidence: 'access_token found in URL',
          timestamp: new Date().toISOString(),
          confidence: 'high',
        };
      }
    } catch { continue; }
  }
  return null;
}

export const oauthCheck: ActiveCheck = {
  name: 'oauth',
  category: 'oauth',
  parallel: true,
  async run(_context: BrowserContext, targets: ScanTargets, config: ScanConfig, _requestLogger?: RequestLogger): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    const oauthEndpoints = findOAuthEndpoints(targets.pages, targets.apiEndpoints);

    // Also check for token leakage in all pages
    const tokenFinding = await testTokenInFragment(targets.pages);
    if (tokenFinding) findings.push(tokenFinding);

    if (oauthEndpoints.length === 0) return findings;

    // Test each OAuth endpoint
    for (const endpoint of oauthEndpoints.slice(0, 5)) { // limit to 5 endpoints
      const stateFinding = await testMissingState(endpoint, config);
      if (stateFinding) findings.push(stateFinding);

      const redirectFinding = await testRedirectUriManipulation(endpoint, config);
      if (redirectFinding) findings.push(redirectFinding);
    }

    return findings;
  },
};

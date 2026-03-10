import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

// ─── JWT Utilities ──────────────────────────────────────────────────

/** Regex to find JWT tokens (3 dot-separated base64url segments) */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g;

/** Common weak/default JWT secrets used by tutorials, boilerplates, and dev setups */
export const WEAK_SECRETS = [
  'secret',
  'password',
  'jwt_secret',
  'jwt-secret',
  'your-256-bit-secret',
  'your_secret_key',
  'supersecret',
  'changeme',
  'changeit',
  'mysecret',
  'test',
  'key',
  '1234567890',
  'shhhhh',
  'default',
  'my-secret-key',
  'jwt_secret_key',
  'token-secret',
  'HS256-secret',
  'keyboard cat',
  'secretkey',
  'verysecret',
  'development',
  'devkey',
  'appkey',
];

/**
 * Base64url-decode without padding.
 */
export function base64UrlDecode(str: string): string {
  // Add back padding
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Base64url-encode without padding.
 */
function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Parse a JWT token into header, payload, and signature parts.
 * Returns null if the token is malformed.
 */
export function parseJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    return { header, payload, signature: parts[2] || '' };
  } catch {
    return null;
  }
}

/**
 * Build a JWT with "alg": "none" and empty signature.
 */
export function buildNoneAlgToken(originalPayload: Record<string, unknown>): string {
  const header = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = base64UrlEncode(JSON.stringify(originalPayload));
  return `${header}.${payload}.`;
}

/**
 * Build a JWT with "alg": "None" (mixed case variants).
 */
export function buildNoneAlgVariants(originalPayload: Record<string, unknown>): string[] {
  const variants = ['none', 'None', 'NONE', 'nOnE'];
  return variants.map((alg) => {
    const header = base64UrlEncode(JSON.stringify({ alg, typ: 'JWT' }));
    const payload = base64UrlEncode(JSON.stringify(originalPayload));
    return `${header}.${payload}.`;
  });
}

/**
 * Create HMAC-SHA256 signed JWT with a given secret.
 */
async function signHs256(payload: Record<string, unknown>, secret: string): Promise<string> {
  const { createHmac } = await import('node:crypto');
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const signature = createHmac('sha256', secret)
    .update(`${header}.${body}`)
    .digest();
  return `${header}.${body}.${base64UrlEncode(signature)}`;
}

/**
 * Verify if an HMAC-SHA256 JWT was signed with the given secret.
 */
export function verifyHs256(token: string, secret: string): boolean {
  const { createHmac } = require('node:crypto');
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const expected = createHmac('sha256', secret)
    .update(`${parts[0]}.${parts[1]}`)
    .digest();
  return base64UrlEncode(expected) === parts[2];
}

/**
 * Extract JWT tokens from response headers and body.
 */
export function extractJwts(
  headers: Record<string, string>,
  body?: string,
  cookies?: Array<{ name: string; value: string }>,
): Array<{ token: string; source: string }> {
  const results: Array<{ token: string; source: string }> = [];
  const seen = new Set<string>();

  const addToken = (token: string, source: string) => {
    if (!seen.has(token)) {
      seen.add(token);
      results.push({ token, source });
    }
  };

  // Check Authorization header
  const auth = headers['authorization'] || headers['Authorization'];
  if (auth) {
    const match = auth.match(/Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/);
    if (match) addToken(match[1], 'Authorization header');
  }

  // Check Set-Cookie headers
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === 'set-cookie') {
      const cookieTokens = value.match(JWT_RE);
      if (cookieTokens) {
        for (const t of cookieTokens) addToken(t, `Set-Cookie header`);
      }
    }
  }

  // Check cookies
  if (cookies) {
    for (const cookie of cookies) {
      const cookieTokens = cookie.value.match(JWT_RE);
      if (cookieTokens) {
        for (const t of cookieTokens) addToken(t, `Cookie: ${cookie.name}`);
      }
    }
  }

  // Check response body (JSON responses, HTML)
  if (body) {
    const bodyTokens = body.match(JWT_RE);
    if (bodyTokens) {
      for (const t of bodyTokens) addToken(t, 'Response body');
    }
  }

  return results;
}

/**
 * Analyze a JWT for security issues without making network requests.
 */
export function analyzeJwtSecurity(
  parsed: { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string },
  token: string,
): Array<{ issue: string; severity: 'critical' | 'high' | 'medium' | 'low'; detail: string }> {
  const issues: Array<{ issue: string; severity: 'critical' | 'high' | 'medium' | 'low'; detail: string }> = [];

  // Check for "none" algorithm
  const alg = String(parsed.header.alg || '').toLowerCase();
  if (alg === 'none' || alg === 'nona') {
    issues.push({
      issue: 'JWT uses "none" algorithm',
      severity: 'critical',
      detail: `The JWT header specifies alg="${parsed.header.alg}". Tokens with the "none" algorithm have no signature verification — anyone can forge valid tokens.`,
    });
  }

  // Check for missing/empty signature with a signing algorithm declared
  if (alg !== 'none' && !parsed.signature) {
    issues.push({
      issue: 'JWT has signing algorithm but empty signature',
      severity: 'high',
      detail: `The JWT header declares alg="${parsed.header.alg}" but the signature segment is empty. The server may not be verifying signatures.`,
    });
  }

  // Check for missing expiry
  if (!parsed.payload.exp) {
    issues.push({
      issue: 'JWT has no expiry (exp) claim',
      severity: 'medium',
      detail: 'The JWT payload has no "exp" claim. Tokens without expiry never become invalid — if stolen, they can be used indefinitely.',
    });
  }

  // Check for very long expiry (> 30 days)
  if (parsed.payload.exp && typeof parsed.payload.exp === 'number') {
    const now = Math.floor(Date.now() / 1000);
    const ttlDays = (parsed.payload.exp - now) / 86400;
    if (ttlDays > 30) {
      issues.push({
        issue: 'JWT has excessively long expiry',
        severity: 'low',
        detail: `The JWT expires in ${Math.round(ttlDays)} days. Long-lived tokens increase the window for token theft attacks.`,
      });
    }
  }

  // Check for sensitive data in payload
  const sensitiveKeys = ['password', 'passwd', 'secret', 'ssn', 'credit_card', 'creditcard', 'cc_number'];
  for (const key of Object.keys(parsed.payload)) {
    if (sensitiveKeys.some((s) => key.toLowerCase().includes(s))) {
      issues.push({
        issue: `JWT contains potentially sensitive field: ${key}`,
        severity: 'medium',
        detail: `The JWT payload contains the field "${key}" which may expose sensitive data. JWT payloads are base64-encoded (NOT encrypted) — anyone can decode them.`,
      });
    }
  }

  // Check for weak secret (HS256 only)
  if (alg === 'hs256' || alg === 'hs384' || alg === 'hs512') {
    for (const secret of WEAK_SECRETS) {
      if (verifyHs256(token, secret)) {
        issues.push({
          issue: `JWT signed with weak/default secret: "${secret}"`,
          severity: 'critical',
          detail: `The JWT is signed with the well-known secret "${secret}". An attacker can forge any token by signing with this secret. This is a common finding in production apps that ship with default/tutorial secrets.`,
        });
        break; // One match is enough
      }
    }
  }

  return issues;
}

// ─── Active Check ───────────────────────────────────────────────────

export const jwtCheck: ActiveCheck = {
  parallel: true,
  name: 'jwt',
  category: 'jwt',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];
    const analyzedTokens = new Set<string>();

    // Phase 1: Collect JWTs from page responses
    log.info('Collecting JWTs from page responses...');
    const jwtSources = await collectJwtsFromPages(context, targets, config, requestLogger);

    for (const { token, source, pageUrl } of jwtSources) {
      if (analyzedTokens.has(token)) continue;
      analyzedTokens.add(token);

      const parsed = parseJwt(token);
      if (!parsed) continue;

      // Static analysis
      const issues = analyzeJwtSecurity(parsed, token);
      for (const issue of issues) {
        findings.push({
          id: randomUUID(),
          category: 'jwt',
          severity: issue.severity,
          title: issue.issue,
          description: issue.detail,
          url: pageUrl,
          evidence: `Token source: ${source}\nHeader: ${JSON.stringify(parsed.header)}\nPayload keys: ${Object.keys(parsed.payload).join(', ')}\nAlgorithm: ${parsed.header.alg}`,
          timestamp: new Date().toISOString(),
        });
      }

      // Phase 2: Active testing — try "none" algorithm bypass
      if (config.profile !== 'quick') {
        const noneFindings = await testNoneAlgorithm(
          context, token, parsed, pageUrl, source, config, requestLogger,
        );
        findings.push(...noneFindings);
      }
    }

    log.info(`JWT check: ${findings.length} finding(s) from ${analyzedTokens.size} token(s)`);
    return findings;
  },
};

/**
 * Collect JWTs from page responses by visiting pages and checking responses.
 */
async function collectJwtsFromPages(
  context: BrowserContext,
  targets: ScanTargets,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<Array<{ token: string; source: string; pageUrl: string }>> {
  const results: Array<{ token: string; source: string; pageUrl: string }> = [];
  const seen = new Set<string>();

  // Test auth-related and API endpoints (most likely to return JWTs)
  const priorityUrls = targets.pages.filter((url) =>
    /\/(login|auth|token|api|dashboard|profile|account|user)/i.test(url),
  );
  // Add remaining pages (capped)
  const otherUrls = targets.pages.filter((url) => !priorityUrls.includes(url));
  const urlsToCheck = [...priorityUrls, ...otherUrls].slice(0, 15);

  for (const url of urlsToCheck) {
    const page = await context.newPage();
    try {
      const response = await page.request.fetch(url, { timeout: config.timeout });
      const headers = response.headers();
      let body: string | undefined;

      const ct = headers['content-type'] || '';
      if (ct.includes('json') || ct.includes('html') || ct.includes('text')) {
        body = await response.text();
        if (body.length > 50000) body = body.slice(0, 50000);
      }

      // Get cookies from browser context
      const cookies = await context.cookies(url);

      const jwts = extractJwts(headers, body, cookies);
      for (const { token, source } of jwts) {
        if (!seen.has(token)) {
          seen.add(token);
          results.push({ token, source, pageUrl: url });
        }
      }

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url,
        responseStatus: response.status(),
        phase: 'active-jwt-collect',
      });
    } catch (err) {
      log.debug(`JWT collect: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return results;
}

/**
 * Test if the server accepts a JWT with "none" algorithm (no signature).
 * This is the highest-impact JWT vulnerability — allows complete token forgery.
 */
async function testNoneAlgorithm(
  context: BrowserContext,
  originalToken: string,
  parsed: { header: Record<string, unknown>; payload: Record<string, unknown> },
  pageUrl: string,
  source: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const alg = String(parsed.header.alg || '').toLowerCase();

  // Skip if already using "none"
  if (alg === 'none') return findings;

  // Build "none" algorithm variants
  const noneTokens = buildNoneAlgVariants(parsed.payload);

  // Find auth-related endpoints to test the forged token against
  const testEndpoints = findAuthEndpoints(pageUrl, source);
  if (testEndpoints.length === 0) return findings;

  for (const endpoint of testEndpoints.slice(0, 2)) {
    for (const forgedToken of noneTokens) {
      const page = await context.newPage();
      try {
        // Try with Authorization header
        const response = await page.request.fetch(endpoint, {
          headers: { Authorization: `Bearer ${forgedToken}` },
          timeout: config.timeout,
        });
        const status = response.status();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: endpoint,
          responseStatus: status,
          phase: 'active-jwt-none-alg',
        });

        // If the server accepts the forged token (2xx response), it's vulnerable
        if (status >= 200 && status < 300) {
          // Confirm by comparing with original — only flag if original also succeeds
          const origResponse = await page.request.fetch(endpoint, {
            headers: { Authorization: `Bearer ${originalToken}` },
            timeout: config.timeout,
          });

          if (origResponse.status() >= 200 && origResponse.status() < 300) {
            const forgedParsed = parseJwt(forgedToken);
            findings.push({
              id: randomUUID(),
              category: 'jwt',
              severity: 'critical',
              title: 'JWT "none" Algorithm Accepted — Token Forgery Possible',
              description: `The server accepts JWT tokens with alg="none" (no signature). An attacker can forge any token by setting the algorithm to "none" and removing the signature. This allows complete authentication bypass — any user/role can be impersonated.`,
              url: endpoint,
              evidence: [
                `Original token algorithm: ${parsed.header.alg}`,
                `Forged token algorithm: ${forgedParsed?.header.alg}`,
                `Forged token accepted with HTTP ${status}`,
                `Original token status: ${origResponse.status()}`,
                `Token source: ${source}`,
              ].join('\n'),
              request: {
                method: 'GET',
                url: endpoint,
                headers: { Authorization: `Bearer ${forgedToken}` },
              },
              response: { status },
              timestamp: new Date().toISOString(),
            });
            return findings; // One proof is enough
          }
        }
      } catch (err) {
        log.debug(`JWT none-alg test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

/**
 * Find endpoints where we can test a forged JWT.
 * Prefers the URL where the token was found + common authenticated endpoints.
 */
function findAuthEndpoints(pageUrl: string, source: string): string[] {
  const endpoints = [pageUrl];
  try {
    const base = new URL(pageUrl);
    // Add common auth-gated API paths
    const paths = ['/api/me', '/api/user', '/api/profile', '/api/account', '/api/v1/me', '/rest/user/whoami'];
    for (const path of paths) {
      endpoints.push(`${base.origin}${path}`);
    }
  } catch { /* ignore */ }
  return endpoints;
}

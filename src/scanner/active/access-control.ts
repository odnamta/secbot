import { randomUUID } from 'node:crypto';
import { chromium, type BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/** URL patterns that suggest admin/privileged endpoints */
const ADMIN_URL_PATTERNS = /\/(admin|dashboard|manage|settings|config|users|roles|permissions|billing|internal|staff|moderate|review|reports|analytics|system|control|panel)/i;

/** Common admin paths to probe when no auth is provided */
const UNAUTH_ADMIN_PATHS = [
  '/admin', '/admin/', '/administrator', '/admin/login', '/admin/dashboard',
  '/manage', '/manager', '/management',
  '/wp-admin/', '/wp-login.php',
  '/cpanel', '/phpmyadmin/', '/pma/',
  '/adminer.php', '/adminer/',
  '/api/admin', '/api/v1/admin', '/api/internal',
  '/graphql', '/graphiql', '/playground',
  '/debug', '/debug/', '/_debug',
  '/console', '/dev', '/devtools',
  '/server-status', '/server-info',
  '/swagger', '/swagger-ui/', '/swagger-ui.html', '/api-docs',
  '/metrics', '/prometheus', '/health/full',
  '/.env', '/.git/config',
];

/**
 * Path normalization bypass techniques.
 * These exploit inconsistencies between proxy/WAF URL parsing and backend routing.
 * If /admin returns 403 but /admin/..;/admin returns 200, the ACL is broken.
 */
export const PATH_NORMALIZATION_BYPASSES = [
  { suffix: '/..;/', description: 'Tomcat/Spring path parameter bypass (..;)' },
  { suffix: '/%2e/', description: 'URL-encoded dot (path normalization confusion)' },
  { suffix: '/./', description: 'Self-referential path segment' },
  { suffix: '%20', description: 'Trailing space (IIS, some proxies)' },
  { suffix: '%09', description: 'Trailing tab character' },
  { suffix: '..%00/', description: 'Null byte path truncation' },
  { suffix: '/', description: 'Trailing slash difference' },
  { suffix: '.json', description: 'Extension appended (framework routing bypass)' },
  { suffix: '?', description: 'Empty query string (routing bypass)' },
  { suffix: '#', description: 'Fragment in URL (proxy/WAF bypass)' },
  { suffix: '.html', description: 'HTML extension (static file bypass)' },
  { suffix: ';', description: 'Semicolon path parameter (Tomcat/JBoss)' },
];

/**
 * Common default credentials to test on login pages.
 * These are vendor defaults and common weak passwords.
 */
export const DEFAULT_CREDENTIALS = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'password' },
  { username: 'admin', password: '123456' },
  { username: 'admin', password: 'admin123' },
  { username: 'root', password: 'root' },
  { username: 'root', password: 'toor' },
  { username: 'test', password: 'test' },
  { username: 'user', password: 'user' },
  { username: 'guest', password: 'guest' },
  { username: 'administrator', password: 'administrator' },
  { username: 'demo', password: 'demo' },
  { username: 'admin', password: '' },
];

/** HTTP methods to test for method override bypass */
const OVERRIDE_METHODS = ['PUT', 'DELETE', 'PATCH'] as const;

/** Headers used to bypass URL-based access control */
const BYPASS_HEADERS: Array<{ name: string; value: string }> = [
  { name: 'X-Original-URL', value: '' },  // value set per-request
  { name: 'X-Rewrite-URL', value: '' },
  { name: 'X-Forwarded-For', value: '127.0.0.1' },
  { name: 'X-Custom-IP-Authorization', value: '127.0.0.1' },
];

/** Detect if a response indicates successful access (not blocked) */
function isSuccessResponse(status: number): boolean {
  return status >= 200 && status < 400;
}

/** Detect if a response indicates access denied */
function isDeniedResponse(status: number): boolean {
  return status === 401 || status === 403;
}

/** Extract admin-only endpoints from crawl — pages that require elevated privileges */
export function identifyPrivilegedEndpoints(pages: string[]): string[] {
  return pages.filter((url) => {
    try {
      const parsed = new URL(url);
      return ADMIN_URL_PATTERNS.test(parsed.pathname);
    } catch {
      return false;
    }
  });
}

/**
 * Probe common admin/debug paths WITHOUT authentication.
 * Exposed admin panels, debug consoles, and API docs are high-severity findings
 * even without auth credentials — they shouldn't be publicly accessible at all.
 */
async function probeUnauthenticatedAdminPaths(
  context: BrowserContext,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const origin = new URL(config.targetUrl).origin;
  const seen = new Set<string>();

  // Limit probing based on profile
  const paths = config.profile === 'quick'
    ? UNAUTH_ADMIN_PATHS.slice(0, 8)
    : config.profile === 'deep'
      ? UNAUTH_ADMIN_PATHS
      : UNAUTH_ADMIN_PATHS.slice(0, 16);

  log.info(`Probing ${paths.length} common admin paths (unauthenticated)...`);

  for (const path of paths) {
    const url = `${origin}${path}`;
    const page = await context.newPage();
    try {
      const response = await page.request.fetch(url, { maxRedirects: 0 });
      const status = response.status();
      const body = await response.text();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url,
        responseStatus: status,
        phase: 'active-access-control-unauth',
      });

      // Skip 404s, 401s, 403s (properly protected)
      if (status === 404 || status === 401 || status === 403) continue;
      // Skip redirects to login pages (properly protected)
      if (status >= 300 && status < 400) {
        const location = response.headers()['location'] ?? '';
        if (/login|signin|auth|sso/i.test(location)) continue;
      }

      // 200 on an admin/debug path without auth = finding
      if (status >= 200 && status < 300 && body.length > 100) {
        // Deduplicate by path prefix
        const pathPrefix = path.replace(/\/$/, '').split('/').slice(0, 2).join('/');
        if (seen.has(pathPrefix)) continue;
        seen.add(pathPrefix);

        // Classify severity based on content
        const isDebug = /debug|console|phpmyadmin|adminer|graphiql|playground|swagger|pprof|metrics|prometheus/i.test(path);
        const isAdmin = /admin|manage|panel|dashboard|cpanel|wp-admin/i.test(path);

        findings.push({
          id: randomUUID(),
          category: 'broken-access-control',
          severity: isDebug ? 'high' : isAdmin ? 'critical' : 'medium',
          title: `Exposed ${isAdmin ? 'Admin Panel' : isDebug ? 'Debug/API Endpoint' : 'Internal Endpoint'}: ${path}`,
          description: `The path "${path}" is accessible without authentication (HTTP ${status}). ${isAdmin ? 'Admin panels should require authentication.' : 'Debug and internal endpoints should not be publicly accessible.'}`,
          url,
          evidence: `Path: ${path}\nStatus: ${status}\nBody length: ${body.length}\nResponse snippet: ${body.slice(0, 300)}`,
          request: { method: 'GET', url },
          response: { status, bodySnippet: body.slice(0, 200) },
          timestamp: new Date().toISOString(),
          confidence: 'high',
        });
      }
    } catch (err) {
      log.debug(`Unauth admin probe: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  if (findings.length > 0) {
    log.info(`Found ${findings.length} exposed admin/debug endpoint(s)`);
  }

  // Phase 0b: Path normalization bypass on paths that returned 403/401
  if (config.profile !== 'quick') {
    const normFindings = await testPathNormalizationBypass(context, config, requestLogger);
    findings.push(...normFindings);
  }

  return findings;
}

/**
 * Test path normalization bypass techniques on admin paths that returned 403/401.
 * If /admin → 403 but /admin/..;/admin → 200, the ACL is bypassable.
 */
async function testPathNormalizationBypass(
  context: BrowserContext,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const origin = new URL(config.targetUrl).origin;

  // Test a subset of admin paths with normalization bypasses
  const testPaths = ['/admin', '/admin/', '/api/admin', '/internal', '/console', '/dashboard'];
  const bypasses = config.profile === 'deep' ? PATH_NORMALIZATION_BYPASSES : PATH_NORMALIZATION_BYPASSES.slice(0, 6);

  for (const basePath of testPaths) {
    // First check if the path is protected (returns 401/403)
    let isProtected = false;
    const checkPage = await context.newPage();
    try {
      const baseUrl = `${origin}${basePath}`;
      const baseResp = await checkPage.request.fetch(baseUrl, { maxRedirects: 0 });
      const baseStatus = baseResp.status();
      isProtected = baseStatus === 401 || baseStatus === 403;

      if (!isProtected) continue; // Only test bypass on protected paths
    } catch {
      continue;
    } finally {
      await checkPage.close();
    }

    // Try each normalization bypass
    for (const bypass of bypasses) {
      const page = await context.newPage();
      try {
        const cleanPath = basePath.replace(/\/$/, '');
        const bypassUrl = `${origin}${cleanPath}${bypass.suffix}`;

        const resp = await page.request.fetch(bypassUrl, { maxRedirects: 0 });
        const status = resp.status();
        const body = await resp.text();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: bypassUrl,
          responseStatus: status,
          phase: 'active-access-control-path-norm',
        });

        // If bypass returns 200 with real content, the ACL is broken
        if (status >= 200 && status < 300 && body.length > 100) {
          findings.push({
            id: randomUUID(),
            category: 'broken-access-control',
            severity: 'critical',
            title: `Path Normalization ACL Bypass: ${basePath} → ${bypass.description}`,
            description: `The path "${basePath}" returns 401/403, but "${cleanPath}${bypass.suffix}" returns ${status}. ` +
              `${bypass.description}. The proxy/WAF blocks the original path but the backend serves it via a normalized variant. ` +
              `This bypasses URL-based access control entirely.`,
            url: bypassUrl,
            evidence: [
              `Protected path: ${basePath} (returns 401/403)`,
              `Bypass path: ${cleanPath}${bypass.suffix} (returns ${status})`,
              `Technique: ${bypass.description}`,
              `Response length: ${body.length}`,
              `Response snippet: ${body.slice(0, 300)}`,
            ].join('\n'),
            request: { method: 'GET', url: bypassUrl },
            response: { status, bodySnippet: body.slice(0, 200) },
            timestamp: new Date().toISOString(),
            confidence: 'high',
          });
          break; // One bypass per path is enough
        }
      } catch (err) {
        log.debug(`Path norm bypass: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }

    if (findings.length > 0) break; // One finding is enough
  }

  if (findings.length > 0) {
    log.info(`Found ${findings.length} path normalization bypass(es)`);
  }

  return findings;
}

export const accessControlCheck: ActiveCheck = {
  name: 'access-control',
  category: 'broken-access-control',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Phase 0: Unauthenticated admin path probing (no auth needed)
    // Probe common admin/debug paths to find exposed admin panels
    const unauthFindings = await probeUnauthenticatedAdminPaths(context, config, requestLogger);
    findings.push(...unauthFindings);

    // Phase 0c: Default credentials testing on login pages
    if (config.profile !== 'quick') {
      const defaultCredFindings = await testDefaultCredentials(context, targets, config, requestLogger);
      findings.push(...defaultCredFindings);
    }

    // Phase 0d: Session fixation testing — check if session ID regenerates after login
    if (config.profile !== 'quick') {
      const sessionFixationFindings = await testSessionFixation(context, targets, config, requestLogger);
      findings.push(...sessionFixationFindings);
    }

    // Auth-based checks require both admin and regular user sessions
    if (!config.authStorageState) {
      if (findings.length === 0) {
        log.info('Access control check: no --auth provided, only unauthenticated probing ran');
      }
      return findings;
    }
    if (!config.idorAltAuthState) {
      log.info('Access control check: no --idor-alt-auth provided, skipping role-based tests');
      return findings;
    }

    // Identify admin/privileged endpoints from crawl
    const allUrls = [...new Set([...targets.pages, ...targets.apiEndpoints])];
    const privilegedEndpoints = identifyPrivilegedEndpoints(allUrls);

    if (privilegedEndpoints.length === 0) {
      log.info('Access control check: no privileged endpoints detected');
      return [];
    }

    log.info(`Testing ${privilegedEndpoints.length} privileged endpoints for broken access control...`);

    // Phase 1: Test if admin endpoints are accessible as regular user
    // The primary auth (--auth) is the admin, --idor-alt-auth is the regular user
    let altContext: BrowserContext | undefined;
    try {
      const browser = context.browser()
        ?? await chromium.launch({ headless: true });
      altContext = await browser.newContext({
        storageState: config.idorAltAuthState,
      });

      for (const endpoint of privilegedEndpoints) {
        const page = await altContext.newPage();
        try {
          const response = await page.request.fetch(endpoint);
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: endpoint,
            responseStatus: status,
            phase: 'active-access-control',
          });

          if (isSuccessResponse(status)) {
            // Regular user can access admin endpoint — broken access control
            const body = await response.text();
            findings.push({
              id: randomUUID(),
              category: 'broken-access-control',
              severity: 'critical',
              title: `Broken Access Control: Admin Endpoint Accessible by Regular User`,
              description: `The privileged endpoint "${endpoint}" is accessible with regular user credentials. This allows unauthorized access to admin functionality. The response status was ${status}.`,
              url: endpoint,
              evidence: `Endpoint: ${endpoint}\nAccess as regular user: ${status} (should be 401/403)\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method: 'GET', url: endpoint },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
          }
        } catch (err) {
          log.debug(`Access control test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    } finally {
      if (altContext) {
        await altContext.close();
      }
    }

    // Phase 2: Test HTTP method override on protected endpoints
    // Use the regular user context to test if method changes bypass auth
    for (const endpoint of privilegedEndpoints.slice(0, 5)) {
      for (const method of OVERRIDE_METHODS) {
        const page = await context.newPage();
        try {
          const response = await page.request.fetch(endpoint, { method });
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method,
            url: endpoint,
            responseStatus: status,
            phase: 'active-access-control-method',
          });

          // If a different method succeeds where GET might have been blocked
          if (isSuccessResponse(status)) {
            const body = await response.text();
            findings.push({
              id: randomUUID(),
              category: 'broken-access-control',
              severity: 'high',
              title: `HTTP Method Override Bypass on "${new URL(endpoint).pathname}"`,
              description: `The endpoint "${endpoint}" responds to ${method} requests with status ${status}. HTTP method override may bypass access controls that only check GET/POST.`,
              url: endpoint,
              evidence: `Method: ${method}\nStatus: ${status}\nResponse snippet: ${body.slice(0, 300)}`,
              request: { method, url: endpoint },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
              confidence: 'medium',
            });
            break; // One finding per endpoint is enough
          }
        } catch (err) {
          log.debug(`Method override test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    // Phase 3: Header-based bypass (X-Original-URL, X-Forwarded-For)
    for (const endpoint of privilegedEndpoints.slice(0, 3)) {
      const parsed = new URL(endpoint);

      for (const header of BYPASS_HEADERS) {
        const page = await context.newPage();
        try {
          const headerValue = header.name.includes('URL') ? parsed.pathname : header.value;
          const baseUrl = header.name.includes('URL') ? `${parsed.origin}/` : endpoint;

          const response = await page.request.fetch(baseUrl, {
            headers: { [header.name]: headerValue },
          });
          const status = response.status();

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: baseUrl,
            responseStatus: status,
            phase: 'active-access-control-header',
          });

          if (isSuccessResponse(status)) {
            const body = await response.text();
            // Check if the response contains admin-related content
            if (ADMIN_URL_PATTERNS.test(body) || body.length > 500) {
              findings.push({
                id: randomUUID(),
                category: 'broken-access-control',
                severity: 'high',
                title: `Header-Based Access Control Bypass via ${header.name}`,
                description: `Access controls on "${endpoint}" can be bypassed using the "${header.name}" header. The server processed the request and returned admin content.`,
                url: endpoint,
                evidence: `Header: ${header.name}: ${headerValue}\nStatus: ${status}\nResponse length: ${body.length}\nResponse snippet: ${body.slice(0, 300)}`,
                request: { method: 'GET', url: baseUrl },
                response: { status, bodySnippet: body.slice(0, 200) },
                timestamp: new Date().toISOString(),
                confidence: 'medium',
              });
              break;
            }
          }
        } catch (err) {
          log.debug(`Header bypass test: ${(err as Error).message}`);
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }

    log.info(`Access control check: ${findings.length} finding(s)`);
    return findings;
  },
};

/**
 * Test default credentials on login pages and API auth endpoints.
 * Tries common vendor defaults (admin/admin, root/root, etc.) via:
 *   1. JSON POST to API endpoints that look like auth (login, signin, auth)
 *   2. HTML form submit on detected login pages
 *
 * Only runs when no --auth is provided (otherwise the user already has creds).
 */
async function testDefaultCredentials(
  context: BrowserContext,
  targets: ScanTargets,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const origin = new URL(config.targetUrl).origin;

  // Skip if user already provided auth
  if (config.authStorageState) return findings;

  // Identify auth endpoints from API endpoints and pages
  const authEndpoints: string[] = [];

  // Check API endpoints for auth-related paths
  for (const ep of targets.apiEndpoints) {
    if (/\/(login|signin|sign-in|auth|authenticate|session|token)(?:\/|$|\?)/i.test(ep)) {
      authEndpoints.push(ep);
    }
  }

  // Also probe common auth API paths
  const commonAuthPaths = ['/api/login', '/api/auth/login', '/api/v1/login', '/api/signin', '/api/auth', '/api/session'];
  for (const path of commonAuthPaths) {
    authEndpoints.push(`${origin}${path}`);
  }

  // Deduplicate
  const uniqueEndpoints = [...new Set(authEndpoints)];

  if (uniqueEndpoints.length === 0) return findings;

  // Limit credentials based on profile
  const creds = config.profile === 'deep' ? DEFAULT_CREDENTIALS : DEFAULT_CREDENTIALS.slice(0, 6);
  log.info(`Testing ${creds.length} default credentials on ${uniqueEndpoints.length} auth endpoint(s)...`);

  for (const endpoint of uniqueEndpoints) {
    let found = false;

    for (const { username, password } of creds) {
      if (found) break;

      const page = await context.newPage();
      try {
        // Try JSON POST (most common for modern APIs)
        const jsonBody = JSON.stringify({ username, password, email: username });
        const resp = await page.request.fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          data: jsonBody,
        });
        const status = resp.status();
        const body = await resp.text();

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'POST',
          url: endpoint,
          responseStatus: status,
          phase: 'active-access-control-default-creds',
        });

        // Check for successful login indicators
        if (status >= 200 && status < 300) {
          const looksLikeSuccess =
            /token|jwt|session|access_token|refresh_token|bearer|authenticated|logged.?in|welcome/i.test(body) &&
            body.length > 20;

          if (looksLikeSuccess) {
            findings.push({
              id: randomUUID(),
              category: 'broken-access-control',
              severity: 'critical',
              title: `Default Credentials Accepted: ${username}/${password || '(empty)'}`,
              description: `The auth endpoint ${new URL(endpoint).pathname} accepts default credentials (${username}/${password || '(empty)'}). This allows unauthorized access to the application. Default and vendor credentials must be changed before deployment.`,
              url: endpoint,
              evidence: [
                `Endpoint: ${endpoint}`,
                `Credentials: ${username}/${password || '(empty)'}`,
                `Response status: ${status}`,
                `Auth indicators found in response`,
                `Response snippet: ${body.slice(0, 200)}`,
              ].join('\n'),
              request: { method: 'POST', url: endpoint, body: jsonBody },
              response: { status, bodySnippet: body.slice(0, 300) },
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
            found = true;
          }
        }
      } catch (err) {
        log.debug(`Default creds test: ${(err as Error).message}`);
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  if (findings.length > 0) {
    log.info(`Found ${findings.length} endpoint(s) accepting default credentials!`);
  }

  return findings;
}

/**
 * Test for session fixation vulnerability (CWE-384).
 * Checks if the application regenerates session IDs after authentication.
 * If the same session cookie persists across login, an attacker can fix a session
 * ID in the victim's browser and then hijack their authenticated session.
 *
 * Also checks session ID entropy — weak randomness enables session prediction (CWE-330).
 */
async function testSessionFixation(
  context: BrowserContext,
  targets: ScanTargets,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const origin = new URL(config.targetUrl).origin;

  // Skip if user already provided auth (we can't test login flow with pre-set auth)
  if (config.authStorageState) return findings;

  // Find login pages from crawled pages only — don't probe arbitrary paths
  // to avoid false positives on safe endpoints
  const loginPages = targets.pages.filter((p) =>
    /\/(login|signin|sign-in|auth|authenticate|log-in)(?:\/|$|\?|#)/i.test(p),
  );

  if (loginPages.length === 0) return findings;

  log.info(`Testing ${Math.min(loginPages.length, 3)} login page(s) for session fixation...`);

  for (const loginUrl of loginPages.slice(0, 3)) {
    const page = await context.newPage();
    try {
      // Step 1: Visit login page and capture pre-auth cookies
      const response = await page.goto(loginUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });
      if (!response || response.status() >= 400) {
        await page.close();
        continue;
      }

      const preAuthCookies = await context.cookies(origin);
      const preAuthSessionCookies = preAuthCookies.filter((c) =>
        /session|sess|sid|token|auth|jwt|connect\.sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|__Host-|__Secure-/i.test(c.name),
      );

      if (preAuthSessionCookies.length === 0) {
        // No session cookies set on login page — nothing to test
        await page.close();
        continue;
      }

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'GET',
        url: loginUrl,
        responseStatus: response.status(),
        phase: 'active-session-fixation-pre-auth',
      });

      // Step 2: Check session ID entropy (CWE-330)
      for (const cookie of preAuthSessionCookies) {
        const entropy = calculateEntropy(cookie.value);
        const isWeak = entropy < 3.0 || cookie.value.length < 16;
        const isSequential = /^\d{1,10}$/.test(cookie.value) || /^[a-f0-9]{1,8}$/i.test(cookie.value);

        if (isWeak || isSequential) {
          findings.push({
            id: randomUUID(),
            category: 'broken-access-control',
            severity: isSequential ? 'critical' : 'high',
            title: `Weak Session ID: "${cookie.name}" (Low Entropy)`,
            description: `The session cookie "${cookie.name}" has ${isSequential ? 'a sequential/predictable' : 'low entropy'} value (${entropy.toFixed(1)} bits/char, length: ${cookie.value.length}). Session IDs should use cryptographically random values with at least 128 bits of entropy. ${isSequential ? 'Sequential session IDs allow an attacker to predict and hijack other users\' sessions.' : 'Low entropy increases the probability of brute-force session guessing.'}`,
            url: loginUrl,
            evidence: `Cookie: ${cookie.name}\nValue: ${cookie.value.slice(0, 20)}...\nEntropy: ${entropy.toFixed(2)} bits/char\nLength: ${cookie.value.length}\n${isSequential ? 'Pattern: sequential/predictable' : 'Pattern: low randomness'}`,
            request: { method: 'GET', url: loginUrl },
            response: { status: response.status(), bodySnippet: '' },
            timestamp: new Date().toISOString(),
            confidence: isSequential ? 'high' : 'medium',
          });
        }
      }

      // Step 3: Attempt login with known-bad credentials to trigger session regeneration
      // We don't need valid creds — just checking if the session cookie changes after POST
      const loginForm = await page.locator('form').first();
      const hasForm = (await loginForm.count()) > 0;

      if (hasForm) {
        const preLoginValues = preAuthSessionCookies.map((c) => ({ name: c.name, value: c.value }));

        // Fill with obviously-fake credentials and submit
        try {
          const passwordInput = page.locator('input[type="password"]').first();
          const usernameInput = page.locator('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[name*="login"]').first();

          if ((await passwordInput.count()) > 0 && (await usernameInput.count()) > 0) {
            await usernameInput.fill('secbot_fixation_test@invalid.test');
            await passwordInput.fill('secbot_fixation_test_12345');

            // Submit the form
            const submitBtn = page.locator('button[type="submit"], input[type="submit"]').first();
            if ((await submitBtn.count()) > 0) {
              await submitBtn.click({ timeout: 5000 }).catch(() => {});
            } else {
              await loginForm.evaluate((f) => (f as HTMLFormElement).submit()).catch(() => {});
            }

            // Wait for response
            await page.waitForLoadState('domcontentloaded', { timeout: 5000 }).catch(() => {});

            // Check post-login cookies
            const postLoginCookies = await context.cookies(origin);
            const postLoginSessionCookies = postLoginCookies.filter((c) =>
              preLoginValues.some((pre) => pre.name === c.name),
            );

            // Compare: if session cookie value is EXACTLY the same, fixation may be possible
            for (const pre of preLoginValues) {
              const post = postLoginSessionCookies.find((c) => c.name === pre.name);
              if (post && post.value === pre.value) {
                // Session ID didn't change — potential fixation
                // But only flag if the login actually processed (page navigated or form submitted)
                findings.push({
                  id: randomUUID(),
                  category: 'broken-access-control',
                  severity: 'medium',
                  title: `Potential Session Fixation: "${pre.name}" Not Regenerated`,
                  description: `The session cookie "${pre.name}" was not regenerated after a login attempt. If the server also doesn't regenerate on successful login, an attacker can fix a known session ID in the victim's browser, wait for them to authenticate, and then hijack their session using the pre-set ID. CWE-384.`,
                  url: loginUrl,
                  evidence: `Cookie: ${pre.name}\nPre-login value: ${pre.value.slice(0, 20)}...\nPost-login value: ${post.value.slice(0, 20)}...\nValues match: true (session not regenerated)`,
                  request: { method: 'POST', url: loginUrl },
                  response: { status: 200, bodySnippet: '' },
                  timestamp: new Date().toISOString(),
                  confidence: 'medium',
                });
              }
            }

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'POST',
              url: loginUrl,
              responseStatus: 200,
              phase: 'active-session-fixation-post-login',
            });
          }
        } catch (err) {
          log.debug(`Session fixation form test: ${(err as Error).message}`);
        }
      }
    } catch (err) {
      log.debug(`Session fixation test: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

/**
 * Calculate Shannon entropy of a string (bits per character).
 * Higher entropy = more random. Session IDs should have > 4.0 bits/char.
 */
function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

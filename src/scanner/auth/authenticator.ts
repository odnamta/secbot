import type { Page, BrowserContext } from 'playwright';
import type { AuthOptions, AuthResult, CookieInfo } from '../types.js';
import { detectLoginForm } from './login-detector.js';
import { log } from '../../utils/logger.js';

/** Default timeout for navigation after login submission (ms) */
const POST_LOGIN_TIMEOUT = 15000;

/**
 * Authenticate against a target application.
 *
 * Flow:
 *  1. Navigate to loginUrl
 *  2. Detect or use provided selectors for the login form
 *  3. Fill username + password
 *  4. Extract CSRF token if present
 *  5. Submit form and wait for navigation
 *  6. Capture storage state (cookies + localStorage)
 */
export async function authenticate(
  page: Page,
  options: AuthOptions,
): Promise<AuthResult> {
  const { loginUrl, username, password } = options;

  log.info(`Authenticating at ${loginUrl} as "${username}"...`);

  try {
    // Step 1: Navigate to login page
    await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: 30000 });

    // Step 2: Determine selectors — prefer user-provided, fall back to auto-detect
    let usernameSelector = options.usernameSelector;
    let passwordSelector = options.passwordSelector;
    let submitSelector = options.submitSelector;

    if (!usernameSelector || !passwordSelector || !submitSelector) {
      const detected = await detectLoginForm(page);
      if (!detected) {
        return {
          success: false,
          cookies: [],
          error: `No login form detected at ${loginUrl}`,
        };
      }
      usernameSelector = usernameSelector ?? detected.usernameSelector;
      passwordSelector = passwordSelector ?? detected.passwordSelector;
      submitSelector = submitSelector ?? detected.submitSelector;
    }

    // Step 3: Extract CSRF token before submitting
    const csrfToken = await extractCsrfToken(page);
    if (csrfToken) {
      log.debug(`CSRF token found: ${csrfToken.slice(0, 8)}...`);
    }

    // Step 4: Fill in credentials
    await page.fill(usernameSelector, username);
    await page.fill(passwordSelector, password);

    // Step 5: Submit and wait for navigation
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle', timeout: POST_LOGIN_TIMEOUT }).catch(() => {
        // Some SPAs don't do a full navigation — that's fine
        log.debug('No full navigation after submit (SPA detected?)');
      }),
      page.click(submitSelector),
    ]);

    // Brief pause to let any post-login redirects settle
    await page.waitForTimeout(1000);

    // Step 6: Check for success — heuristic: still on login page?
    const currentUrl = page.url();
    const stillOnLogin = currentUrl === loginUrl || currentUrl.includes('/login') || currentUrl.includes('/signin');

    // Check for error messages on the page
    const hasError = await page.evaluate(() => {
      const errorPatterns = [
        '.error', '.alert-danger', '.alert-error', '[role="alert"]',
        '.login-error', '.auth-error', '.form-error',
      ];
      for (const sel of errorPatterns) {
        const el = document.querySelector(sel);
        if (el && el.textContent && el.textContent.trim().length > 0) {
          return el.textContent.trim().slice(0, 200);
        }
      }
      return null;
    });

    if (hasError && stillOnLogin) {
      return {
        success: false,
        cookies: [],
        error: `Login appears to have failed. Error on page: ${hasError}`,
      };
    }

    // Step 7: Capture storage state
    const context = page.context();
    const storageState = JSON.stringify(await context.storageState());
    const cookies = await extractCookies(context, currentUrl);

    log.info(`Authentication successful — redirected to ${currentUrl}`);

    return {
      success: true,
      storageState,
      csrfToken: csrfToken ?? undefined,
      cookies,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.error(`Authentication failed: ${message}`);
    return {
      success: false,
      cookies: [],
      error: message,
    };
  }
}

/**
 * Extract CSRF token from the page.
 *
 * Checks (in priority order):
 *  1. <meta name="csrf-token" content="...">
 *  2. <meta name="_csrf" content="...">
 *  3. <input name="_csrf" value="...">
 *  4. <input name="csrf_token" value="...">
 *  5. <input name="_token" value="...">
 *  6. <input name="authenticity_token" value="..."> (Rails)
 */
export async function extractCsrfToken(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    // Meta tags
    const metaSelectors = [
      'meta[name="csrf-token"]',
      'meta[name="_csrf"]',
      'meta[name="csrf_token"]',
      'meta[name="X-CSRF-Token"]',
    ];
    for (const sel of metaSelectors) {
      const meta = document.querySelector(sel);
      if (meta) {
        const content = meta.getAttribute('content');
        if (content) return content;
      }
    }

    // Hidden inputs
    const inputSelectors = [
      'input[name="_csrf"]',
      'input[name="csrf_token"]',
      'input[name="_token"]',
      'input[name="authenticity_token"]',
      'input[name="csrfmiddlewaretoken"]', // Django
      'input[name="__RequestVerificationToken"]', // ASP.NET
    ];
    for (const sel of inputSelectors) {
      const input = document.querySelector(sel) as HTMLInputElement | null;
      if (input?.value) return input.value;
    }

    return null;
  });
}

async function extractCookies(context: BrowserContext, url: string): Promise<CookieInfo[]> {
  const cookies = await context.cookies(url);
  return cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: c.sameSite,
  }));
}

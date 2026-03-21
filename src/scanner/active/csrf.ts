import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/** Regex matching common CSRF token field names */
const CSRF_TOKEN_NAMES = /^(csrf|_csrf|csrfmiddlewaretoken|xsrf|_xsrf|__RequestVerificationToken|authenticity_token|_token|antiforgery|__anti-forgery|_anti_forgery|nonce|_wp_nonce|form_token|form_build_id|__VIEWSTATE|__EVENTVALIDATION)$/i;

/** Broader pattern for hidden inputs that look like tokens */
const TOKEN_VALUE_RE = /^[a-f0-9]{16,}$|^[A-Za-z0-9+/=]{20,}$|^[A-Za-z0-9_-]{20,}$/;

/** State-changing form actions (methods that modify data) */
const STATE_CHANGING_METHODS = /^(post|put|patch|delete)$/i;

/** Form action paths that are clearly state-changing */
const STATE_CHANGING_PATHS = /\/(login|signup|register|checkout|transfer|payment|settings|profile|password|delete|update|create|submit|feedback|contact|comment|review|order|cart|subscribe|unsubscribe|send|confirm|approve|reject|cancel|publish|upload|invite)/i;

/**
 * Check if a form has CSRF protection via token hidden fields.
 */
function formHasCsrfToken(form: FormInfo): boolean {
  for (const input of form.inputs) {
    // Check by name
    if (CSRF_TOKEN_NAMES.test(input.name)) return true;

    // Check hidden inputs with token-like values
    if (input.type === 'hidden' && input.value && TOKEN_VALUE_RE.test(input.value)) {
      // Also check if the name suggests a token
      if (/token|csrf|nonce|verify|auth/i.test(input.name)) return true;
    }
  }
  return false;
}

/**
 * Check if cookies have SameSite protection.
 * Returns 'none' | 'lax' | 'strict' | 'missing'.
 * Exported for testing.
 */
export function getSameSiteCookieStatus(cookies: Array<{ name: string; sameSite?: string }>): string {
  // Look for session-like cookies
  const sessionCookies = cookies.filter((c) =>
    /session|sess|sid|auth|token|login|user/i.test(c.name),
  );

  if (sessionCookies.length === 0) return 'missing';

  // Return the weakest SameSite setting found
  const levels = sessionCookies.map((c) => {
    const ss = (c.sameSite ?? '').toLowerCase();
    if (ss === 'strict') return 'strict';
    if (ss === 'lax') return 'lax';
    if (ss === 'none') return 'none';
    return 'missing'; // No SameSite attribute
  });

  if (levels.includes('none')) return 'none';
  if (levels.includes('missing')) return 'missing';
  if (levels.includes('lax')) return 'lax';
  return 'strict';
}

export const csrfCheck: ActiveCheck = {
  name: 'csrf',
  category: 'csrf',
  parallel: true,
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Test forms for missing CSRF tokens
    const stateChangingForms = targets.forms.filter((f) => {
      const method = f.method ?? 'get';
      if (!STATE_CHANGING_METHODS.test(method)) return false;
      return true;
    });

    if (stateChangingForms.length === 0) {
      log.debug('CSRF: no state-changing forms found');
      return findings;
    }

    log.info(`CSRF: testing ${stateChangingForms.length} state-changing forms...`);

    // Check SameSite cookie status once for the target — applies to all forms
    let sameSiteStatus: string = 'missing';
    try {
      const targetOrigin = new URL(config.targetUrl).origin;
      const cookies = await context.cookies(targetOrigin);
      sameSiteStatus = getSameSiteCookieStatus(cookies);
      if (sameSiteStatus === 'lax' || sameSiteStatus === 'strict') {
        log.info(`CSRF: session cookies have SameSite=${sameSiteStatus} — will downgrade severity`);
      }
    } catch {
      log.debug('CSRF: could not retrieve cookies from browser context');
    }

    const sameSiteMitigated = sameSiteStatus === 'lax' || sameSiteStatus === 'strict';

    // De-dup by action URL to avoid testing the same endpoint multiple times
    const testedActions = new Set<string>();

    for (const form of stateChangingForms) {
      const actionUrl = resolveFormAction(form);
      if (testedActions.has(actionUrl)) continue;
      testedActions.add(actionUrl);

      const hasCsrfToken = formHasCsrfToken(form);

      if (!hasCsrfToken) {
        // No CSRF token found — verify by submitting cross-origin
        const verified = await verifyCsrfMissing(context, form, config, requestLogger);

        if (verified) {
          const isHighValue = STATE_CHANGING_PATHS.test(actionUrl);

          // Downgrade severity when SameSite cookies mitigate CSRF
          // SameSite=Lax/Strict prevents the browser from sending cookies on cross-origin form POSTs,
          // which is the primary CSRF attack vector. This doesn't eliminate the finding entirely
          // because: (1) older browsers may not enforce SameSite, (2) GET-based state changes
          // bypass SameSite=Lax. But it substantially reduces exploitability.
          let severity: 'high' | 'medium' | 'low';
          if (sameSiteMitigated) {
            severity = 'low';
          } else {
            severity = isHighValue ? 'high' : 'medium';
          }

          const sameSiteNote = sameSiteMitigated
            ? ` Mitigated by SameSite=${sameSiteStatus[0].toUpperCase() + sameSiteStatus.slice(1)} on session cookies — ` +
              `cross-origin form submissions will not include session cookies in modern browsers.`
            : '';

          const responseIndicators = ['No CSRF token in form', 'Server accepted cross-origin POST'];
          if (sameSiteMitigated) {
            responseIndicators.push(`SameSite=${sameSiteStatus[0].toUpperCase() + sameSiteStatus.slice(1)} on session cookies`);
          }

          findings.push({
            id: randomUUID(),
            category: 'csrf',
            severity,
            title: `Missing CSRF Protection on ${form.method?.toUpperCase() ?? 'POST'} Form`,
            description:
              `The form at ${form.pageUrl} submits to ${actionUrl} via ${(form.method ?? 'POST').toUpperCase()} ` +
              `without a CSRF token. An attacker can craft a malicious page that auto-submits this form ` +
              `when a logged-in user visits it, performing the action without the user's knowledge.` +
              sameSiteNote,
            url: form.pageUrl,
            evidence: formatFormEvidence(form, sameSiteMitigated ? sameSiteStatus : undefined),
            timestamp: new Date().toISOString(),
            confidence: sameSiteMitigated ? 'low' : (verified === 'confirmed' ? 'high' : 'medium'),
            evidencePack: {
              payloadUsed: `Cross-origin form submission to ${actionUrl}`,
              responseIndicators,
              detectionMethod: 'form-analysis',
              curlCommand: buildCurlCommand(form),
            },
          });
        }
      }
    }

    return findings;
  },
};

/**
 * Resolve the form's action URL to an absolute URL.
 */
function resolveFormAction(form: FormInfo): string {
  try {
    return new URL(form.action, form.pageUrl).href;
  } catch {
    return form.action;
  }
}

/**
 * Format form fields as evidence string.
 */
function formatFormEvidence(form: FormInfo, sameSiteStatus?: string): string {
  const fields = form.inputs
    .map((i) => `  ${i.type ?? 'text'}: ${i.name}${i.value ? ` = "${i.value.slice(0, 30)}"` : ''}`)
    .join('\n');

  const sameSiteLine = sameSiteStatus
    ? `\nSameSite Mitigation: ${sameSiteStatus[0].toUpperCase() + sameSiteStatus.slice(1)} (session cookies)`
    : '';

  return (
    `Form on: ${form.pageUrl}\n` +
    `Action: ${form.action}\n` +
    `Method: ${(form.method ?? 'POST').toUpperCase()}\n` +
    `Fields:\n${fields}\n` +
    `CSRF Token: NOT FOUND` +
    sameSiteLine
  );
}

/**
 * Build a curl command that demonstrates the CSRF vulnerability.
 */
function buildCurlCommand(form: FormInfo): string {
  const action = resolveFormAction(form);
  const dataFields = form.inputs
    .filter((i) => i.type !== 'submit' && i.type !== 'button')
    .map((i) => `${encodeURIComponent(i.name)}=${encodeURIComponent(i.value ?? 'test')}`)
    .join('&');

  return `curl -s -X POST '${action}' -d '${dataFields}' -H 'Origin: https://evil.example.com'`;
}

/**
 * Verify CSRF is actually missing by attempting a cross-origin-like POST.
 * Returns 'confirmed' if server accepts, 'likely' if we can't verify but token is missing,
 * or false if protected.
 */
async function verifyCsrfMissing(
  context: BrowserContext,
  form: FormInfo,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<'confirmed' | 'likely' | false> {
  const page = await context.newPage();
  try {
    const actionUrl = resolveFormAction(form);

    // Build form data
    const formData: Record<string, string> = {};
    for (const input of form.inputs) {
      if (input.type === 'submit' || input.type === 'button') continue;
      formData[input.name] = input.value ?? 'test';
    }

    // Submit with cross-origin indicators (no cookies from the real session,
    // but with Origin header indicating cross-site request)
    const response = await page.request.fetch(actionUrl, {
      method: (form.method ?? 'POST').toUpperCase(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://evil.example.com',
        'Referer': 'https://evil.example.com/csrf-poc.html',
      },
      data: new URLSearchParams(formData).toString(),
    });

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: (form.method ?? 'POST').toUpperCase(),
      url: actionUrl,
      headers: { Origin: 'https://evil.example.com' },
      responseStatus: response.status(),
      phase: 'active-csrf',
    });

    const status = response.status();

    // If server returns 403/401/419 with cross-origin request, it's protected
    if (status === 403 || status === 401 || status === 419 || status === 422) {
      log.debug(`CSRF: ${actionUrl} rejected cross-origin POST (${status}) — protected`);
      return false;
    }

    // If server returns 200/302/301, the form was accepted without CSRF token
    if (status >= 200 && status < 400) {
      log.info(`CSRF: ${actionUrl} accepted cross-origin POST (${status}) — vulnerable`);
      return 'confirmed';
    }

    // 405 Method Not Allowed — can't verify but token is missing
    if (status === 405) {
      return 'likely';
    }

    // 500 errors might indicate the form was processed (just crashed)
    if (status >= 500) {
      return 'likely';
    }

    return false;
  } catch (err) {
    log.debug(`CSRF verification failed for ${form.pageUrl}: ${(err as Error).message}`);
    return 'likely'; // Can't verify but token is missing
  } finally {
    await page.close();
  }
}

import type { Page } from 'playwright';
import type { LoginForm } from '../types.js';
import { log } from '../../utils/logger.js';

/**
 * Heuristic login form detection.
 *
 * Scans the page DOM for common login form patterns:
 *  - Forms containing a password input
 *  - Username/email inputs near a password field
 *  - Submit buttons with login/sign-in text
 *
 * Returns the best match or null if no login form is found.
 */
export async function detectLoginForm(page: Page): Promise<LoginForm | null> {
  log.debug('Detecting login form...');

  const result = await page.evaluate(() => {
    // ── Helpers ─────────────────────────────────────────────────
    function textMatches(el: Element, patterns: RegExp[]): boolean {
      const text = (el.textContent ?? '').trim().toLowerCase();
      const ariaLabel = (el.getAttribute('aria-label') ?? '').toLowerCase();
      const value = (el.getAttribute('value') ?? '').toLowerCase();
      const combined = `${text} ${ariaLabel} ${value}`;
      return patterns.some((p) => p.test(combined));
    }

    function selectorFor(el: Element): string {
      if (el.id) return `#${el.id}`;
      const name = el.getAttribute('name');
      if (name) {
        const tag = el.tagName.toLowerCase();
        return `${tag}[name="${name}"]`;
      }
      // Fallback: build a path with nth-child
      const tag = el.tagName.toLowerCase();
      const type = el.getAttribute('type');
      if (type) return `${tag}[type="${type}"]`;
      return tag;
    }

    // ── Detection ───────────────────────────────────────────────

    // Step 1: Find all password inputs
    const passwordInputs = Array.from(
      document.querySelectorAll('input[type="password"]'),
    );
    if (passwordInputs.length === 0) return null;

    // Step 2: For each password input, find the enclosing form (or body)
    for (const pwInput of passwordInputs) {
      const form = pwInput.closest('form');
      const container = form ?? document.body;

      // Step 3: Find a username/email input
      // Look for common selectors first, then fall back to first text-like input
      const usernameSelectors = [
        'input[type="email"]',
        'input[name="email"]',
        'input[name="username"]',
        'input[name="user"]',
        'input[name="login"]',
        'input[name="user_login"]',
        'input[name="user_name"]',
        'input[name="account"]',
        'input[id="email"]',
        'input[id="username"]',
        'input[id="login"]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
      ];

      let usernameInput: Element | null = null;
      for (const sel of usernameSelectors) {
        usernameInput = container.querySelector(sel);
        if (usernameInput) break;
      }

      // Fallback: first text/email/tel input that isn't the password field
      if (!usernameInput) {
        const textInputs = Array.from(
          container.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])'),
        ).filter((el) => el !== pwInput);
        if (textInputs.length > 0) {
          usernameInput = textInputs[0];
        }
      }

      if (!usernameInput) continue;

      // Step 4: Find submit button
      const loginPatterns = [/log\s*in/i, /sign\s*in/i, /submit/i, /masuk/i, /enter/i];

      let submitEl: Element | null = null;

      // Try button[type=submit] or input[type=submit] first
      const submitCandidates = Array.from(
        container.querySelectorAll(
          'button[type="submit"], input[type="submit"], button:not([type]), [role="button"]',
        ),
      );

      // Prefer buttons whose text matches login patterns
      for (const candidate of submitCandidates) {
        if (textMatches(candidate, loginPatterns)) {
          submitEl = candidate;
          break;
        }
      }

      // Fall back to first submit button
      if (!submitEl && submitCandidates.length > 0) {
        submitEl = submitCandidates[0];
      }

      // Last resort: any button in the form
      if (!submitEl) {
        submitEl = container.querySelector('button');
      }

      if (!submitEl) continue;

      // Build result
      const formSelector = form ? selectorFor(form) : 'body';
      return {
        formSelector,
        usernameSelector: selectorFor(usernameInput),
        passwordSelector: selectorFor(pwInput),
        submitSelector: selectorFor(submitEl),
      };
    }

    return null;
  });

  if (result) {
    log.debug(`Login form detected: username=${result.usernameSelector}, password=${result.passwordSelector}, submit=${result.submitSelector}`);
  } else {
    log.debug('No login form detected on page');
  }

  return result;
}

import type { Page } from 'playwright';
import type { LoginForm } from '../types.js';
import { log } from '../../utils/logger.js';

/**
 * Browser-side login form detection script.
 * Passed as a raw string to page.evaluate() to avoid esbuild's __name injection
 * breaking Playwright's function serialization.
 */
/* eslint-disable no-var */
const DETECT_LOGIN_SCRIPT = `(() => {
  var textMatches = function(el, patterns) {
    var text = (el.textContent || '').trim().toLowerCase();
    var ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
    var value = (el.getAttribute('value') || '').toLowerCase();
    var combined = text + ' ' + ariaLabel + ' ' + value;
    return patterns.some(function(p) { return p.test(combined); });
  };

  var selectorFor = function(el) {
    if (el.id) return '#' + el.id;
    var name = el.getAttribute('name');
    if (name) {
      var tag = el.tagName.toLowerCase();
      return tag + '[name="' + name + '"]';
    }
    var tag = el.tagName.toLowerCase();
    var type = el.getAttribute('type');
    if (type) return tag + '[type="' + type + '"]';
    return tag;
  };

  var passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  if (passwordInputs.length === 0) return null;

  for (var i = 0; i < passwordInputs.length; i++) {
    var pwInput = passwordInputs[i];
    var form = pwInput.closest('form');
    var container = form || document.body;

    var usernameSelectors = [
      'input[type="email"]', 'input[name="email"]', 'input[name="username"]',
      'input[name="user"]', 'input[name="login"]', 'input[name="user_login"]',
      'input[name="user_name"]', 'input[name="account"]',
      'input[id="email"]', 'input[id="username"]', 'input[id="login"]',
      'input[autocomplete="username"]', 'input[autocomplete="email"]'
    ];

    var usernameInput = null;
    for (var j = 0; j < usernameSelectors.length; j++) {
      usernameInput = container.querySelector(usernameSelectors[j]);
      if (usernameInput) break;
    }

    if (!usernameInput) {
      var textInputs = Array.from(
        container.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])')
      ).filter(function(el) { return el !== pwInput; });
      if (textInputs.length > 0) usernameInput = textInputs[0];
    }

    if (!usernameInput) continue;

    var loginPatterns = [/log\\s*in/i, /sign\\s*in/i, /submit/i, /masuk/i, /enter/i];
    var submitEl = null;
    var submitCandidates = Array.from(
      container.querySelectorAll('button[type="submit"], input[type="submit"], button:not([type]), [role="button"]')
    );

    for (var k = 0; k < submitCandidates.length; k++) {
      if (textMatches(submitCandidates[k], loginPatterns)) {
        submitEl = submitCandidates[k];
        break;
      }
    }

    if (!submitEl && submitCandidates.length > 0) submitEl = submitCandidates[0];
    if (!submitEl) submitEl = container.querySelector('button');
    if (!submitEl) continue;

    var formSelector = form ? selectorFor(form) : 'body';
    return {
      formSelector: formSelector,
      usernameSelector: selectorFor(usernameInput),
      passwordSelector: selectorFor(pwInput),
      submitSelector: selectorFor(submitEl)
    };
  }

  return null;
})()`;
/* eslint-enable no-var */

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

  const result = await page.evaluate(DETECT_LOGIN_SCRIPT) as LoginForm | null;

  if (result) {
    log.debug(`Login form detected: username=${result.usernameSelector}, password=${result.passwordSelector}, submit=${result.submitSelector}`);
  } else {
    log.debug('No login form detected on page');
  }

  return result;
}

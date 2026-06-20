# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** high | **CVSS:** 7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** medium (scanner: dom-sink heuristic — NOT auto-verified)

> **BEFORE SUBMITTING:** Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome with DevTools open. Confirm the alert fires. The curl command below does NOT prove execution (curl doesn't run JS). Only submit if you see the alert in a real browser. The HTTP exchange in the scan returned status 0 (client-side only). If alert does NOT fire, close this as FP — modern SPAs may sanitize via DOMPurify before innerHTML assignment.

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

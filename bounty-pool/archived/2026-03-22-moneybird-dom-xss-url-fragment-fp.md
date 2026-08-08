# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** medium | **CVSS:** 6.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** medium (scanner) / **FALSE POSITIVE** (confirmed)

> **Archived 2026-08-08:** Confirmed FP — recorded as `not-applicable` twice in `learning-data/outcomes.json` (2026-03-22 and 2026-03-26). Root cause: browser URL-encodes the fragment before it reaches any innerHTML sink, so the payload is rendered as inert text, not executed as HTML. The SecBot dom-sink detector saw its marker string in the DOM but the payload was already encoded and harmless.

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

## Reproduction

**Browser only** (URL fragments are not sent to the server — curl will not reproduce this):

1. Open this URL directly in a browser:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>
   ```
2. Confirm the alert dialog fires, indicating the fragment payload reached an `innerHTML` sink.

**SecBot detection evidence** (Playwright, 2026-03-22T12:45:31):
```
Finding ID: 6d09cce8-8bd9-464a-9dd5-835b5255b015
Payload: #<img src=x onerror=alert("secbot-xss-37")>
Sinks:    innerHTML-set (×2)
Method:   dom-sink (Playwright DOM inspection)
```

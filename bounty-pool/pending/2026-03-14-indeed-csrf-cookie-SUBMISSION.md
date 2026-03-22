# HackerOne Submission Draft — Indeed

**Program:** Indeed Bug Bounty Program
**Asset:** id.indeed.com
**Weakness:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
**Severity:** Medium (CVSS 5.4)

---

## Title

CSRF Token Cookie Missing Secure Flag on Login Page (id.indeed.com) — Configuration Inconsistency

## Summary

The `CSRF` cookie on `id.indeed.com` (the authentication/login domain) is set without the `Secure` flag, allowing it to be transmitted over unencrypted HTTP connections. This is a configuration oversight evidenced by the fact that the companion `INDEED_CSRF_TOKEN` cookie IS set with the `Secure` flag — the same CSRF protection mechanism has inconsistent security attributes.

## Steps to Reproduce

1. Open a terminal and run:
```bash
curl -sI 'https://id.indeed.com/?r=us' | grep -i set-cookie
```

2. Observe the response contains two CSRF-related cookies:
```
Set-Cookie: CSRF=<token>;Domain=.indeed.com;Path=/
Set-Cookie: INDEED_CSRF_TOKEN=<token>;Domain=.indeed.com;Path=/;Secure
```

3. Note the inconsistency:
   - `CSRF` cookie: **NO Secure flag**
   - `INDEED_CSRF_TOKEN` cookie: **HAS Secure flag**

4. The `CSRF` cookie is set on the login page (`id.indeed.com`), which handles user authentication.

## Impact

**MitM Cookie Theft on Authentication Flow:**

An attacker on a shared network (public Wi-Fi, corporate proxy) can intercept the `CSRF` cookie when a victim's browser makes any HTTP request to `*.indeed.com` (e.g., following an HTTP link, image load, or redirect). With the CSRF token:

1. The attacker can forge cross-site requests that pass CSRF validation
2. This affects the login/authentication domain, elevating the impact beyond a typical marketing page
3. Combined with the CSP policy on `id.indeed.com` using `'unsafe-inline'` in `default-src`, the authentication page has reduced defense-in-depth

**Attack scenario:**
- Victim connects to public Wi-Fi
- Victim visits any `http://` page that loads a resource from `*.indeed.com` (or attacker injects such a request via DNS spoofing)
- Browser sends `CSRF` cookie over HTTP (no Secure flag)
- Attacker captures the CSRF token
- Attacker crafts a forged request using the stolen CSRF token

## Supporting Materials

**Cookie comparison (from curl output):**
```
CSRF=y89sWHQ6GGgqZb3exhHwbl5z2QGz9YjX;Domain=.indeed.com;Path=/
                                                                  ← Missing Secure

INDEED_CSRF_TOKEN=<value>;Domain=.indeed.com;Path=/;Secure
                                                    ^^^^^^ ← Has Secure
```

**CSP header on login page:**
```
content-security-policy: default-src 'self' https: data: 'unsafe-inline'; ...
```
Note: `'unsafe-inline'` in `default-src` on the login page reduces XSS protection.

**Full response headers available in attached scan report.**

## Suggested Fix

Add the `Secure` flag to the `CSRF` cookie to match the `INDEED_CSRF_TOKEN` cookie:

```
# Before
Set-Cookie: CSRF=<token>;Domain=.indeed.com;Path=/

# After
Set-Cookie: CSRF=<token>;Domain=.indeed.com;Path=/;Secure;SameSite=Lax
```

This is likely a one-line configuration change in the cookie-setting code for the `CSRF` cookie.

---

*Discovered by SecBot automated security scanner on 2026-03-14. Verified manually via curl.*

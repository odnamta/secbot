# WordPress Admin Login Accessible Without Rate Limiting — Brute Force Risk

**Severity:** medium | **CVSS:** 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**Platform:** RedStorm | **Program:** Kredivo
**Confidence:** high
**Scan date:** 2026-03-22

## Description

The WordPress administrative login page (`/wp-login.php`) on `blog.kredivo.com` is publicly accessible and accepts unlimited authentication attempts without any rate limiting, CAPTCHA, or lockout mechanism. An attacker can automate credential guessing attacks to brute-force the WordPress admin password.

## Steps to Reproduce

**Step 1 — Confirm login page is accessible:**
```bash
curl -sI 'https://blog.kredivo.com/wp-login.php'
# Expected: HTTP/1.1 200 OK, Content-Length: 9360 (WordPress login form)
```

**Step 2 — Confirm no rate limiting on repeated login attempts:**
```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Cookie: wordpress_test_cookie=WP+Cookie+check'
done
# Expected: 15 responses all return 302 (login redirect) with no 429 and no lockout
```

**Step 3 — Verify absence of rate limit headers:**
```bash
curl -sI -X POST 'https://blog.kredivo.com/wp-login.php' \
  -d 'log=admin&pwd=test&wp-submit=Log+In&testcookie=1' \
  -H 'Cookie: wordpress_test_cookie=WP+Cookie+check'
# Observe: No X-RateLimit-*, Retry-After, or X-Rate-Limit headers in response
```

## Evidence

- `GET https://blog.kredivo.com/wp-login.php` → HTTP 200, body 9360 bytes (WordPress login form fully rendered)
- SecBot sent 15 rapid POST requests to `/wp-login.php` — all returned HTTP 302 (authentication redirect) with no rate-limit headers and no lockout
- No `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`, or `X-Rate-Limit` headers observed
- No CAPTCHA or login attempt counter visible in response

## Impact

An attacker can run an automated brute-force attack against the WordPress admin account. Common WordPress passwords and credential dumps (e.g., from previous breaches) can be tried at high speed. Successful compromise of the WordPress admin account would grant:
- Full control of the Kredivo blog (content defacement, malware injection)
- Potential for supply chain attack via malicious blog posts targeting Kredivo users/customers
- Server-level access depending on hosting configuration (file manager, PHP execution via theme editor)
- Possible lateral movement if admin credentials are reused on other Kredivo systems

## Suggested Fix

1. **Rate limiting:** Implement IP-based rate limiting (max 5 attempts per 5 minutes per IP)
2. **Lockout:** Enable account lockout after 5 failed attempts (WP plugin: Limit Login Attempts Reloaded, or native WP 5.2+ lockout feature)
3. **CAPTCHA:** Add CAPTCHA to the login form (e.g., reCAPTCHA v3 via plugin)
4. **IP allowlist:** Restrict `/wp-login.php` access to known admin IP addresses via `.htaccess` or nginx
5. **Two-factor authentication:** Enforce 2FA on all admin accounts
6. **XML-RPC:** Disable `/xmlrpc.php` if not needed (alternate bruteforce vector)

## References

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP Top 10: A07:2021 — Identification and Authentication Failures
- WordPress Hardening: https://wordpress.org/documentation/article/hardening-wordpress/

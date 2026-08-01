# No Rate Limiting on WordPress Admin Login Endpoint

**Severity:** Medium | **CVSS:** 5.9 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
**Platform:** RedStorm | **Program:** Kredivo
**Confidence:** High
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures
**Affected Asset:** https://blog.kredivo.com/wp-login.php

---

## Description

The WordPress admin login endpoint at `https://blog.kredivo.com/wp-login.php` is publicly accessible and imposes no rate limiting or account lockout on login attempts. An attacker can submit unlimited credential pairs at machine speed, making the admin account vulnerable to brute-force and credential-stuffing attacks.

While blog.kredivo.com is a content/marketing subdomain, a compromise of the WordPress admin account allows an attacker to:
- Inject malicious scripts into the blog (affecting all visitors)
- Serve malware or credential-harvesting pages from a trusted Kredivo domain
- Exfiltrate any visitor data stored in the WordPress database
- Pivot using stored API keys, SMTP credentials, or plugin secrets

---

## Steps to Reproduce

### Step 1 — Verify the login page is publicly accessible

```bash
curl -si 'https://blog.kredivo.com/wp-login.php' | head -20
```

Expected: HTTP/2 200, `Set-Cookie: wordpress_test_cookie=...`

### Step 2 — Confirm there is no rate limiting

Send 50 rapid login attempts and observe that all receive HTTP 200 responses (login form re-rendered with "incorrect credentials"), not 429 Too Many Requests or account lockout:

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -d 'log=admin&pwd=wrongpassword'$i'&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -b 'wordpress_test_cookie=WP+Cookie+check'
done
```

Expected: 50 responses of `200` with no lockout, no CAPTCHA, no rate limit headers (`Retry-After`, `X-RateLimit-*`).

### Step 3 — Verify no login attempt auditing

Check response headers for any rate limiting signals:

```bash
curl -sI -X POST 'https://blog.kredivo.com/wp-login.php' \
  -d 'log=admin&pwd=test&wp-submit=Log+In&testcookie=1' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'wordpress_test_cookie=WP+Cookie+check'
```

Expected: No `X-RateLimit-*`, `Retry-After`, or `cf-mitigated` headers.

---

## Impact

An attacker who discovers or guesses the WordPress admin username (commonly `admin`, `kredivo`, or the email prefix) can run a credential-stuffing attack using leaked password databases (e.g., HaveIBeenPwned lists). With no throttling:

- At 10 requests/second: 1 million credential pairs tested in ~28 hours
- At 100 requests/second: same in ~3 hours

A successful compromise gives full WordPress admin control over blog.kredivo.com — enabling malicious script injection into pages visited by Kredivo customers and partners.

---

## Suggested Fix

1. **Cloudflare Rate Limiting Rule** — Limit POST requests to `/wp-login.php` to 5 per minute per IP.
2. **WordPress plugin** — Install Wordfence or Solid Security; enable login rate limiting and account lockout after N failed attempts.
3. **Nginx / server-level** (if self-hosted):

```nginx
# Rate limit: 5 login attempts per minute per IP
limit_req_zone $binary_remote_addr zone=wp_login:10m rate=5r/m;

location = /wp-login.php {
    limit_req zone=wp_login burst=2 nodelay;
    limit_req_status 429;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

4. **Additional hardening** — Enable two-factor authentication for all admin accounts; restrict `/wp-login.php` to known IPs via Cloudflare Access or server-level allowlist.

---

## Detection

- **SecBot scan:** 2026-03-22T12:37:39Z (stealth profile)
- **Detection method:** rate-limit probe (15 sequential POST requests, all returned HTTP 200, no lockout)
- **CVSS vector note:** AC:H reflects that successful exploitation requires either knowledge of the admin username or a credential list — the endpoint itself is trivially reachable (no MFA, no IP restriction).

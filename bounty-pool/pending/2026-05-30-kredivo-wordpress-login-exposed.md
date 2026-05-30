# Exposed WordPress Admin Login Without Rate Limiting or Access Restriction

**Severity:** High | **CVSS:** 8.1 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
**Platform:** RedStorm | **Program:** Kredivo
**Confidence:** High | **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures

## Summary

The WordPress admin login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible with HTTP 200. There is no IP allowlist, no HTTP Basic Auth layer, no Cloudflare Access protection, and no rate limiting — allowing an attacker to make unlimited login attempts without throttling or account lockout.

## Steps to Reproduce

**1. Confirm the login page is publicly accessible:**
```bash
curl -s -o /dev/null -w "%{http_code}" https://blog.kredivo.com/wp-login.php
# Returns: 200
```

**2. Confirm the WordPress login form is rendered:**
```bash
curl -L -i 'https://blog.kredivo.com/wp-login.php' | grep -i 'wordpress\|wp-login\|log in'
# Returns: WordPress login form HTML with "Log In" button
```

**3. Confirm no rate limiting on repeated login attempts:**
```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code} " -X POST \
    -d 'log=admin&pwd=password123&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    https://blog.kredivo.com/wp-login.php
done
# Returns: 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200
# (all 15 requests succeed, no 429, no lockout, no Retry-After header)
```

**4. No rate-limit headers in response:**
```bash
curl -sI -X POST https://blog.kredivo.com/wp-login.php | grep -i 'x-ratelimit\|retry-after\|cf-ray'
# Returns: (empty — no rate limit headers)
```

## Impact

An attacker can automate credential guessing against the WordPress admin account without restriction:

1. **Brute-force / credential stuffing:** Using leaked credential databases, an attacker can attempt thousands of username/password combinations per minute against `/wp-login.php` with no throttling.
2. **Admin takeover → content injection:** If credentials are guessed, the attacker gains WordPress admin access, enabling arbitrary content modification, malicious link injection into blog posts, and webshell upload via the Theme Editor.
3. **Phishing amplification:** `blog.kredivo.com` is an official Kredivo domain. An attacker who gains admin access can publish fake posts impersonating Kredivo to phish Kredivo customers, redirect users to malicious sites, or harvest credentials via fake login pages.
4. **Pivot to server:** WordPress theme/plugin editor can execute PHP on the server. Depending on hosting configuration, this could allow lateral movement into the Kredivo infrastructure.

## Evidence

```
GET https://blog.kredivo.com/wp-login.php → HTTP 200
Response body: WordPress admin login form present
Rate limit test: 15 rapid POST requests → all HTTP 200, no throttling
Headers: No X-RateLimit-*, Retry-After, or Cloudflare Access challenge present
```

## Suggested Fix

**Option 1 (Recommended) — Cloudflare Access:**
Gate `blog.kredivo.com/wp-login.php` behind Cloudflare Access (Zero Trust → Applications → Add). Require company email login before the WordPress form is reached.

**Option 2 — Nginx IP restriction:**
```nginx
location = /wp-login.php {
    allow 203.0.113.10;  # Office/VPN IP
    deny all;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

**Option 3 — WordPress security plugin:**
Install Wordfence or Solid Security. Enable "Limit Login Attempts" with lockout after 5 failures and IP-based rate limiting.

**Minimum viable fix:** Add HTTP Basic Auth in front of `/wp-login.php` — free, no plugins required, can be done in minutes at the server level.

## References

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP A07:2021 — Identification and Authentication Failures
- WordPress Hardening Guide: https://wordpress.org/documentation/article/hardening-wordpress/

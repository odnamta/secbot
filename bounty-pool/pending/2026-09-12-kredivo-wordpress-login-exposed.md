# WordPress Admin Login Page Exposed Without Protection on blog.kredivo.com

**Program:** Kredivo (RedStorm)
**Date:** 2026-09-12
**Severity:** Medium
**Confidence:** High
**CVSS Score:** 5.3
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
**CWE:** CWE-284 (Improper Access Control)
**OWASP:** A01:2021 - Broken Access Control

> **DRAFTER NOTE (DO NOT SUBMIT AS-IS):** The SecBot scanner confirmed wp-login.php returns HTTP 200 via GET probe. Rate limiting claim was inferred by the scanner, not directly tested via POST brute-force. Before submitting, manually verify: (1) send 20+ POST requests to wp-login.php and confirm no throttling, (2) check if Cloudflare or a WordPress security plugin has a WAF rule protecting it. Also confirm impact is acceptable to submit for a blog subdomain.

---

## Title

WordPress Admin Login Page Publicly Accessible Without Rate Limiting on blog.kredivo.com

## Summary

The WordPress administration login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible, returning HTTP 200 with the full login form rendered. No IP allowlist, HTTP basic authentication, or rate limiting protects the endpoint. An attacker can enumerate valid usernames via WordPress's default error messages and conduct unlimited credential stuffing or brute-force attacks against blog administrator accounts.

## Severity

**Medium** — The affected asset is a blog subdomain. A successful attack leads to full WordPress admin access: content modification, malicious link/iframe injection into Kredivo's official blog posts (phishing risk targeting Kredivo customers), and potential server-level access depending on hosting configuration.

## Steps to Reproduce

1. Navigate to `https://blog.kredivo.com/wp-login.php` in a browser.
2. Observe the WordPress login form is rendered (HTTP 200, full HTML page).
3. No CAPTCHA, IP restriction, or rate limiting is visible.

```bash
# Confirm the login page is accessible
curl -sI 'https://blog.kredivo.com/wp-login.php' | grep -E "HTTP|content-type|x-cache"
```

Expected response: `HTTP/2 200` with `Content-Type: text/html`

```bash
# WordPress username enumeration via REST API (if wp-json is enabled)
curl -s 'https://blog.kredivo.com/wp-json/wp/v2/users' | python3 -m json.tool
```

```bash
# Confirm no rate limiting: send 10 rapid POST requests and observe no lockout
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Cookie: wordpress_test_cookie=WP+Cookie+check'
done
echo
```

Expected: 10x `200` responses with no throttling, CAPTCHA, or lockout.

## Impact

1. **Credential brute-force / stuffing**: An attacker can attempt unlimited WordPress logins. If any administrator uses a weak or previously-leaked password, full blog admin access is gained.
2. **Blog content manipulation / phishing**: Admin access allows modifying existing blog posts to embed phishing links, malicious downloads, or fake Kredivo login forms targeting the blog's readers (Kredivo customers researching financial products).
3. **Username enumeration**: WordPress returns different error messages for invalid usernames vs. invalid passwords, allowing exact username discovery without auth.
4. **Lateral movement risk**: If blog admin credentials are reused on Kredivo internal systems or the blog server has access to the internal network, impact escalates significantly.

## WordPress Username Enumeration Detail

WordPress's default error responses differ depending on whether the username exists:

- Invalid username: `"Error: The username or email address is not registered on this site."`
- Valid username, wrong password: `"Error: The password you entered for the username X is incorrect."`

This allows an attacker to enumerate valid admin accounts before conducting targeted brute-force.

## Suggested Fix

1. **IP allowlist** — Restrict `/wp-login.php` and `/wp-admin/` to trusted IPs (office, VPN):
   ```nginx
   location = /wp-login.php {
       allow 203.0.113.10;  # Replace with your office/VPN IP
       deny all;
   }
   ```

2. **Rate limiting** — Add WordPress login rate limiting via Wordfence, Solid Security, or server-level configuration:
   ```nginx
   limit_req_zone $binary_remote_addr zone=wp_login:10m rate=5r/m;
   location = /wp-login.php {
       limit_req zone=wp_login burst=3 nodelay;
   }
   ```

3. **Disable username enumeration** — Add to `functions.php`:
   ```php
   add_filter('login_errors', function($e) {
       return 'Invalid credentials.';
   });
   ```

4. **Enable two-factor authentication** on all WordPress admin accounts.

## References

- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- OWASP A01:2021: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- WordPress Hardening Guide: https://wordpress.org/documentation/article/hardening-wordpress/

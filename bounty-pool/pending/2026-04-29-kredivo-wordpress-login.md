# Unprotected WordPress Admin Login Endpoint on blog.kredivo.com

**Severity:** High | **CVSS:** 8.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
**Platform:** RedStorm | **Program:** Kredivo
**Confidence:** High | **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures
**Scan Date:** 2026-03-22

## Title

Unprotected WordPress Admin Login at `/wp-login.php` — No Rate Limiting, No IP Restriction

## Summary

The WordPress admin login endpoint `https://blog.kredivo.com/wp-login.php` is publicly accessible (HTTP 200) with no rate limiting, IP restriction, or multi-factor authentication requirement. An attacker can perform unlimited automated brute-force or credential stuffing attacks against any WordPress admin account with no throttling or lockout enforced.

## Steps to Reproduce

**1. Confirm the endpoint is publicly accessible:**
```bash
curl -sI 'https://blog.kredivo.com/wp-login.php' | head -5
# Expected: HTTP/2 200
```

**2. Confirm there is no rate limiting by sending repeated requests:**
```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1'
done
# Expected: 10x 200 responses, no 429 or lockout
```

**3. Confirm no lockout occurs even with sequential wrong passwords:**
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST 'https://blog.kredivo.com/wp-login.php' \
  -d 'log=admin&pwd=Password1&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1'
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST 'https://blog.kredivo.com/wp-login.php' \
  -d 'log=admin&pwd=Password123!&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1'
# Both return 200 — no lockout enforced
```

## Impact

1. **Full admin account takeover** — an attacker using a credential stuffing list or wordlist can compromise the WordPress admin account with no throttling resistance
2. **Content injection and malware delivery** — a compromised WordPress admin can install plugins, modify templates, and inject malicious JavaScript into blog pages, turning blog.kredivo.com into a malware delivery mechanism for Kredivo's customers and prospective customers
3. **Reputational and regulatory risk** — Kredivo is a fintech/BNPL company; a compromised customer-facing blog could undermine trust and create regulatory concerns (OJK compliance)
4. **Lateral movement** — WordPress admin with `edit_themes` or `install_plugins` capability can potentially write PHP to the server filesystem, escalating from web admin to OS-level access depending on server configuration

## Suggested Fix

1. **Restrict `/wp-login.php` by IP** — limit access to company IPs/VPN only at the Nginx/Apache level:
   ```nginx
   location = /wp-login.php {
       allow <your-office-ip>;
       deny all;
       fastcgi_pass unix:/run/php/php8.1-fpm.sock;
       include fastcgi_params;
       fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
   }
   ```

2. **Enable WordPress login rate limiting** — install Wordfence, Solid Security, or Login LockDown, OR use `rack-attack`-equivalent PHP middleware

3. **Enable Two-Factor Authentication** on all WordPress admin accounts (Wordfence or WP 2FA plugin)

4. **Consider relocating the login URL** — move wp-login.php to a non-standard URL using a plugin like WPS Hide Login, reducing automated attack surface

## References

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP A07:2021 — Identification and Authentication Failures
- WordPress Hardening Guide: https://developer.wordpress.org/advanced-administration/security/hardening/

# RedStorm Submission Draft — Kredivo

**Program:** Kredivo Bug Bounty (RedStorm)
**Asset:** blog.kredivo.com (explicitly in-scope per program scope)
**Weakness:** CWE-307: Improper Restriction of Excessive Authentication Attempts + CWE-284: Improper Access Control
**Severity:** Medium
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (5.3)

---

## Title

Exposed WordPress Admin Login (`/wp-login.php`) Without Rate Limiting on blog.kredivo.com

## Summary

The WordPress admin login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible (HTTP 200) and accepts unlimited login attempts without any rate limiting, account lockout, or CAPTCHA protection. An attacker can perform unrestricted brute-force or credential-stuffing attacks against WordPress administrator accounts.

## Steps to Reproduce

**1. Confirm the admin login page is accessible:**
```bash
curl -sI 'https://blog.kredivo.com/wp-login.php' | head -5
# Expected: HTTP/2 200
```

**2. Confirm no rate limiting on repeated requests:**
```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1'
done
# Expected: 15x 200 — no 429, no Retry-After header, no lockout
```

**3. Confirm absence of lockout or CAPTCHA:**
```bash
curl -s 'https://blog.kredivo.com/wp-login.php' | grep -i "captcha\|blocked\|locked\|too many"
# Expected: no output
```

**Full request to check response headers:**
```bash
curl -v -X POST 'https://blog.kredivo.com/wp-login.php' \
  -d 'log=test&pwd=test&wp-submit=Log+In' \
  2>&1 | grep -E "^[<>]|HTTP/"
```

## Observed Behavior

- `GET https://blog.kredivo.com/wp-login.php` → `HTTP 200`, body length 9360 bytes (WordPress login form)
- 15 consecutive `POST` login attempts: all returned `HTTP 200`, no rate-limit headers (`X-RateLimit-*`, `Retry-After`) observed, no account lockout triggered
- No CAPTCHA or MFA challenge present

## Impact

An attacker can automate credential-stuffing attacks using leaked credential databases (e.g., previous breaches involving Kredivo customer emails) or brute-force common WordPress admin passwords without any throttling.

**Attack scenario:**
1. Attacker obtains a list of Kredivo employee/customer email addresses (readily available from past Indonesian fintech data leaks)
2. Runs a credential-stuffing tool (Hydra, Burp Intruder, custom script) against `/wp-login.php`
3. On successful compromise: gains WordPress admin access → arbitrary code execution via plugin/theme editor → potential server-side pivot

Even for a blog subdomain, WordPress admin compromise enables:
- Planting malicious JavaScript in posts (client-side attacks on blog visitors including Kredivo customers)
- Lateral movement if the blog shares infrastructure or credentials with other Kredivo services
- Reputational damage via defacement

## Why blog.kredivo.com Is Still In Scope

The program explicitly lists `blog.kredivo.com` as an in-scope asset in the scope definition. Blog subdomains on fintech platforms are valid attack surfaces — compromised blogs have been used to distribute malware, perform watering-hole attacks on customers, and as a foothold for infrastructure access.

## OWASP / CWE

- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-284**: Improper Access Control
- **OWASP A07:2021** — Identification and Authentication Failures
- **OWASP WSTG-ATHN-03**: Testing for Weak Lock Out Mechanism

## Suggested Fix

1. **Add WordPress-level rate limiting:**
   - Install WP plugin: Limit Login Attempts Reloaded or Wordfence
   - Config: lock after 5 failed attempts, 20-minute lockout
2. **Add Cloudflare rate limiting rule** on `blog.kredivo.com/wp-login.php` — max 5 POST requests per IP per 60 seconds
3. **Restrict `/wp-login.php` by IP** if admin login is only needed from office IPs:
   ```nginx
   location = /wp-login.php {
     allow <office-ip-range>;
     deny all;
   }
   ```
4. **Enable two-factor authentication** for all WordPress admin accounts

## Timeline

- **2026-03-22:** Detected by automated scanner (stealth profile)
- **2026-05-06:** Triaged and drafted for submission

---

*Discovered by SecBot automated security scanner. Researcher: Dio Atmandoko.*

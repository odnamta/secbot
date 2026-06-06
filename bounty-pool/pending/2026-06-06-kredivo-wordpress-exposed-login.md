# Exposed WordPress Login Page Without Rate Limiting or Access Control

**Target:** https://blog.kredivo.com  
**Platform:** RedStorm (redstorm.io)  
**Program:** Kredivo  
**Severity:** High | **CVSS:** 8.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**OWASP:** A07:2021 – Identification and Authentication Failures  
**Confidence:** High | **Detection:** endpoint-replay  
**Scan date:** 2026-03-22

---

## Summary

The WordPress admin login endpoint (`/wp-login.php`) on `blog.kredivo.com` is publicly accessible without IP allowlisting, rate limiting, or any brute-force protection. An attacker can submit unlimited login attempts at machine speed against any WordPress username.

---

## Steps to Reproduce

**Verify the endpoint is exposed and unprotected:**

```bash
# 1. Confirm the login page is accessible (expect HTTP 200 with WordPress form)
curl -s -o /dev/null -w "%{http_code}" https://blog.kredivo.com/wp-login.php
# Expected: 200

# 2. Confirm no rate limiting — send 15 rapid requests, observe no 429 or lockout
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST https://blog.kredivo.com/wp-login.php \
    -d "log=admin&pwd=wrongpassword$i&wp-submit=Log+In&testcookie=1" \
    -H "Cookie: wordpress_test_cookie=WP+Cookie+check"
done
# Expected: 200 200 200 200 200 ... (no throttling)

# 3. Check for no rate-limit headers in response
curl -sI -X POST https://blog.kredivo.com/wp-login.php \
  -d "log=admin&pwd=wrongpassword&wp-submit=Log+In" | grep -i "retry\|ratelimit\|x-rate"
# Expected: empty (no rate-limit headers present)
```

**What happens:**  
All 15 requests return `HTTP 200` with the WordPress login form or an "incorrect password" message. No `429 Too Many Requests`, no `Retry-After` header, no account lockout, no CAPTCHA.

---

## Impact

1. **Credential brute-force:** An attacker can iterate over a wordlist (e.g., rockyou.txt) at thousands of attempts per minute against the `admin` account or any enumerated WordPress username. No throttling mechanism blocks this.

2. **Blog compromise → brand damage:** Full WordPress admin access allows injecting malicious content, SEO spam, malware scripts, or defacement into Kredivo's official blog — directly affecting brand trust for a public-facing fintech.

3. **Credential reuse:** If the WordPress admin password matches any internal Kredivo credential, the blast radius extends beyond the blog.

**Worst-case scenario:** An attacker gains WordPress admin access, injects a malicious JS payload harvesting visitor credentials, and the blog's domain (blog.kredivo.com) acts as a trusted phishing vector for Kredivo users.

---

## Evidence

```
GET https://blog.kredivo.com/wp-login.php → HTTP 200 OK
Content-Type: text/html; charset=UTF-8

<form name="loginform" id="loginform" action="https://blog.kredivo.com/wp-login.php" method="post">
  <p>
    <label for="user_login">Username or Email Address</label>
    <input type="text" name="log" id="user_login" ...>
  </p>
  ...
</form>
```

15 successive POST requests to `/wp-login.php` with incorrect credentials — all returned `HTTP 200` with no throttling indication.

---

## Suggested Fix

**Option 1 (recommended): IP allowlist + secondary auth**
```nginx
# nginx — restrict wp-login.php to office/VPN IPs
location = /wp-login.php {
    allow 203.0.113.0/24;  # Replace with Kredivo office/VPN CIDR
    deny all;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

**Option 2: WordPress plugin**  
Install Wordfence or Solid Security (iThemes Security) and enable:
- Login attempt limiting (e.g., 5 attempts per 15 minutes per IP)
- Two-factor authentication for admin accounts
- Rename `/wp-login.php` to a custom path

**Option 3: Cloudflare WAF rule** (if behind Cloudflare)
```
(http.request.uri.path eq "/wp-login.php" and not ip.src in {203.0.113.0/24})
→ Block
```

---

## Notes for Verifier (Dio)

- Verify current WordPress version and check for known CVEs: `curl -s https://blog.kredivo.com/ | grep -i 'generator.*WordPress'`
- Check if there is a `wp-cron.php` or `xmlrpc.php` also exposed (common companion issues)
- blog.kredivo.com is explicitly in-scope per Kredivo RedStorm scope file
- Bounty tier: HIGH → ~Rp 1,500,000 (~$95)
- This is a well-evidenced, reproducible finding — no browser required, curl-only

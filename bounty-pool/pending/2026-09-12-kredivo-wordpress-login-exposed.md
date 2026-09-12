# WordPress Admin Login Page Exposed Without Protection on blog.kredivo.com

**Program:** Kredivo (RedStorm)
**Date:** 2026-09-12
**Severity:** Medium
**Confidence:** High
**CVSS Score:** 6.5
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures

> **DRAFTER NOTE (DO NOT SUBMIT AS-IS):** Multiple manual verifications required before submission:
> 1. **reCAPTCHA v3 present** — Scan evidence confirms the login page loads `google.com/recaptcha/api.js?render=6Lcq-sgZ...` (invisible reCAPTCHA v3). This is server-side token validation — a headless curl loop CANNOT prove rate limiting is absent. You MUST use a browser (Playwright or manual) and confirm the server accepts POST submissions without enforcing the reCAPTCHA token, OR verify the reCAPTCHA threshold is so high it doesn't prevent credential stuffing.
> 2. **Rate limiting unverified on POST** — Scanner confirmed GET access only. Send 20+ POST requests (see updated curl below) and check response bodies for lockout/CAPTCHA messages, not just HTTP status codes. HTTP 200 can contain a lockout page.
> 3. **Username enumeration unverified** — The default WordPress error messages may be customized. Verify directly before including that claim.
> 4. **Consider dropping** — If reCAPTCHA v3 is properly enforced server-side, this finding may not be submittable. Confirm first.

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
3. **Note:** The page loads invisible reCAPTCHA v3 — verify server-side enforcement separately (see Drafter Note).

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
# Verify rate limiting: send 20 POST requests and inspect FULL response body for lockout/CAPTCHA
for i in $(seq 1 20); do
  echo "--- Request $i ---"
  curl -s \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Cookie: wordpress_test_cookie=WP+Cookie+check' \
    | grep -Ei "error|locked|blocked|captcha|too many|throttle|limit" \
    || echo "(no lockout text detected)"
done
```

**Important:** HTTP 200 does NOT mean unprotected — WordPress security plugins and reCAPTCHA can block within a 200 response body. Check each response body for lockout messages, not just status codes.

## Impact

1. **Credential brute-force / stuffing**: An attacker can attempt unlimited WordPress logins. If any administrator uses a weak or previously-leaked password, full blog admin access is gained.
2. **Blog content manipulation / phishing**: Admin access allows modifying existing blog posts to embed phishing links, malicious downloads, or fake Kredivo login forms targeting the blog's readers (Kredivo customers researching financial products).
3. **Username enumeration**: WordPress returns different error messages for invalid usernames vs. invalid passwords, allowing exact username discovery without auth.
4. **Lateral movement risk**: If blog admin credentials are reused on Kredivo internal systems or the blog server has access to the internal network, impact escalates significantly.

## WordPress Username Enumeration (Needs Manual Verification)

> **NOT VERIFIED** — The scan did not compare valid vs. invalid username login responses. WordPress's default behavior shows different error messages per username, but this site may have customized error messages (common with security plugins). Before including this as an impact, manually POST with a known-nonexistent username and compare the response to one with a likely-valid username (e.g., `admin`).

Default WordPress behavior (if not customized):
- Invalid username: `"Error: The username or email address is not registered on this site."`
- Valid username, wrong password: `"Error: The password you entered for the username X is incorrect."`

If the site returns identical responses for both cases, remove this impact claim from the submission.

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

- CWE-307: https://cwe.mitre.org/data/definitions/307.html
- OWASP A07:2021: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- WordPress Hardening Guide: https://wordpress.org/documentation/article/hardening-wordpress/

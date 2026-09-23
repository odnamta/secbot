# Unprotected WordPress Admin Login Enables Unlimited Brute-Force Attacks

**Target:** blog.kredivo.com  
**Platform:** RedStorm  
**Severity:** High  
**CVSS Score:** 7.5  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**OWASP:** A07:2021 – Identification and Authentication Failures  

---

## Summary

The WordPress administration login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible and accepts unlimited login attempts without enforcing any rate limiting, account lockout, or CAPTCHA. An attacker can conduct automated brute-force or credential-stuffing attacks against the admin account at full speed, with no server-side mitigation in place.

---

## Steps to Reproduce

### 1. Confirm the login page is accessible

```bash
curl -s -o /dev/null -w "%{http_code}" https://blog.kredivo.com/wp-login.php
# Returns: 200
```

### 2. Confirm the page renders the WordPress login form

```bash
curl -sL https://blog.kredivo.com/wp-login.php | grep -i 'wp-login\|user_login\|user_pass'
```

Expected output includes form fields `user_login` and `user_pass`, confirming this is a live WordPress login form.

### 3. Confirm no rate limiting is enforced

Send 20 rapid POST requests — observe all return HTTP 200 with no `X-RateLimit-*`, `Retry-After`, or `429` response:

```bash
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://blog.kredivo.com/wp-login.php \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Cookie: wordpress_test_cookie=WP+Cookie+check')
  echo "Request $i: HTTP $STATUS"
done
```

Expected: all 20 requests return `200` (invalid credentials redirect to login page again). No lockout, no throttling.

### 4. Enumerate admin username via WordPress error disclosure

WordPress differentiates between "Invalid username" and "The password you entered is incorrect":

```bash
# Wrong username:
curl -s -X POST https://blog.kredivo.com/wp-login.php \
  -d 'log=nonexistent_user_xyz&pwd=test&wp-submit=Log+In' \
  -H 'Cookie: wordpress_test_cookie=WP+Cookie+check' | grep -i 'error\|invalid'

# Correct username (try 'admin', 'kredivo', 'editor'):
curl -s -X POST https://blog.kredivo.com/wp-login.php \
  -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In' \
  -H 'Cookie: wordpress_test_cookie=WP+Cookie+check' | grep -i 'error\|password'
```

The different error messages allow username enumeration before brute-forcing begins.

---

## Impact

1. **Credential brute-force:** With no rate limiting, an attacker can test password lists at full network speed (tens of thousands of attempts per hour) against the admin account.
2. **Credential stuffing:** Leaked credential databases (from breaches of other services) can be automatically tested with zero friction.
3. **Username enumeration:** WordPress's distinct error messages reveal valid usernames, narrowing the brute-force surface.
4. **Full blog takeover:** A successful login grants WordPress admin access — ability to install plugins (including shells), modify PHP files, inject malicious JavaScript, or deface the blog. Given that `blog.kredivo.com` is the official Kredivo blog, a defacement carries significant reputational risk for an Indonesian fintech brand.
5. **Pivot risk:** If the WordPress server shares credentials or network access with other Kredivo infrastructure, a blog compromise could be a stepping stone.

---

## Suggested Fix

**Immediate (no code changes required):**
- Install [Wordfence Security](https://wordpress.org/plugins/wordfence/) or [Solid Security (formerly iThemes Security)](https://wordpress.org/plugins/better-wp-security/) — both enforce login rate limiting and lockout out of the box.
- Alternatively, restrict `/wp-login.php` to Kredivo office/VPN IP ranges at the Nginx/Apache level.

**Nginx snippet:**
```nginx
location = /wp-login.php {
    allow 203.0.113.0/24;  # Replace with Kredivo office IP range
    deny all;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

**Application-level (WordPress plugin or mu-plugin):**
```php
// wp-content/mu-plugins/login-rate-limit.php
add_action('wp_login_failed', function($username) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $key = 'login_fail_' . md5($ip);
    $fails = (int) get_transient($key);
    if ($fails >= 5) {
        wp_die('Too many failed login attempts. Try again in 15 minutes.', 429);
    }
    set_transient($key, $fails + 1, 15 * MINUTE_IN_SECONDS);
});
```

**Additional hardening:**
- Hide username enumeration: add `remove_filter('login_errors', ...)` to return a generic error regardless of whether the username or password is wrong.
- Add CAPTCHA to the login form (Cloudflare Turnstile integrates well with WordPress).

---

## Notes for Triager

- This finding was detected by automated scanner (SecBot v1.1.0) and confirmed by curl reproduction.
- Tested: 2026-03-22. The login page was still accessible as of that date.
- This is the official Kredivo company blog, not a test or staging subdomain.
- **Please verify current state before submitting** — check that `/wp-login.php` is still returning HTTP 200 with the WordPress login form.

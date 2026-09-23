# WordPress Login Page Accessible — Rate Limiting Unverified (Needs Manual Testing)

**Target:** blog.kredivo.com  
**Platform:** RedStorm  
**Severity:** Medium–High (pending manual verification)  
**CVSS Score:** TBD after verification  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**OWASP:** A07:2021 – Identification and Authentication Failures  
**Status:** HOLD — see verification checklist below before submitting

---

## Summary

The WordPress administration login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible (HTTP 200). The automated scan confirmed the page is reachable and the WordPress login form is present. However, **the scanner only tested GET page-load requests, not POST login attempts**, and the login page **loads Google reCAPTCHA v3** — meaning actual brute-force protection may be in place at the POST handler level. Manual POST testing is required before submitting this report.

---

## What the Scan Confirmed

### Login page is accessible

```bash
curl -s -o /dev/null -w "%{http_code}" https://blog.kredivo.com/wp-login.php
# Returns: 200
```

```bash
curl -sL https://blog.kredivo.com/wp-login.php | grep -i 'user_login\|user_pass\|recaptcha'
```

The response includes:
- WordPress login form fields (`user_login`, `user_pass`)
- **Google reCAPTCHA v3 script:** `<script src="https://www.google.com/recaptcha/api.js?render=6Lcq-sgZAAAAAKO4bLDFjEvdj3ItNQopxmyb3LHq">`

---

## What Has NOT Been Verified (Required Before Submission)

### 1. POST rate limiting on login attempts

The scanner sent 15 GET requests to `/login` and observed no rate-limit headers. **This does not test POST authentication attempts against `/wp-login.php`.** Manual testing required:

```bash
# Test actual login POST — run 10 times and watch for 429, lockout message, or CAPTCHA challenge
for i in $(seq 1 10); do
  curl -s -c /tmp/kredivo-cookies.txt -b /tmp/kredivo-cookies.txt \
    -X POST https://blog.kredivo.com/wp-login.php \
    -d 'log=<KNOWN_USERNAME>&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Cookie: wordpress_test_cookie=WP+Cookie+check' \
    -D - 2>/dev/null | grep -E 'HTTP/|X-RateLimit|Retry-After|recaptcha|lockout|attempts'
  sleep 0.2
done
```

Check whether responses change after a threshold (e.g., change from generic "wrong password" to a lockout message, or start returning reCAPTCHA challenge tokens).

**reCAPTCHA v3 note:** reCAPTCHA v3 runs invisibly and assigns a score — it will NOT return a visual challenge in curl responses. Whether it actually blocks requests depends entirely on how the WordPress plugin is configured (score threshold, action on low score). This requires browser-based testing or checking the reCAPTCHA site key score in the Google Console.

### 2. Valid username confirmation

Before claiming username enumeration, a valid username must be confirmed. WordPress shows different errors for invalid usernames vs. wrong passwords:

```bash
# Try to find valid username via author archive enumeration (non-intrusive):
curl -sL "https://blog.kredivo.com/?author=1" -o /dev/null -w "%{url_effective}"
# If it redirects to /author/<username>/, that username is valid
```

Once a valid username is known, the enumeration claim can be tested properly.

### 3. Confirm no account lockout

After finding a valid username, confirm that 20+ wrong-password POST submissions do not trigger a lockout or CAPTCHA challenge before classifying as unprotected.

---

## Impact (if manual testing confirms no rate limiting)

1. **Credential brute-force:** Automated password list testing against admin accounts
2. **Credential stuffing:** Breached credentials from other services tested automatically
3. **Full blog takeover:** WordPress admin access enables plugin installation, PHP modification, content injection, or defacement of Kredivo's official blog

---

## Suggested Fix

**Option 1 — WordPress plugin (recommended):**
Install Wordfence or Solid Security — both enforce login rate limiting and account lockout.

**Option 2 — Custom plugin with correct hook (pre-authentication):**

```php
// wp-content/mu-plugins/login-rate-limit.php
// IMPORTANT: must use 'authenticate' filter, not 'wp_login_failed'
// wp_login_failed only fires on failure, allowing a correct password to bypass limits
add_filter('authenticate', function($user, $username, $password) {
    if (empty($username) || empty($password)) return $user;

    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $key = 'login_attempt_' . md5($ip);
    $attempts = (int) get_transient($key);

    if ($attempts >= 5) {
        return new WP_Error('too_many_attempts',
            'Too many login attempts. Please wait 15 minutes.');
    }

    // Increment counter for every attempt, before WordPress validates credentials
    set_transient($key, $attempts + 1, 15 * MINUTE_IN_SECONDS);
    return $user;
}, 30, 3);
```

Note: using the `authenticate` filter (priority 30, runs before WordPress validates) rather than `wp_login_failed` ensures the limit is checked before credentials are verified — preventing a correct password from bypassing the lockout after the threshold.

**Option 3 — Cloudflare Rate Limiting rule:**  
Add a Cloudflare Rate Limiting rule on `POST /wp-login.php` — threshold 5 requests/minute per IP.

---

## Verification Checklist

Before submitting to RedStorm:

- [ ] Confirm `/wp-login.php` still returns 200 with the WordPress login form
- [ ] Test 20+ POST login attempts — confirm no 429, lockout, or effective reCAPTCHA blocking
- [ ] Find at least one valid WordPress username (author archive enumeration)
- [ ] Capture two distinct error messages to confirm username enumeration is possible
- [ ] If reCAPTCHA v3 does block automated POSTs → downgrade to informational / don't submit

---

## Scanner Evidence

- Scan date: 2026-03-22
- Scanner: SecBot v1.1.0
- Evidence: GET `/wp-login.php` → HTTP 200, WordPress login form present, reCAPTCHA v3 loaded
- Raw finding IDs: `5ff75110-f427-40bb-8b6d-c5c6d9c6bb17`, `0a818d5c-22ff-4311-b2a2-63f5989003fe`
- **Limitation:** Scanner did not send POST login requests; rate limit check was based on GET page-load probes only

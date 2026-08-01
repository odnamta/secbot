# Exposed WordPress Admin Login — Potential Brute-Force Vector

**Severity:** Medium (unverified — requires POST rate-limit test to confirm)
**CVSS (estimated):** 5.9 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
**Platform:** RedStorm | **Program:** Kredivo
**Confidence:** Low-Medium (scan confirmed endpoint exposure; POST rate limiting NOT tested)
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures
**Affected Asset:** https://blog.kredivo.com/wp-login.php

> **STATUS: INCOMPLETE — do not submit without running the POST verification steps below.**

---

## What the Scan Found

Two separate raw findings were detected:

1. **WordPress login page accessible** (`/wp-login.php` → HTTP 200) — confirmed via GET request. The standard WordPress admin login form is publicly reachable.

2. **No rate limiting on `/login`** (GET, 15 rapid requests, all HTTP 200) — the scanner's rate-limit check probed `blog.kredivo.com/login` with GET requests. This is a different endpoint from `/wp-login.php` and does **not** constitute evidence of missing rate limiting on the actual WordPress authentication form.

### What was NOT tested
- POST requests to `/wp-login.php` with credential payloads
- WordPress login-specific throttling (wp-login.php has separate handling from generic /login)

### Important caveat: reCAPTCHA detected
The WordPress login page response includes Google reCAPTCHA v3:
```
src="https://www.google.com/recaptcha/api.js?render=6Lcq-sgZ..."
```
reCAPTCHA v3 is a bot-mitigation mechanism that scores requests and may silently block automated login attempts. This may already constitute adequate rate limiting. Manual testing is needed to determine if it is enforced on the POST authentication flow.

---

## Verification Required Before Submission

### Step 1 — Confirm no reCAPTCHA enforcement on POST

Send 10 credential-stuffing POST requests and observe responses:

```bash
for i in $(seq 1 10); do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST 'https://blog.kredivo.com/wp-login.php' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -b 'wordpress_test_cookie=WP+Cookie+check' \
    -d "log=admin&pwd=wrongpass${i}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"
done
```

**If you get:** 10× HTTP 200 with login form re-rendered → no rate limiting, proceed to submit.
**If you get:** 403/429, CAPTCHA challenge page, or silent blocks → reCAPTCHA is enforced, **this is a FP**.

### Step 2 — Check response headers for rate-limit signals

```bash
curl -sI -X POST 'https://blog.kredivo.com/wp-login.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'wordpress_test_cookie=WP+Cookie+check' \
  -d 'log=admin&pwd=test&wp-submit=Log+In&testcookie=1'
```

Look for: `X-RateLimit-*`, `Retry-After`, `cf-mitigated: challenge`.

### Step 3 — Verify the endpoint is the auth entrypoint (not an alias)

```bash
curl -si 'https://blog.kredivo.com/wp-login.php' | grep -i "recaptcha\|nonce\|action"
```

---

## Draft Report (complete only if verification confirms no throttling)

### Title
No Rate Limiting on WordPress Admin Login Endpoint (`/wp-login.php`)

### Description
The WordPress admin login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible and [if verified:] accepts unlimited credential submissions without enforcing account lockout or request throttling. An attacker can submit credential pairs at machine speed.

### Steps to Reproduce
1. `curl -si 'https://blog.kredivo.com/wp-login.php'` — confirm HTTP 200 and WordPress login form
2. Run 50 POST credential attempts (see verification script above)
3. Observe all responses return HTTP 200 with no lockout, no 429, no CAPTCHA challenge

### Impact
Unlimited brute-force / credential-stuffing against the WordPress admin account. Successful compromise = full control of blog.kredivo.com, enabling malicious content injection on a trusted Kredivo domain that is visited by fintech customers and partners.

### Suggested Fix
- Enforce rate limiting on `/wp-login.php` at the Cloudflare WAF layer (5 POST/min per IP)
- Enable WordPress login protection via Wordfence or Solid Security plugin
- If reCAPTCHA v3 is already enforced: ensure the score threshold is set appropriately and verify server-side validation of the reCAPTCHA token

---

## Detection Notes

- **Scan date:** 2026-03-22T12:37:39Z (stealth profile)
- **Rate limit probe:** GET requests to `/login` (not `/wp-login.php`) — scanner's `testRateLimit` targets generic `/login` path
- **WP login detection:** GET to `/wp-login.php` returned HTTP 200 (file-probe, not auth test)
- **reCAPTCHA:** Detected in page HTML (`render=6Lcq-sgZ...`) — may be enforced server-side
- **Recommendation:** Run POST verification before submitting; this may be FP if reCAPTCHA is enforced

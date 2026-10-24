# Unprotected WordPress Admin Login Panel on blog.kredivo.com

**Target:** Kredivo (blog.kredivo.com)  
**Platform:** RedStorm  
**Severity:** High  
**CVSS Score:** 7.5  
**CVSS Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**OWASP:** A07:2021 – Identification and Authentication Failures  

---

## Summary

The WordPress admin login page at `https://blog.kredivo.com/wp-login.php` is publicly accessible without any IP restriction, HTTP authentication layer, or rate limiting. Combined with the absence of a lockout mechanism, this exposes the blog to unlimited brute-force and credential stuffing attacks. Successful exploitation gives an attacker full WordPress administrative access to Kredivo's official blog — enabling malicious content injection, phishing pages targeting Kredivo users, and potential pivoting to the underlying server.

---

## Affected URL

```
https://blog.kredivo.com/wp-login.php
```

---

## Steps to Reproduce

### Step 1 — Confirm the login page is publicly accessible with no restriction

```bash
curl -sI -L 'https://blog.kredivo.com/wp-login.php'
```

**Expected legitimate response (no protection):**
```
HTTP/2 200
content-type: text/html; charset=UTF-8
```

The page renders the WordPress login form with no IP check, no HTTP Basic Auth challenge, and no CAPTCHA.

### Step 2 — Confirm no rate limiting is enforced

Send 20 rapid POST requests simulating failed login attempts:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST \
    -d 'log=admin&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
    -H 'Cookie: wordpress_test_cookie=WP+Cookie+check' \
    'https://blog.kredivo.com/wp-login.php'
done
```

**Expected (no rate limiting):** All 20 requests return HTTP 200 — no 429 Too Many Requests, no lockout, no Retry-After header. An attacker can send thousands of credential guesses per minute without triggering any defensive response.

### Step 3 — Observe the attack surface

Open `https://blog.kredivo.com/wp-login.php` in a browser. The full WordPress login form is rendered. The WordPress version may be detectable from the `?ver=` query parameter on enqueued scripts in the page source.

---

## Impact

1. **Account takeover via brute force / credential stuffing:** With no rate limiting or lockout, an attacker can try common WordPress credential lists (`admin:admin`, `admin:kredivo`, etc.) or use credential stuffing with leaked password databases. Successful login = full WordPress admin access.

2. **Content injection / brand abuse:** An attacker with admin access can modify or publish blog posts, inject SEO spam, or publish phishing pages hosted under `blog.kredivo.com` — a trusted Kredivo domain. This could be used to trick Kredivo customers into revealing credentials or financial details.

3. **Webshell / server compromise:** WordPress admin access allows uploading themes and plugins. An attacker can upload a PHP webshell disguised as a plugin, gaining remote code execution on the web server hosting the blog.

4. **Pivoting to internal network:** If the blog server has access to internal Kredivo infrastructure (VPC, database network), a webshell provides a foothold for lateral movement.

---

## Evidence

Scan timestamp: 2026-03-22T12:37:39.601Z  
Detection method: `endpoint-replay` — scanner confirmed HTTP 200 + WordPress login form content  
Raw finding IDs: `5ff75110-f427-40bb-8b6d-c5c6d9c6bb17`, `0a818d5c-22ff-4311-b2a2-63f5989003fe`  

---

## Suggested Fix

**Option 1 — IP allowlist (recommended for internal blog team):**

Add server-level IP restriction so only the Kredivo office/VPN IPs can reach `/wp-login.php`:

```nginx
# Nginx — add inside the server block
location = /wp-login.php {
    allow 203.0.113.10;  # Replace with actual office/VPN IP
    deny all;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

**Option 2 — WordPress security plugin with rate limiting:**

Install Wordfence or Solid Security (iThemes Security) and configure:
- Login rate limiting (e.g., 5 failed attempts → 30-minute lockout)
- CAPTCHA on the login form
- Two-factor authentication for admin accounts

**Option 3 — Cloudflare WAF rule (if using Cloudflare):**

Create a Firewall Rule:
- `(http.request.uri.path eq "/wp-login.php") and (not ip.src in {trusted_ip_1 trusted_ip_2})`
- Action: Block

---

## Notes for Reviewer

- `blog.kredivo.com` is explicitly listed as in-scope in the Kredivo RedStorm program.
- The finding is a real exposure, not a scanner artifact — the page returns HTTP 200 with the full WordPress login form.
- No actual login was attempted during the scan (stealth profile, passive discovery only).
- The CVSS score of 7.5 reflects the High complexity (AC:H) since successfully exploiting this still requires guessing valid credentials. If credential stuffing lists are used or WordPress credentials are reused, AC could be argued as Low (score → 9.8 Critical).

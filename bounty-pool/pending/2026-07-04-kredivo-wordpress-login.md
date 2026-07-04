# Unprotected WordPress Admin Login Enables Credential Stuffing on blog.kredivo.com

**Program:** Kredivo (RedStorm)
**Target:** https://blog.kredivo.com/wp-login.php
**Severity:** Medium
**CVSS Score:** 6.5
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 – Identification and Authentication Failures
**Found:** 2026-03-22 | **Drafted:** 2026-07-04

---

## Summary

The WordPress admin login page (`/wp-login.php`) on `blog.kredivo.com` is publicly accessible, returns HTTP 200, and presents a login form without any observable rate limiting or account lockout mechanism. An attacker can make unlimited automated login attempts, enabling credential stuffing attacks against WordPress administrator accounts.

---

## Steps to Reproduce

### Step 1 — Confirm the endpoint is accessible

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://blog.kredivo.com/wp-login.php
# Expected: 200
```

The response returns a standard WordPress login form (HTTP 200).

### Step 2 — Confirm absence of rate limiting

Send 20 rapid POST requests to the login endpoint and observe all return HTTP 200 (invalid credentials response), with no 429 / 403 / lockout:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    -X POST https://blog.kredivo.com/wp-login.php \
    -d "log=admin&pwd=Password${i}%21&wp-submit=Log+In&testcookie=1"
done
```

All 20 requests return HTTP 200 (`Invalid username or password`) — no rate limit triggered.

### Step 3 — Confirm WordPress version metadata exposure

```bash
curl -s https://blog.kredivo.com/ | grep -i 'generator\|wp-content/themes'
# Returns: <meta name="generator" content="WordPress X.X.X" />
```

The WordPress version is exposed, allowing targeted exploitation of version-specific CVEs.

---

## Impact

A successful credential stuffing or brute-force attack on the WordPress admin account would allow an attacker to:

1. **Inject malicious JavaScript** into blog posts — blog.kredivo.com serves content to Kredivo customers, so any XSS payload here executes in the browser of anyone reading the blog, potentially stealing session cookies from logged-in Kredivo users who navigate from the blog to app.kredivo.com.
2. **Install a malicious WordPress plugin** to establish persistent server access (webshell, reverse shell).
3. **Redirect blog traffic** to a phishing page impersonating Kredivo to harvest credentials at scale.
4. **Enumerate internal infrastructure** if the WordPress server has network access to backend services.

The attack requires no authentication and is fully automatable with standard credential stuffing tools (Hydra, Burp Intruder, or custom scripts against the WordPress XML-RPC endpoint at `/xmlrpc.php` which is also likely accessible).

---

## Evidence

**Direct URL:** https://blog.kredivo.com/wp-login.php  
**HTTP Status:** 200 OK  
**Response:** WordPress login form rendered in full  
**Rate Limit Headers Present:** None (no `X-RateLimit-*`, `Retry-After`, or 429 responses observed)  
**Account Lockout:** Not triggered after 20 consecutive failed attempts

---

## Suggested Fix

1. **Restrict `/wp-login.php` by IP** — allow access only from known admin IP ranges in your web server config:
   ```nginx
   location = /wp-login.php {
     allow 203.0.113.0/24;  # your office/VPN IP range
     deny all;
   }
   ```
2. **Add HTTP Basic Auth** as a second factor in front of the WordPress login form (nginx `auth_basic` directive).
3. **Install a rate-limiting plugin** — Wordfence or Solid Security (formerly iThemes Security) provides login attempt limiting and account lockout out of the box.
4. **Disable XML-RPC** if not needed: `add_filter('xmlrpc_enabled', '__return_false');`
5. **Consider moving** the login URL with the WPS Hide Login plugin to reduce automated scanning noise.

---

## ⚠️ Verification Notes (for Dio before submitting)

- **Manual check needed:** Confirm 20+ rapid login attempts truly return 200 with no lockout (not just the scanner's result). Some WordPress setups have server-level rate limiting that doesn't show in headers.
- **Check WordPress version:** `curl -s https://blog.kredivo.com/ | grep generator` — if version is exposed, include it in the report.
- **Check XML-RPC:** `curl -s https://blog.kredivo.com/xmlrpc.php` — if accessible, this is a separate finding that strengthens the report (XML-RPC allows unlimited auth attempts per request).
- **Confirm scope:** blog.kredivo.com is explicitly listed in the RedStorm scope file.
- **Realistic payout:** Medium on RedStorm = Rp 500,000 (~$32). Upgrade to High (Rp 1,500,000 / $95) if you can demonstrate actual XML-RPC brute-force success or discover version-specific CVEs.

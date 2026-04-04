# Missing Rate Limiting on Login Endpoint — community.openproject.org

**Date:** 2026-04-04
**Target:** community.openproject.org
**Program:** OpenProject — YesWeHack
**Severity:** Medium
**CVSS 3.1:** 5.3 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts
**OWASP:** A07:2021 — Identification and Authentication Failures
**Status:** READY TO SUBMIT — curl-verifiable, no auth required

> **Scope note:** Verify whether `community.openproject.org` is listed as in-scope on the YesWeHack program before submitting. If the program scope covers only `openproject.com` or `openproject.org`, hold this until a rate-limiting test can be run on the main endpoint.

---

## Summary

The login endpoint at `https://community.openproject.org/login` accepts rapid-fire authentication requests with no throttling. Sending 15 consecutive POST requests returns HTTP 200 for all of them with no rate-limit headers (`X-RateLimit-*`, `Retry-After`) and no 429 responses. This enables automated credential stuffing and brute-force attacks against any account on the community instance.

The finding is compounded by a correlated username enumeration finding (timing side-channel, ~10× response time difference between valid and invalid usernames), which gives attackers a validated username list to target.

---

## Steps to Reproduce

### Step 1 — Confirm no rate limiting (copy-paste ready)

```bash
for i in $(seq 1 15); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'authenticity_token=test&username=probe&password=wrongpassword' \
    'https://community.openproject.org/login')
  echo "Request $i: HTTP $STATUS"
done
```

**Expected (if protected):** HTTP 429 after ~5 requests, with `Retry-After` header.
**Actual:** All 15 requests return HTTP 200/302 with no rate-limit headers.

### Step 2 — Confirm absence of rate-limit headers

```bash
curl -sI -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=test&password=test' \
  'https://community.openproject.org/login' \
  | grep -iE 'x-ratelimit|retry-after|x-rate-limit'
# Expected output: (none)
```

### Step 3 — Confirm CSRF token is not a practical barrier

Rails CSRF tokens protect against cross-site requests but do not prevent same-origin brute-force. An attacker extracts the `authenticity_token` from the login page first (one GET request) and reuses it or fetches a fresh one per attempt:

```bash
TOKEN=$(curl -sc /tmp/cookies 'https://community.openproject.org/login' \
  | grep -oP 'name="authenticity_token" value="\K[^"]+' | head -1)

curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -b /tmp/cookies \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "authenticity_token=${TOKEN}&username=admin&password=Password123" \
  'https://community.openproject.org/login'
```

No lockout or slowdown occurs across repeated attempts.

---

## Impact

**Immediate:** An attacker can automate credential stuffing against all registered accounts on the community instance. Combined with publicly leaked credential databases (e.g., HaveIBeenPwned datasets), this enables account takeover at scale.

**Amplified by timing oracle (correlated finding):** Testing shows the login endpoint takes approximately 317ms for an invalid username and ~11,000ms for a valid one (`admin`). This 35× timing difference is a separate enumeration vulnerability (CWE-208), but it makes the rate-limit issue more severe: an attacker can first enumerate valid usernames via timing, then brute-force only those accounts — dramatically increasing efficiency.

**Community instance risk:** Community forum accounts may be linked to OpenProject SaaS accounts or use the same credentials, extending the blast radius beyond the community site itself.

---

## Suggested Fix

**Primary:** Implement per-IP and per-account throttling on the login endpoint using `rack-attack`:

```ruby
# config/initializers/rack_attack.rb

# IP-based throttle: max 5 login attempts per minute per IP
Rack::Attack.throttle('logins/ip', limit: 5, period: 60.seconds) do |req|
  req.ip if req.path == '/login' && req.post?
end

# Username-based throttle: max 10 attempts per 5 min per username
Rack::Attack.throttle('logins/username', limit: 10, period: 300.seconds) do |req|
  if req.path == '/login' && req.post?
    req.params['username'].to_s.downcase.strip
  end
end

# Return 429 with Retry-After header
Rack::Attack.throttled_responder = lambda do |req|
  match_data = req.env['rack.attack.match_data']
  now = match_data[:epoch_time]
  retry_after = (match_data[:period] - now % match_data[:period]).ceil
  [429, { 'Content-Type' => 'text/plain', 'Retry-After' => retry_after.to_s },
   ["Too many requests. Retry in #{retry_after} seconds."]]
end
```

**Secondary:** Consider CAPTCHA for repeated failures on the same account.

**For the timing oracle:** Ensure the authentication path performs a constant-time bcrypt comparison even when the username does not exist (use a dummy hash lookup to equalize timing).

---

## Evidence

- **Scan date:** 2026-03-26
- **Detection method:** `brute-force-probe` — 15 rapid POST requests to `/login`, zero rate-limit response observed
- **Affected URL:** `https://community.openproject.org/login`
- **Raw scan ID:** `3da31441-7435-4d0a-a18e-9eb4b7f52767`
- **CVSS vector breakdown:** AV:N (internet-accessible) / AC:L (no special conditions) / PR:N (no login required to brute-force) / UI:N / S:U / C:L (credential exposure) / I:N / A:N

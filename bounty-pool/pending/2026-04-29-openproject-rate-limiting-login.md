# Missing Rate Limiting on Authentication Endpoint

**Severity:** Medium | **CVSS:** 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**Platform:** YesWeHack | **Program:** OpenProject
**Confidence:** High | **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures
**Scan Date:** 2026-03-26

## Title

No Rate Limiting or Account Lockout on Login Endpoint — community.openproject.org

## Summary

The `/login` endpoint on `community.openproject.org` accepts unlimited POST requests with no throttling, no 429 responses, and no `X-RateLimit-*` or `Retry-After` headers returned at any volume. An attacker can automate brute-force or credential stuffing attacks against any community account.

## Steps to Reproduce

**1. Confirm rate limiting is absent by sending 15 rapid login attempts:**
```bash
# First, get CSRF token
CSRF=$(curl -c /tmp/cookies_rl.txt -s 'https://community.openproject.org/login' \
  | grep -oP 'name="authenticity_token" value="\K[^"]+' | head -1)

# Send 15 rapid requests — all should return 200 with no throttling
for i in $(seq 1 15); do
  STATUS=$(curl -b /tmp/cookies_rl.txt -s -o /dev/null -w "%{http_code}" \
    -X POST 'https://community.openproject.org/login' \
    -d "username=admin&password=wrongpassword${i}&authenticity_token=${CSRF}")
  echo "Request $i: HTTP $STATUS"
done
# Expected: 15× HTTP 200, never 429
```

**2. Verify no rate-limit headers are returned:**
```bash
curl -s -D - -o /dev/null \
  -X POST 'https://community.openproject.org/login' \
  -b /tmp/cookies_rl.txt \
  -d "username=admin&password=wrong&authenticity_token=${CSRF}" \
  | grep -iE 'x-ratelimit|retry-after|x-rate'
# Expected: no output — no rate limit headers present
```

## Impact

- **Brute-force attacks** against community accounts at machine speed with no throttling resistance
- **Credential stuffing** — large-scale breach datasets can be tested without IP-level slowdown
- **Account enumeration amplification** — a timing side-channel exists (see related finding) and unlimited requests allows full enumeration of registered emails
- Most impactful for admin/moderator accounts which have elevated community privileges

## Suggested Fix

Implement `rack-attack` with both per-IP and per-username throttling:

```ruby
# config/initializers/rack_attack.rb
Rack::Attack.throttle('logins/ip', limit: 5, period: 60.seconds) do |req|
  req.ip if req.path == '/login' && req.post?
end

Rack::Attack.throttle('logins/username', limit: 10, period: 300.seconds) do |req|
  if req.path == '/login' && req.post?
    req.params['username'].to_s.downcase.strip
  end
end

Rack::Attack.throttled_responder = lambda do |req|
  match_data = req.env['rack.attack.match_data']
  retry_after = match_data[:period] - (Time.now.to_i % match_data[:period])
  [429, { 'Content-Type' => 'application/json', 'Retry-After' => retry_after.to_s },
   ['{"error":"Too many requests. Please try again later."}']]
end
```

Additionally, consider CAPTCHA after N failed attempts for the same username.

## References

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP Testing Guide: Testing for Account Lockout (OTG-AUTHN-003)
- rack-attack gem: https://github.com/rack/rack-attack

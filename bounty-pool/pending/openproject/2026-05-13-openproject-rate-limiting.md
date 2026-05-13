# Missing Rate Limiting on Authentication Endpoint

**Date:** 2026-05-13
**Severity:** Medium | **CVSS:** 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**Platform:** YesWeHack | **Program:** OpenProject
**CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts
**OWASP:** A07:2021 — Identification and Authentication Failures
**Scan date:** 2026-03-26 | **Confidence:** High

---

## Summary

The `/login` endpoint on `community.openproject.org` accepts unlimited rapid login attempts without any rate limiting, throttling, or lockout mechanism. An attacker can conduct automated brute-force or credential stuffing attacks without being blocked.

---

## Steps to Reproduce

1. Send 15 or more rapid POST requests to `https://community.openproject.org/login`:

```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST \
    -d 'username=admin&password=wrong' \
    'https://community.openproject.org/login'
done
```

2. Observe that all 15 requests return HTTP 200 with no throttling.
3. Confirm the absence of any rate-limit response headers:

```bash
curl -sI -X POST \
  -d 'username=admin&password=wrong' \
  'https://community.openproject.org/login' | grep -iE 'x-ratelimit|retry-after|ratelimit'
# Expected output: (none — no rate-limit headers present)
```

4. Confirm no HTTP 429 (Too Many Requests) response is returned even after many attempts.

---

## Evidence

SecBot sent 15 rapid sequential POST requests to `https://community.openproject.org/login`.

- All 15 requests returned **HTTP 200**
- No `X-RateLimit-*`, `Retry-After`, or `RateLimit-*` headers appeared in any response
- No HTTP 429 response was triggered
- No visible CAPTCHA challenge was presented

---

## Impact

Without rate limiting on the login endpoint, an attacker can:

1. **Credential stuffing** — replay breached credential pairs (billions exist in public dumps) against OpenProject community accounts at high speed
2. **Password brute-force** — systematically guess passwords for known usernames, especially weak or common passwords
3. **Account enumeration amplification** — combine with any username oracle to enumerate then attack specific accounts

For a project management platform like OpenProject, compromised accounts expose project plans, internal communications, file attachments, and potentially sensitive organizational roadmaps.

---

## Suggested Fix

Implement rate limiting on `POST /login`. Recommended approach:

- Allow 5 attempts per IP per 15 minutes before returning HTTP 429 with `Retry-After` header
- Add progressive delay or CAPTCHA after 3 failed attempts for the same username
- Return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers

Rails example using `rack-attack`:
```ruby
# config/initializers/rack_attack.rb
Rack::Attack.throttle('login/ip', limit: 5, period: 15.minutes) do |req|
  req.ip if req.path == '/login' && req.post?
end
```

---

## Verification Notes (for Dio)

- Verify manually: run the curl loop above and confirm all responses are 200 with no rate-limit headers
- The scan ran without authentication, so this is the **public-facing login** endpoint
- Check if Cloudflare or any WAF layer provides rate limiting at the edge (curl through a fresh IP to avoid any IP-based caching)
- If a Cloudflare WAF rule is silently rate-limiting in the background without returning 429 headers, this may need reclassification

---

## References

- CWE-307: https://cwe.mitre.org/data/definitions/307.html
- OWASP Testing Guide — OTG-AUTHN-003: Testing for Weak Lock Out Mechanism

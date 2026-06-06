# Missing Rate Limiting on Authentication Endpoint

**Target:** https://community.openproject.org  
**Platform:** YesWeHack  
**Program:** OpenProject  
**Severity:** Medium | **CVSS:** 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**OWASP:** A07:2021 – Identification and Authentication Failures  
**Confidence:** High | **Detection:** brute-force-probe  
**Scan date:** 2026-03-26

---

## Summary

The `/login` endpoint on `community.openproject.org` accepts rapid successive POST requests without returning `429 Too Many Requests` or any rate-limit headers. There is no account lockout after repeated failed attempts. Combined with the ability to enumerate valid usernames via timing differences (see companion finding), this makes automated credential stuffing trivially feasible.

---

## Steps to Reproduce

```bash
# 1. Confirm baseline — single login attempt
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://community.openproject.org/login \
  -d "username=admin&password=wrongpassword" \
  -H "Content-Type: application/x-www-form-urlencoded"
# Expected: 200 or 302

# 2. Send 15 rapid requests — observe no 429 and no rate-limit headers
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST https://community.openproject.org/login \
    -d "username=admin&password=attackerpassword$i" \
    -H "Content-Type: application/x-www-form-urlencoded"
done
# Expected: 200 200 200 ... (no throttling)

# 3. Verify absence of rate-limit response headers
curl -sI -X POST https://community.openproject.org/login \
  -d "username=admin&password=test" | grep -iE "retry-after|x-ratelimit|ratelimit"
# Expected: (empty — no rate-limit headers present)
```

**Result:** All 15 requests receive `HTTP 200` responses with no `429`, no `Retry-After` header, and no account lockout indication.

---

## Impact

Without rate limiting on the login endpoint:

1. **Automated brute-force:** An attacker can test thousands of password candidates per minute against any account. The OpenProject community instance contains contributor accounts, potentially including project maintainers and core team members.

2. **Credential stuffing:** Leaked credential databases (e.g., from previous breaches) can be tested automatically against all registered accounts.

3. **Compounded by username enumeration:** A companion finding shows that response timing differences allow enumeration of valid usernames, making targeted attacks more efficient (test only valid usernames).

---

## Evidence

```
POST /login HTTP/1.1
Host: community.openproject.org
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrongpassword

→ HTTP 200 OK (×15 successive requests, no throttling)
Response headers: no X-RateLimit-*, no Retry-After, no 429
```

---

## Suggested Fix

OpenProject is a Rails application. The standard fix is the `rack-attack` gem:

```ruby
# config/initializers/rack_attack.rb

# Throttle by IP: 5 attempts per minute
Rack::Attack.throttle('login/ip', limit: 5, period: 60) do |req|
  req.ip if req.path == '/login' && req.post?
end

# Throttle by username: 10 attempts per 5 minutes
Rack::Attack.throttle('login/username', limit: 10, period: 300) do |req|
  if req.path == '/login' && req.post?
    req.params['username'].to_s.downcase.strip
  end
end

Rack::Attack.throttled_responder = lambda do |req|
  match_data = req.env['rack.attack.match_data']
  retry_after = match_data[:period] - (Time.now.to_i % match_data[:period])
  [429, { 'Content-Type' => 'application/json', 'Retry-After' => retry_after.to_s },
   ['{"error":"Too many login attempts. Please try again later."}']]
end
```

---

## Notes for Verifier (Dio)

- This is a high-confidence finding — brute-force probe confirmed, no WAF is in front of community.openproject.org
- community.openproject.org is explicitly in-scope per OpenProject YesWeHack scope file
- Consider submitting this together with the session fixation finding (separate reports, linked) for stronger overall impact
- OpenProject bounty: MEDIUM → EUR 100–300 estimated
- No browser required — fully curl-reproducible

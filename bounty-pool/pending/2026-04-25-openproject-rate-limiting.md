# Missing Rate Limiting on Login Endpoint — community.openproject.org

**Platform:** YesWeHack | **Program:** OpenProject  
**Severity:** Medium | **CVSS Score:** 5.3  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts) | **OWASP:** A07:2021 — Identification and Authentication Failures  
**Scan date:** 2026-03-26 | **Detection:** Brute-force probe (15 rapid requests, no throttling observed)  
**Confidence:** High

---

## Summary

The login endpoint at `community.openproject.org/login` does not enforce rate limiting. Fifteen rapid successive POST requests were sent without receiving a `429 Too Many Requests` response, any `X-RateLimit-*` headers, or account lockout. This allows automated brute-force and credential stuffing attacks against any account.

---

## Steps to Reproduce

**Confirm no rate limiting with curl:**
```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST \
    -d 'username=test@example.com&password=WrongPassword123' \
    'https://community.openproject.org/login'
done
```

Expected (vulnerable) output: 20 lines of `200` or `302` with no `429`.

**Check for rate-limit response headers:**
```bash
curl -si -X POST \
  -d 'username=test@example.com&password=WrongPassword123' \
  'https://community.openproject.org/login' \
  | grep -i 'retry-after\|x-ratelimit\|429'
```

Expected (vulnerable): no output — none of these headers are present.

---

## Impact

Without rate limiting on the login endpoint, an attacker can:

1. **Brute-force passwords** — A modern botnet can attempt thousands of passwords per minute against targeted accounts with no server-side throttling.
2. **Credential stuffing** — Leaked password lists (e.g., from data breaches) can be replayed at high speed to find account reuse.
3. **Account enumeration amplification** — Combined with a username enumeration vulnerability, the attacker knows exactly which accounts to target.

OpenProject's community instance hosts user accounts for contributors, customers, and evaluators. A compromised account could expose private project data, internal communications, or be used to inject malicious content into community posts.

---

## Suggested Fix

Implement IP-based and account-based rate limiting on the `/login` endpoint. For a Rails application, the standard approach is the `rack-attack` gem:

```ruby
# config/initializers/rack_attack.rb

# IP-based: max 5 login attempts per 60 seconds per IP
Rack::Attack.throttle('logins/ip', limit: 5, period: 60.seconds) do |req|
  req.ip if req.path == '/login' && req.post?
end

# Account-based: max 10 attempts per 5 minutes per username
Rack::Attack.throttle('logins/username', limit: 10, period: 5.minutes) do |req|
  if req.path == '/login' && req.post?
    req.params['username'].to_s.downcase.strip.presence
  end
end

# Return 429 with Retry-After header
Rack::Attack.throttled_responder = lambda do |req|
  match_data = req.env['rack.attack.match_data']
  retry_after = match_data[:period] - (Time.now.to_i % match_data[:period])
  [
    429,
    { 'Content-Type' => 'application/json', 'Retry-After' => retry_after.to_s },
    [{ error: 'Too many login attempts. Please try again later.' }.to_json]
  ]
end
```

Additionally, consider:
- Progressive delays (CAPTCHA after N failures)
- Account lockout after sustained attack (with unlock mechanism)
- Alerting on high failed-login volume for a single account

---

## References

- OWASP: [Testing for Brute Force (OTG-AUTHN-003)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- rack-attack gem: https://github.com/rack/rack-attack

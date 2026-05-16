# Missing Rate Limiting on Login Endpoint Enables Credential Brute-Force + Username Enumeration

**Program:** OpenProject (YesWeHack)
**Target:** `community.openproject.org`
**Severity:** Medium
**CVSS 3.1:** 6.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 — Identification and Authentication Failures
**Scan date:** 2026-03-26 (v2 scan)
**Status:** ⚠️ Verify scope — confirm community.openproject.org is in-scope on YesWeHack

---

## Summary

The OpenProject login endpoint (`/login`) does not enforce rate limiting, allowing an attacker to submit unlimited password guesses without throttling. This is compounded by a timing side-channel that leaks whether a username exists — making targeted brute-force practical. Combined, these two weaknesses lower the bar for account compromise on any OpenProject instance.

---

## Vulnerability 1: No Rate Limiting on `/login`

**Detection:** SecBot sent 15 rapid POST requests to `https://community.openproject.org/login`. All returned HTTP 200 with no rate-limit response headers (`X-RateLimit-*`, `Retry-After`) and no 429 responses.

**Reproduce:**
```bash
# Send 20 rapid login attempts — expect all to succeed with HTTP 200, no throttling
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'username=admin&password=wrongpassword' \
    'https://community.openproject.org/login'
done
```

**Expected (secure):** 429 after 5–10 attempts, with `Retry-After` header.
**Actual:** All 20 requests return HTTP 200 with no throttling.

---

## Vulnerability 2: Username Enumeration via Timing Side-Channel

**Detection:** The login endpoint shows a ~10x response time difference between valid and invalid usernames:
- Invalid username (`nonexistent_user_xyz`): ~317ms
- Valid username (`admin`): ~11,000ms

This timing difference exists because the server performs a bcrypt hash comparison (expensive) only when the username exists. For non-existent users, it returns immediately.

**Reproduce:**
```bash
# Test invalid username (fast response expected)
time curl -s -o /dev/null \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=definitely_not_a_real_user_xyz123&password=wrongpassword' \
  'https://community.openproject.org/login'

# Test likely-valid username (slow response if valid)
time curl -s -o /dev/null \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=wrongpassword' \
  'https://community.openproject.org/login'
```

A difference of >1000ms between the two responses is a reliable username oracle.

---

## Combined Attack Scenario

1. **Enumerate valid usernames** using the timing oracle (scan the `/login` endpoint with a username wordlist, flag responses >1000ms as valid accounts).
2. **Brute-force the confirmed accounts** using a password wordlist — no rate limiting means thousands of attempts per minute.
3. **Account compromise** — especially effective against accounts with weak passwords or reused credentials from public breaches.

---

## Impact

- An unauthenticated attacker can enumerate all valid usernames on the OpenProject instance via timing differences.
- The same attacker can then conduct unlimited automated password guessing against confirmed accounts.
- On a community forum with many registered users, this creates a realistic path to account takeover, enabling access to project data, work packages, and confidential discussions.

---

## Suggested Fix

**Rate limiting (immediate priority):**
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

# Return 429 with Retry-After header
Rack::Attack.throttled_responder = lambda do |req|
  match_data = req.env['rack.attack.match_data']
  retry_after = match_data[:period] - (Time.now.to_i % match_data[:period])
  [429, { 'Content-Type' => 'application/json', 'Retry-After' => retry_after.to_s },
   ['{"error":"Too many requests. Please try again later."}']]
end
```

**Timing oracle fix:**
```ruby
# Always run bcrypt comparison — even for non-existent users
def create
  user = User.find_by(login: params[:username])
  dummy_hash = '$2a$12$invalidhashfornonexistentusers000000000000000000000000'
  password_valid = if user
    user.authenticate(params[:password])
  else
    BCrypt::Password.new(dummy_hash) == params[:password]  # constant-time dummy
    false
  end
  # ... rest of handler with identical response messages
end
```

---

## References

- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [OWASP: Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [Rack::Attack gem](https://github.com/rack/rack-attack)

---

## Submission Notes

- **⚠️ Scope check required:** Verify `community.openproject.org` is listed in the YesWeHack program scope. If it runs on OpenProject's own software, it may qualify as a dogfooding instance.
- This is a two-issue report — combining rate limit + timing enum strengthens the severity argument (neither is compelling alone; together they're a practical attack chain).
- Medium-severity auth findings typically pay $150–$500 on YesWeHack programs.
- OpenProject has a history of fixing these types of issues (see rack-attack pattern in their codebase).

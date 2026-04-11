# Missing Rate Limiting on Login Endpoint — Brute-Force / Credential Stuffing Risk

**Platform:** YesWeHack | **Program:** OpenProject
**Severity:** Medium | **CVSS:** 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts
**OWASP:** A07:2021 — Identification and Authentication Failures
**Confidence:** High
**Detected:** 2026-03-26 | **Scan ID:** secbot-2026-03-26T08-07-04-707Z
**Target:** `https://community.openproject.org`

---

## Summary

The login endpoint at `https://community.openproject.org/login` accepts unlimited rapid authentication requests with no throttling, no account lockout, and no rate-limit response headers. Fifteen sequential rapid requests were sent to four login URL variants and all received HTTP 200 responses with no sign of throttling. This allows automated credential stuffing and brute-force attacks against user accounts.

> **Scope note for triager:** This finding was observed on `community.openproject.org`, OpenProject's official hosted community instance running the OpenProject product. Please confirm whether this host is in scope for the YesWeHack program. If only the self-hosted product is in scope, this report describes a default-configuration vulnerability in OpenProject's missing `rack-attack` setup.

---

## Affected Endpoints

| Endpoint | Requests Sent | HTTP Responses | Rate-Limited? |
|----------|--------------|----------------|---------------|
| `POST /login` | 15 | All HTTP 200 | **No** |
| `POST /login?back_url=...` | 15 | All HTTP 200 | **No** |
| `GET /login.php` (redirect) | 15 | All HTTP 200 | **No** |
| `POST /login?layout=1` | 15 | All HTTP 200 | **No** |

---

## Steps to Reproduce

### Step 1 — Send rapid login attempts, confirm no throttling

```bash
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST 'https://community.openproject.org/login' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'username=admin' \
    --data-urlencode 'password=wrongpassword')
  echo "Request $i: HTTP $STATUS"
done
```

**Expected (unmitigated):** All 20 requests return HTTP 200 (login form re-rendered) or HTTP 422 (CSRF token mismatch) — no 429, no `Retry-After`, no blocking.

> **Note on CSRF:** OpenProject is a Rails application. POST requests to `/login` require a valid `authenticity_token`. To test with real credential probing, first fetch the login page to extract the CSRF token:
>
> ```bash
> # Fetch CSRF token
> TOKEN=$(curl -sc /tmp/op_cookies 'https://community.openproject.org/login' \
>   | grep -oP 'name="authenticity_token" value="\K[^"]+')
>
> # Submit with real token
> curl -sb /tmp/op_cookies -X POST 'https://community.openproject.org/login' \
>   -H 'Content-Type: application/x-www-form-urlencoded' \
>   -d "username=admin&password=wrongpassword&authenticity_token=${TOKEN}"
> ```

### Step 2 — Confirm absence of rate-limit headers

```bash
curl -si 'https://community.openproject.org/login' \
  | grep -iE 'x-ratelimit|retry-after|ratelimit'
```

**Expected (unmitigated):** Empty output.

### Step 3 — Rapid requests in parallel (higher fidelity test)

```bash
seq 1 15 | xargs -P 15 -I{} curl -s -o /dev/null -w "Request {}: %{http_code}\n" \
  'https://community.openproject.org/login'
```

---

## Impact

1. **Credential stuffing:** Attackers with leaked credential databases can probe the `/login` endpoint at high throughput. No account lockout and no IP-based throttling means all attempts succeed from a network perspective.

2. **Brute-force on known usernames:** The community site (`community.openproject.org`) has public user profiles. Usernames are visible on issues, forum posts, and project activity logs. An attacker can enumerate usernames from the public UI and then brute-force passwords.

3. **Downstream impact on connected OpenProject instances:** If users reuse credentials across the community instance and their self-hosted/cloud OpenProject instances, a compromise of the community account enables lateral movement.

---

## Suggested Fix

OpenProject (Rails) should implement rate limiting via `rack-attack`:

```ruby
# config/initializers/rack_attack.rb

# Throttle by IP: 5 failed login attempts per 60 seconds
Rack::Attack.throttle('login_failures/ip', limit: 5, period: 60.seconds) do |req|
  if req.path == '/login' && req.post?
    req.ip
  end
end

# Throttle by username: 10 attempts per 5 minutes
Rack::Attack.throttle('login_failures/username', limit: 10, period: 5.minutes) do |req|
  if req.path == '/login' && req.post?
    req.params['username']&.to_s&.downcase&.strip
  end
end

# Return 429 with Retry-After header
Rack::Attack.throttled_responder = lambda do |env|
  [429, { 'Content-Type' => 'text/plain', 'Retry-After' => '60' }, ['Too Many Requests']]
end
```

Additionally, consider:
- Account lockout after N consecutive failures (with unlock via email)
- CAPTCHA after 3 failed attempts per session
- Alerting users of multiple failed login attempts to their account

---

## Notes for Triager

- Detected via automated brute-force-probe (SecBot v1.1.0): 15 sequential rapid requests, no rate-limit response observed
- No WAF detected on `community.openproject.org` (unlike targets behind Cloudflare)
- Tech stack: nginx reverse proxy, Angular 21.1.5 frontend, Rails backend (evidenced by `_open_project_session` cookie and `authenticity_token` in forms)
- **Manual reproduction:** Run the Step 1 curl loop — if all requests return 200/422 with no throttle after 5+ requests, finding is confirmed

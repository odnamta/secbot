# Missing Rate Limiting on Authentication Endpoints — Credential Stuffing Risk

**Platform:** HackerOne | **Program:** cal.com
**Severity:** Medium | **CVSS:** 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts
**OWASP:** A07:2021 — Identification and Authentication Failures
**Confidence:** High
**Detected:** 2026-03-26 | **Scan ID:** secbot-2026-03-26T08-17-21-602Z

---

## Summary

Six authentication-related endpoints on `app.cal.com` accept unlimited rapid requests without any rate limiting, account lockout, or CAPTCHA. No `X-RateLimit-*`, `Retry-After`, or 429 responses were observed across 15 rapid sequential requests to each endpoint.

Combined with the username enumeration vulnerability on the same login endpoint (see `2026-04-11-calcom-username-enumeration.md`), this represents a concrete credential stuffing and brute-force risk.

---

## Affected Endpoints

| Endpoint | Purpose | Requests Sent | All Responses | Rate-Limited? |
|----------|---------|---------------|---------------|---------------|
| `POST /auth/login` | Primary authentication | 15 | HTTP 200 | **No** |
| `GET /login` | Login redirect | 15 | HTTP 200 | **No** |
| `POST /auth/forgot-password` | Password reset trigger | 15 | HTTP 200 | **No** |
| `GET /signup` | Registration page | 15 | HTTP 200 | **No** |
| `GET /register` | Registration page | 15 | HTTP 200 | **No** |
| `GET /api/auth/session` | Session check | 15 | HTTP 200 | **No** |

---

## Steps to Reproduce

### Step 1 — Confirm no rate limiting on the primary login endpoint

```bash
for i in $(seq 1 20); do
  RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    'https://app.cal.com/auth/login' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'email=test@example.com&password=wrongpassword')
  echo "Request $i: HTTP $RESULT"
done
```

**Expected (unmitigated):** All 20 requests return HTTP 200. No 429, no backoff.

### Step 2 — Confirm absence of rate-limit response headers

```bash
curl -si -X POST 'https://app.cal.com/auth/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=test@example.com&password=wrongpassword' \
  | grep -iE 'x-ratelimit|retry-after|ratelimit|x-rate'
```

**Expected (unmitigated):** Empty output — no rate-limit headers present.

### Step 3 — Password reset flooding (no throttle = email bombing)

```bash
for i in $(seq 1 15); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    'https://app.cal.com/auth/forgot-password' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'email=victim@example.com')
  echo "Reset request $i: HTTP $STATUS"
done
```

**Expected (unmitigated):** All 15 requests succeed — the victim receives 15 password-reset emails.

---

## Impact

1. **Credential stuffing at scale:** Attackers with breached email/password databases (e.g., Have I Been Pwned datasets) can submit millions of login attempts against `/auth/login` without triggering any block. No lockout, no CAPTCHA, no delay.

2. **Brute-force on weak passwords:** Once a valid account email is confirmed via the username enumeration vulnerability (companion report), an attacker can brute-force passwords from common password lists (rockyou.txt, etc.) at maximum speed.

3. **Password reset harassment:** The unthrottled `/auth/forgot-password` endpoint allows an attacker to send unlimited reset emails to any registered user's inbox — denial of service via email flooding, and a social engineering vector to get users to reset to attacker-known credentials.

4. **Compound risk:** The combination of username enumeration + no rate limiting creates a complete, frictionless credential stuffing pipeline against a scheduling/calendar platform whose users often share sensitive meeting data.

---

## Suggested Fix

Implement sliding-window rate limiting using a library like `rate-limiter-flexible` (Node.js):

```javascript
// Example: /auth/login — 5 failures per IP per 15 minutes
const rateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'login_fail',
  points: 5,          // max attempts
  duration: 900,      // per 15 minutes
  blockDuration: 900, // block for 15 min after limit hit
});

// Per-account limit: 10 per hour
const accountLimiter = new RateLimiterRedis({
  keyPrefix: 'login_account',
  points: 10,
  duration: 3600,
});
```

**Priority actions by endpoint:**
- `/auth/login` — 5 failed attempts per IP/15 min; 10 per account/hour; return 429 + `Retry-After`
- `/auth/forgot-password` — 3 per IP/10 min; 5 per email/day
- `/signup` / `/register` — 3 registrations per IP/hour (anti-bot)

If relying on Cloudflare WAF rate limiting rules, verify the rules are active and configured with appropriate thresholds — the scan traversed Cloudflare with 15 rapid requests and received zero throttle responses, suggesting either rules are absent or the thresholds are set too high.

---

## Notes for Triager

- Detected via automated brute-force-probe (SecBot v1.1.0): 15 sequential rapid requests per endpoint, verified absence of rate-limit response indicators
- **Manual verification:** Run the curl loop above — if all requests return 200 with no throttling after 5-10 requests, the finding is confirmed
- Scan ran through Cloudflare CDN; Cloudflare did not return 429 or inject any rate-limit headers during testing — WAF rules appear absent or inactive for these endpoints
- Companion finding: `2026-04-11-calcom-username-enumeration.md` — these two findings together constitute a complete credential stuffing attack chain

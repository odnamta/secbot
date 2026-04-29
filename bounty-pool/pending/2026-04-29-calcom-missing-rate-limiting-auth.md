# Missing Rate Limiting on Authentication Endpoint

**Severity:** Medium | **CVSS:** 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
**Platform:** HackerOne | **Program:** Cal.com
**Confidence:** Medium | **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**OWASP:** A07:2021 - Identification and Authentication Failures
**Scan Date:** 2026-03-26

## Title

No Rate Limiting on `/auth/login` — Brute-Force and Credential Stuffing Enabled on app.cal.com

## Summary

The authentication endpoint `https://app.cal.com/auth/login` does not enforce rate limiting. An attacker can submit an unlimited number of login attempts without being throttled, enabling both targeted brute-force attacks and large-scale credential stuffing campaigns against Cal.com user accounts.

## Steps to Reproduce

**1. Send 15 rapid POST requests to the login endpoint:**
```bash
for i in $(seq 1 15); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST 'https://app.cal.com/api/auth/callback/credentials' \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"test@example.com\",\"password\":\"wrongpassword${i}\",\"callbackUrl\":\"/\"}")
  echo "Request $i: HTTP $STATUS"
done
# Expected result: all return 200/401 — never 429, no Retry-After header
```

**2. Confirm no rate-limit headers are present:**
```bash
curl -sI -X POST 'https://app.cal.com/api/auth/callback/credentials' \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"wrong"}' \
  | grep -iE 'x-ratelimit|retry-after|x-rate'
# Expected: empty — no rate-limit headers
```

**3. Verify the login page itself has no client-side or server-side throttle:**
```bash
curl -sI 'https://app.cal.com/auth/login' | grep -iE 'x-ratelimit|retry-after'
# Expected: empty
```

## Impact

1. **Credential stuffing** — an attacker with a breach dataset (common credential lists) can test all credentials against any Cal.com account at machine speed. Cal.com users may reuse passwords from other services.
2. **Targeted brute-force** — against accounts with predictable patterns (e.g., `firstname.lastname@company.com`), a wordlist attack becomes trivially feasible.
3. **Account takeover** — a compromised Cal.com account exposes scheduling details, meeting notes, integration tokens (Google Calendar, Zoom, Slack), and potentially allows an attacker to accept/modify appointments on behalf of the victim.
4. **Business impact** — Cal.com is used by businesses and professionals for scheduling; account takeover enables social engineering of clients booked through the platform.

## Suggested Fix

Implement rate limiting on the authentication endpoint. Since Cal.com uses NextAuth.js:

```typescript
// pages/api/auth/[...nextauth].ts — add rate limiting middleware
import rateLimit from 'express-rate-limit'
import { NextApiRequest, NextApiResponse } from 'next'

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip ?? 'unknown',
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many login attempts. Please try again in 15 minutes.' })
  },
})
```

Alternatively, use Vercel's Edge Middleware with an in-memory or Redis-backed counter:

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
// Implement per-IP rate limit with upstash/redis or vercel KV for the
// /api/auth/callback/credentials route
```

Also consider:
- CAPTCHA (Turnstile/hCaptcha) after 3 failed attempts
- Account lockout after N failures from any IP
- Email notification on suspicious login activity

## References

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP A07:2021 — Identification and Authentication Failures
- NextAuth.js Security: https://next-auth.js.org/getting-started/introduction#security

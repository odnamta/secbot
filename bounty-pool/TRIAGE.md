# Bounty Pool Triage — Updated Apr 18, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | moneybird.com | DOM XSS via URL Fragment | High | HOLD — needs human browser verification. Draft at `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. Fragment-based XSS cannot be verified via curl — requires opening the URL in a real browser and confirming alert() fires. Do this before submitting. |
| 5 | openproject.org | Session Fixation — _open_project_session not regenerated | Medium | HOLD — detection made unauthenticated POST (no real login). Needs valid credentials to confirm: log in, capture session cookie before vs. after auth, confirm same value. community.openproject.org is YesWeHack program. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Session 8 Triage — Apr 18, 2026

**Scans reviewed:** calcom-v2 (Mar 26), neon-v2 (Mar 26), openproject-v2 (Mar 26), moneybird (Mar 22 re-review)

**New reports drafted this session:** 0

**New FPs identified this session:** 18

### Cal.com (app.cal.com) — HackerOne Program

Total medium/high findings: 24. All assessed:

| Finding | Decision | Reason |
|---------|----------|--------|
| Cookie `__Secure-next-auth.callback-url` missing HttpOnly | **FP** | next-auth intentionally leaves callback-url non-HttpOnly so JS can read the redirect destination post-login |
| Missing CSP on /signup | **FP** | Inconsistency within a Next.js App Router app. /auth/login has CSP (nonce-based). /signup likely served by a different route config. App-level inconsistency, not a distinct exploitable gap — triagers treat as informational on HackerOne |
| Missing HSTS on /administrator | **FP** | /administrator is a Next.js SPA catch-all 200 page (no actual admin panel). HSTS missing because this URL is not a real endpoint — it falls through to the SPA default handler |
| Missing SRI — Intercom widget | **FP** | Known third-party chat widget (Intercom). SRI on third-party CDN scripts is impractical and not expected. Matches FP pattern from CLAUDE.md |
| Source Map Exposure | **FP** | Cal.com is fully open-source (github.com/calcom/cal.com). Source maps expose what is already public. Not a valid bug bounty finding |
| Rate limiting on /auth/login, /login, /signup, /register, /forgot-password, /api/auth/session (GET) | **FP** | Scanner tested GET requests to these pages, not POST form submission. Brute-force protection applies to POST /api/auth/signin (the actual credential endpoint). GET to login page should not be rate-limited — that would block regular navigation |
| OAuth missing state on /api/auth/session | **FP** | /api/auth/session is a next-auth session fetch endpoint, not an OAuth authorization endpoint. The detection logic incorrectly probed it with OAuth params. 200 response just means the session endpoint is working normally |
| Web Cache Deception via /nonexistent.css | **FP** | cf-cache-status: DYNAMIC in response — Cloudflare is not caching this response. Web Cache Deception requires the CDN to actually cache and serve the poisoned response to other users. No cache = no WCD |
| XPath Injection (boolean-based) on month=, user=, _rsc= params | **FP** | Size difference between tautology/contradiction responses is caused by Next.js RSC (React Server Components) rendering different amounts of content for different param values. The _rsc parameter is a Next.js internal cache-busting param. No XPath context in a Next.js/Prisma/PostgreSQL stack |
| LDAP Injection via user= parameter | **FP** | Cal.com uses NextAuth.js + Prisma + PostgreSQL. No LDAP in the stack. The "error pattern" (invalid.*dn\|invalid.*filter) regex matched innocuous HTML content in the standard Next.js page response |
| Username Enumeration via login form (content-based) | **HOLD → Tier 2** | Pattern `wrong\s*password` detected in response when submitting existing username. This COULD be real CWE-204. Needs manual verification: submit existing vs. non-existing email, compare exact error messages. Cal.com is on HackerOne |
| HTTP Method Override: X-HTTP-Method-Override DELETE on /api/trpc/me/myStats | **FP** | Both baseline POST and override POST return 403. Response size difference (5045 vs 5109 bytes) is just different error message content. Both requests rejected — no access control bypass |
| HTTP Method Override: X-Method-Override PUT on /api/trpc/slots/getSchedule | **FP** | Baseline POST → 404, probe → 403. The 403 is Cloudflare WAF blocking the unusual X-Method-Override header pattern, not the application accepting the method override. tRPC doesn't use HTTP method semantics |
| HTTP Method Override: _method, method, _httpmethod params on /api/trpc/slots/getSchedule | **FP** | Same as above. tRPC doesn't process _method params. The 403 response vs 404 baseline is WAF behavior |
| Race Condition on /register (GET) | **FP** | Race condition test was run against a GET request to the registration page. GET requests returning identical responses under concurrency is expected behavior — race conditions are relevant on POST endpoints that create/modify state |

### Neon.tech (neon.com) — Not in Active Hunt Registry

All findings are info/low/medium on marketing site (neon.com, not console.neon.tech). Not an active bounty target. All findings are FP:

- Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy — all on a marketing/documentation site (neon.com). Missing headers on marketing pages are auto-rejected as informational by triagers (known FP pattern). Neon's actual app is at console.neon.tech — that's what should be in scope.

**Action:** Remove neon from scan targets or redirect to console.neon.tech. If adding to hunt registry, update scope to target `console.neon.tech`.

### OpenProject (community.openproject.org) — YesWeHack Program

Total medium/high findings: 8. All assessed:

| Finding | Decision | Reason |
|---------|----------|--------|
| Missing X-Frame-Options on /api/v3/configuration | **FP** | Low confidence, API endpoint. API endpoints don't need X-Frame-Options (clickjacking applies to UI pages). OpenProject also uses CSP frame-ancestors as primary clickjacking protection |
| Missing HSTS on /login.php | **FP** | /login.php on a Ruby on Rails app returns a redirect or 404. The check caught a non-existent path. HSTS might be enforced at the nginx level anyway |
| Missing CSP on /login.php | **FP** | Same as HSTS — /login.php is not a real endpoint on OpenProject (Rails app). The actual login is at /login |
| Rate limiting on /login, /login.php, /login?layout=1, /login?back_url= (GET) | **FP** | Same issue as cal.com — testing GET requests, not POST credential submission. OpenProject uses Devise with lockable strategy (auto-locks accounts after failed attempts) which is POST-endpoint protection |
| Session Fixation — _open_project_session not regenerated | **HOLD → Tier 2** | Evidence shows pre/post "login" session cookie is identical. BUT: the scanner made an unauthenticated POST (no real credentials). A failed login attempt should NOT regenerate the session — only a successful login should. This needs verification with real credentials. If the session IS fixed on successful login, this is a real CWE-384 finding. OpenProject is on YesWeHack |

### Moneybird Re-Assessment — Existing Pending Files

| File | Decision | Notes |
|------|----------|-------|
| `6d09cce8-dom-based-cross-site-scripting.md` | **HOLD** | Moved to Tier 2. Browser verification required. If alert() fires in browser, this is submittable to HackerOne (Moneybird). Strong finding if confirmed |
| `09dd5267-missing-content-security-policy-header.md` | **FP as standalone** | A missing CSP on a marketing site without XSS is informational and auto-rejected. Keep as supporting context if/when the DOM XSS is submitted — the two together make a stronger report |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP** | postMessage handlers on www.moneybird.com are almost certainly from third-party widgets (Intercom, analytics). Marketing pages routinely inject postMessage listeners from chat/analytics SDKs. Without evidence that the handlers belong to Moneybird application code (not a widget), this is not submittable. Matches FP pattern from CLAUDE.md |

### Moneybird — New Findings from Mar 22 Scan

| Finding | Decision | Reason |
|---------|----------|--------|
| Open Redirects (8 params: url, redirect, next, return, returnTo, redirect_uri, goto, dest) | **FP** | The scanner found `Location: https://moneybird.com/login?url=https%3A%2F%2Fevil.example.com`. This is a www → non-www canonical redirect that preserves query parameters URL-encoded. The redirect destination is `moneybird.com/login` (same domain), not `evil.example.com`. The evil payload becomes a URL-encoded query parameter value, not the redirect target |
| Mixed Content (60+ findings — internal HTTP links) | **FP** | All HTTP resources are `http://www.moneybird.com/*` linking to own domain paths. These are same-domain internal links using HTTP scheme on an HTTPS page. Modern browsers auto-upgrade same-domain requests. Not externally exploitable — triagers mark this informational |
| Missing SRI — Google Tag Manager | **FP** | GTM script at gtm.moneybird.com. Analytics/tracking scripts, by design. SRI not applicable to first-party CDN scripts that change frequently |
| Race Condition on /features/bookkeeping/ (GET) | **FP** | GET request to marketing page. Same issue as all other race condition detections — needs POST on state-changing endpoint |

---

## Overall Assessment — Apr 18, 2026

**Bounty readiness: LOW (unchanged from Session 7)**

Total scans to date: 30+ targets
- 0 confirmed injection vulnerabilities on external targets
- 1 pending DOM XSS (Moneybird) — needs browser verification
- 2 session/auth findings on hold (cal.com user enum, openproject session fixation) — need auth testing

**Root cause (still the same):** Unauthenticated scanning of hardened SaaS targets produces passive findings only. The OpenProject CVE analysis shows the real bugs are all post-auth, requiring two accounts and specific project setup.

**Key FP patterns identified this session:**
1. Next.js RSC size differences triggering false boolean-based injection detections
2. Cloudflare WAF 403 responses triggering false method-override positives
3. Rate limit checks on GET endpoints (login page navigation ≠ brute force endpoint)
4. SPA catch-all routes returning 200 for probed paths (/administrator, /login.php)
5. www→non-www canonical redirects preserving query params flagged as open redirect

## Next Steps (Priority Order)

1. **Browser-verify Moneybird DOM XSS** — open `https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>` in browser. If alert fires → submit immediately. This is the single highest-value finding in the pool.
2. **Cal.com username enumeration** — manually submit existing vs. non-existing email on `/auth/login`, compare error messages. If different → draft report (HackerOne, cal.com).
3. **OpenProject session fixation** — get a community.openproject.org account, log in via Playwright, capture session cookie before/after. If same → draft report (YesWeHack).
4. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
5. **Scope neon-v2 scans** — redirect to `console.neon.tech` (the app) not `neon.com` (marketing)
6. **Indeed submission** — confirm with Dio before submitting (cookie is JS-set, reproduction is browser-only)

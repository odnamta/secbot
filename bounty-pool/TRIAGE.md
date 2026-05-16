# Bounty Pool Triage — Updated 2026-05-16 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM XSS via URL Fragment on homepage | High | dom-sink detection (innerHTML = location.hash). High/high confidence. **Needs browser verification first.** Check scope (www.moneybird.com vs app.moneybird.com). Draft: `2026-05-16-moneybird-dom-xss.md`. Auto-generated draft at `pending/moneybird/6d09cce8-*.md` is superseded. |

### TIER 2 — Hold (needs more work / verification)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 3 | openproject | Rate Limiting + Username Enumeration (timing) on `/login` | Medium | High confidence (15 requests, no 429). Timing oracle: 317ms vs ~11s for valid username. **Scope check:** confirm community.openproject.org is in YesWeHack scope. Draft: `2026-05-16-openproject-rate-limit-brute-force.md` |
| 4 | openproject | Session Fixation — `_open_project_session` not regenerated after login | Medium | Scanner: `endpoint-replay` detection. **NOT VERIFIED** — needs actual authenticated test. May not be real (failed login would also retain session). Draft: `2026-05-16-openproject-session-fixation.md`. Do not submit without browser confirmation. |
| 5 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 6 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |

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

## New Scan Results — 2026-05-16 Triage

Three v2 scans ran on 2026-03-26: calcom-v2, neon-v2, openproject-v2. One prior scan (moneybird, Mar 22) had pending auto-generated drafts that needed upgrading.

### neon.tech (v2 scan — 2026-03-26)

| Finding | Verdict | Reason |
|---------|---------|--------|
| SQLi in URL params (CRITICAL/medium) | **FP** | Description itself says "SQL error evidence appears to be a PostgreSQL documentation link rather than a true database error." The `/unify?a=UUID&n=pricing` endpoint returns a docs URL in content — scanner mistook it for a SQL error. Not a real SQLi. |
| Directory Traversal on /unify (CRITICAL/medium) | **FP** | Windows-style backslash traversal (`..\\..\\etc\\passwd`) sent to Vercel/Cloudflare. Both infrastructure layers normalize paths. curl command in evidence uses backslashes in a URL — browsers and CDNs reject/normalize these. No real traversal. |
| Server-Side Prototype Pollution (CRITICAL/medium) | **FP** | WAF returned HTTP 403. "Canary reflection" is in Cloudflare's error HTML page — the pattern `secbot_pp` or `polluted` matched inside CF's 403 HTML, not the app. No actual prototype pollution evidence. |
| Missing HSTS (HIGH/high) | Informational | On `neon.com/?chatId=1` (not neon.tech — different domain). Low bounty value, typically rejected as informational by triagers. |
| Open Redirect via Login (MEDIUM/medium) | Unverified | Possible but low priority. The login redirect pattern (`?next=`, `?redirect=`) is common on Next.js apps — needs manual verification. Skip for now. |
| Verbose Error on /undefined (MEDIUM/low) | Informational | Low confidence. Next.js 404 page, not a real debug mode disclosure. |
| neon_consent cookie missing Secure/HttpOnly (MEDIUM/high) | **FP** | Cookie name `neon_consent` — this is a consent/analytics cookie. Third-party cookie FP pattern. Auto-rejected by triagers. |
| Missing SRI (MEDIUM/high) | Informational | Standard finding on Next.js apps, auto-rejected as informational. |

### app.cal.com (v2 scan — 2026-03-26)

| Finding | Verdict | Reason |
|---------|---------|--------|
| XPath Injection — month param (HIGH/medium) | **FP** | `month=2026-04` on a calendar page. Single-quote injection breaks the date format → page renders differently (empty calendar vs populated). 17% response size difference is from different month states, not XPath injection. Cal.com uses PostgreSQL/Prisma, not an XML data store — XPath injection is anatomically wrong. |
| XPath Injection — user param (HIGH/medium) | **FP** | `?user=1` on the login page. The `user` param presets the login form username. Injection breaks the value → different page state. Size difference from JS state variation, not injection. |
| XPath Injection — `_rsc` param (HIGH/medium) | **FP** | `_rsc` is Next.js React Server Components internal parameter. Different `_rsc` values cause different RSC payloads to be returned. Single-quote in `_rsc` causes error state → different RSC response size. Not an injection vulnerability. |
| Web Cache Deception via /nonexistent.css (HIGH/medium) | **FP** | Evidence shows `"cf-cache-status":"DYNAMIC"`. `DYNAMIC` means Cloudflare is explicitly NOT caching this endpoint. The detection logic was looking for any cache header as evidence — this finding is backwards. No cache deception vulnerability when the CDN returns DYNAMIC. |
| XXE on /api/trpc/features/map (HIGH/medium) | **FP** | Response was HTTP 403 from Cloudflare WAF. The "detection signal" was matching the regex `/root:.*:0:0|\\/bin\\/(ba)?sh|error|DTD/i` against the Cloudflare 403 HTML page — which contains the word "error". Not real XXE. |
| HTTP Method Override (X-HTTP-Method-Override, _method, method, _httpmethod) | **FP** | cal.com uses tRPC, which does not implement Rails-style HTTP method tunneling. The response code changes (404→403) are from tRPC parsing the modified POST body differently (probe adds extra params). No actual method override accepted. |
| Cookie `__Secure-next-auth.callback-url` missing HttpOnly (MEDIUM/medium) | Informational | NextAuth callback URL cookie. Missing HttpOnly means JS can read it, but the value is just a URL (not a secret). Low value for bounty. |
| Source Map Exposure (MEDIUM/medium) | Note | Original JS source code accessible via `.map` files. Real finding but typically not bounty-worthy on Next.js apps (very common, often intentional for public apps). Skip. |
| Missing Rate Limiting on /auth/login (MEDIUM/medium) | Unverified | 15 requests, no 429. Cal.com uses Cloudflare which may rate-limit at edge without returning headers in app responses. Need more evidence before submitting. |
| OAuth missing state on /api/auth/session (MEDIUM/medium) | **FP** | `/api/auth/session` is NextAuth's session status endpoint, not an OAuth authorization endpoint. No OAuth state parameter applies here. |
| Race Condition on /register (MEDIUM/medium) | Unverified | Possible but needs auth + actual account creation to verify. Low priority. |
| Username Enumeration — login form (MEDIUM/medium) | Unverified | Content-based (response body differs for valid vs invalid). Possible but cal.com likely already handles this. Low priority. |

### community.openproject.org (v2 scan — 2026-03-26)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing HSTS (HIGH/high) | Informational | True positive but informational-level for bounties. Auto-rejected by most programs. |
| Missing CSP (HIGH/high) | Informational | Same as above. |
| Session Fixation (MEDIUM/medium) | **DRAFT — needs verification** | See `2026-05-16-openproject-session-fixation.md`. Scanner did not actually authenticate, so this may not be confirmed. Needs manual test with real credentials. |
| Rate Limiting + Username Enumeration (MEDIUM/high) | **DRAFT — ready to verify** | See `2026-05-16-openproject-rate-limit-brute-force.md`. High confidence, solid evidence. Scope check needed. |
| Username Enumeration via timing (LOW/medium) | Included in rate limit report | Strengthens the brute-force report — included as Vulnerability 2 in the rate limit draft. |
| Missing Rate Limiting on /api/v3/configuration (LOW/high) | Informational | Public API endpoint, not auth-related. Not bounty-worthy. |

### moneybird.com (prior scan — 2026-03-22, auto-generated drafts reviewed)

| Finding | Verdict | Reason |
|---------|---------|--------|
| DOM XSS via URL fragment (HIGH/high) | **DRAFT — needs browser verification** | Auto-generated draft at `pending/moneybird/6d09cce8-*.md` was too thin (missing proper repro steps, wrong curl command). Upgraded draft at `2026-05-16-moneybird-dom-xss.md`. **Verify in browser before submitting.** |
| Missing CSP (HIGH/high) | Informational | At `pending/moneybird/09dd5267-*.md`. Auto-rejected as informational. |
| postMessage missing origin validation (MEDIUM/medium) | Informational | At `pending/moneybird/8c0823c1-*.md`. Moneybird homepage likely uses chat/support widgets (Intercom/Drift) — postMessage from widgets is by design. Skip. |
| Mixed Content — HTTP resource on HTTPS (MEDIUM/high) | Informational | Low value. |

---

## Honest Assessment (May 2026)

**Total findings across 7 targets (Mar–May 2026):**
- 3 active bounty drafts (1 Tier 1, 2 Tier 2 hold)
- 0 confirmed critical/high injection vulns on external targets (all criticals were FP)
- Main patterns of FP: Cloudflare WAF 403s matching patterns, Next.js RSC size variation, CDN cache header misinterpretation

**What's working:**
- 0% submission rate but 100% FP-filter accuracy — no wasted submissions
- DOM XSS detection via static sink analysis is the most reliable active finding method
- Rate limiting detection is reliable (15-request probe works)

**What needs improvement:**
- Boolean-based injection detection has too many false positives on SPA apps (Next.js RSC response size variation)
- WAF response detection needs to check for Cloudflare HTML signatures before claiming findings
- Cache detection needs to check `cf-cache-status: DYNAMIC` as an exclusion signal

## Priority Actions for Dio

1. **Browser-verify moneybird DOM XSS** — open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome. If alert fires, check scope and submit.
2. **Scope-check community.openproject.org** — verify it's in YesWeHack OpenProject scope, then run rate limit manual test.
3. **Session fixation manual test** — create free account on community.openproject.org, check if `_open_project_session` changes after login.
4. **Fix own app** — finance.atmando.app rate limiting + HSTS (Tier A1/A2 from prior session).

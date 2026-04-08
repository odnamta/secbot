# Bounty Pool Triage — Updated Apr 8, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Program | Notes |
|---|--------|---------|----------|---------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | HackerOne | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | app.cal.com | Username Enumeration via login form response discrepancy | Medium | HackerOne | Content-based: "wrong password" vs "user not found". No auth needed. Draft: `2026-04-08-calcom-username-enumeration.md` |
| 3 | app.cal.com | No rate limiting on 6 auth endpoints | Medium | HackerOne | /auth/login, /login, /signup, /register, /auth/forgot-password, /api/auth/session — 15/15 requests succeed, no 429. Draft: `2026-04-08-calcom-rate-limit.md` |
| 4 | community.openproject.org | No rate limiting on 4 login endpoints | Medium | YesWeHack | /login, /login.php, /login?back_url, /login?layout=1 — all unthrottled. Draft: `2026-04-08-openproject-rate-limit.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 5 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 6 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 7 | community.openproject.org | Session Fixation — `_open_project_session` not regenerated post-login | Medium | HOLD — scanner detected session cookie value unchanged before/after POST /login. Needs real credentials to confirm. Rails app should regenerate on login — if misconfigured this is CWE-384. |
| 8 | neon.tech | Open Redirect on /login via url/redirect/next/return/returnTo/redirect_uri/goto/dest params | Medium | NEEDS MANUAL VERIFICATION — scanner saw HTTP 308 from neon.tech/login → neon.com/login preserving query params (canonical domain redirect). Second hop (does neon.com/login act on the param?) unconfirmed. Must manually test: visit https://neon.tech/login?url=https://evil.example.com and follow all redirects to check final destination. Neon not in hunt registry — add if verified. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

---

## False Positives — Mar 26 Scans (Session 8)

### Cal.com (app.cal.com) — 10 FPs

| Finding | Reason |
|---------|--------|
| Source Map Exposure (_next/static/chunks/*.js.map) | Cal.com is open source (github.com/calcom/cal.com). Source maps expose nothing private — the full source code is already public. |
| XPath Injection — `month`, `user`, `_rsc` params | Next.js false positive. `_rsc` is a React Server Components internal param — different content sizes per request are expected. `month` varies because scheduling data changes by month. Size differences (12–17%) are not injection indicators. |
| Race Condition on /register | Scanner sent 10 concurrent GET requests, all returned 200 — declared "race condition." GET requests on a page are idempotent; of course they all succeed. Not a vulnerability. |
| XXE on /api/trpc/features/map | 403 response was a Cloudflare challenge HTML page. Pattern `/root|/bin|error|DTD/i` matched the word "error" in the CF HTML. Not an XXE. |
| LDAP Injection on /auth/login?user= | Response was a normal Next.js HTML page (`<!DOCTYPE html><html class="notranslate"...>`). The `invalid.*dn\|invalid.*filter` pattern matched something in the rendered HTML — not an LDAP error message. HIGH confidence on the scanner is wrong here. |
| HTTP Method Override (5 instances) | Baseline POST returned 403/404; override also returned 403. Getting 403 doesn't mean the override was "accepted" — the server rejected both. Not a vulnerability. |
| Web Cache Deception via /nonexistent.css | Response included `cf-cache-status: DYNAMIC` — Cloudflare explicitly did NOT cache this response. FP: dynamic status means the CDN is treating it as uncacheable. |
| OAuth missing state on /api/auth/session | `/api/auth/session` is a session data endpoint, not an OAuth authorization endpoint. Not relevant to OAuth CSRF. |
| Missing SRI on Intercom widget | `widget.intercom.io/widget/...` is a known third-party widget. SRI on vendor widgets is not a bounty-worthy finding — by design. |
| Missing HSTS/CSP headers | While real, these are typically auto-rejected as informational by HackerOne triagers at established companies with hardened infra. Low ROI. |

### Neon.tech (neon.tech / neon.com) — 4 FPs

| Finding | Reason |
|---------|--------|
| `neon_consent` cookie missing HttpOnly/Secure | "neon_consent" is a GDPR/cookie consent cookie. Third-party/analytics/consent cookies are a known FP pattern — not a security issue. |
| Missing SRI on neon.com/_next/static/ chunks | All 24 resources are self-hosted on neon.com (same domain). SRI is designed for third-party CDN resources — applying it to self-hosted assets is unusual and not required. |
| Verbose error "Database error details" on /undefined | neon.tech is a PostgreSQL-as-a-service company. References to "postgresql/tutorial" on their docs 404 page are completely expected content, not sensitive leakage. |
| Missing HSTS/CSP on marketing site | neon.tech is a marketing/docs site (not the console app). Missing headers on marketing pages are auto-rejected as informational. |

### OpenProject (community.openproject.org) — 2 FPs

| Finding | Reason |
|---------|--------|
| Missing HSTS header | Present on a community forum. While technically valid, missing HSTS on community forums is rarely bounty-worthy at the medium/high level claimed. Informational. |
| Missing CSP header | Same rationale as HSTS above. |

---

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Honest Assessment (Apr 8, Session 8)

**Progress:** 4 new Tier 1 candidates (up from 1 in Session 7). Still all passive/heuristic — no injections, no auth bypasses.

**Bounty readiness: LOW-MEDIUM.**
- 3 medium findings with clear curl-reproducible evidence
- 1 cookie finding (indeed) that needs browser reproduction
- All findings are auth-hardening issues (rate limits, enumeration) — often contested or triaged as low by large programs
- No auth scanning performed — missing a full class of higher-impact vulnerabilities

**Pattern across all scans:**
- Automated scanner is good at finding missing controls (rate limits, headers, enumeration)
- Scanner has FP issues with Next.js RSC params (XPath/SQLi detections), Cloudflare-fronted endpoints (XXE, LDAP), and method override detection logic
- Need authenticated scanning to surface IDOR, privilege escalation, and account-level vulnerabilities

**Recommended actions (priority order):**
1. **Submit cal.com rate limit + username enum** — no auth needed, curl-reproducible, small startup = faster triage
2. **Submit openproject rate limit** — YesWeHack program, Rails app with login variants
3. **Manually verify neon.tech open redirect** — follow the 308 chain to confirm second hop
4. **Get test credentials for T2 targets** — Twitch + OpenProject accounts to confirm T2 holds
5. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
6. **Add neon.tech to hunt registry** — if open redirect confirms, add as HackerOne target

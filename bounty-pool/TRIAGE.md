# Bounty Pool Triage — Updated 2026-04-29 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Platform | Draft |
|---|--------|---------|----------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | HackerOne | `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | kredivo.com | Unprotected WordPress admin login on blog.kredivo.com | High | RedStorm | `2026-04-29-kredivo-wordpress-login.md` |
| 3 | openproject | Missing rate limiting on login (community.openproject.org) | Medium | YesWeHack | `2026-04-29-openproject-rate-limiting-login.md` |

**Notes:**
- **Indeed CSRF:** Cookie set via JS, curl won't reproduce — needs Playwright/browser confirmation before submitting. Only submit if Dio confirms willingness.
- **Kredivo WordPress:** In-scope (blog.kredivo.com explicitly listed). HIGH confidence. Ready to submit. Verify with fresh `curl -sI https://blog.kredivo.com/wp-login.php` before sending.
- **OpenProject Rate Limit:** HIGH confidence (brute-force-probe detected, 15+ requests accepted with no 429). Ready to submit.

### TIER 2 — Hold (needs manual verification)

| # | Target | Finding | Severity | Platform | Draft | Reason |
|---|--------|---------|----------|----------|-------|--------|
| 4 | moneybird | DOM XSS via URL fragment on homepage | High | HackerOne | `pending/moneybird/6d09cce8-...xss.md` | Needs browser confirmation (fragment-based, curl can't verify); auto-verify level = dom-sink detection |
| 5 | openproject | Session fixation — `_open_project_session` not regenerated | Medium | YesWeHack | `2026-04-29-openproject-session-fixation.md` | Medium confidence — needs manual cookie comparison before/after login to confirm |
| 6 | calcom | Missing rate limiting on `/auth/login` | Medium | HackerOne | `2026-04-29-calcom-missing-rate-limiting-auth.md` | Medium confidence — verify by running 15+ rapid POST requests |
| 7 | calcom | Username enumeration via login form | Medium | HackerOne | `2026-04-29-calcom-username-enumeration.md` | Medium confidence — need to confirm exact response difference (message/timing) manually |
| 8 | twitch.tv | `server_session_id` + `api_token` missing HttpOnly | Medium | HackerOne | `2026-03-14-twitch-cookies.md` | HOLD — needs authenticated scan to verify these are actual auth tokens |
| 9 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | (own program) | `2026-03-14-bugcrowd-session-cookies.md` | Weak standalone; needs XSS chain; submitting to own program is bad optics |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite + empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

---

## False Positives Logged (Session 8)

### Cal.com (app.cal.com — HackerOne scope) — 2026-03-26 scan

| Finding | Reason |
|---------|--------|
| XPath Injection ×3 (month, user, _rsc params) | FP — Next.js/tRPC doesn't parse XPath. `_rsc` is a Next.js React Server Components param. Boolean-based detection fired on response differences unrelated to XPath. |
| XXE Injection via /api/trpc/features/map | FP — tRPC endpoints don't parse XML. The POST body with `Content-Type: application/xml` was likely rejected or ignored; 200 response was a false signal. |
| LDAP Injection — wildcard-filter-break | FP — Cal.com uses NextAuth + database auth, no LDAP directory integration. |
| HTTP Method Override ×4 (DELETE/PUT override headers) | FP — tRPC routes by procedure name not HTTP method. Override headers are ignored; the POST was processed normally, returning 200 regardless of X-HTTP-Method-Override header. |
| Web Cache Deception (/admin/30min?month=.../nonexistent.css) | Likely FP — /admin/ routes require authentication; an unauthenticated scanner receives a login redirect (not authenticated page content), so there's nothing sensitive to cache. Needs authenticated verification. |
| OAuth missing state param on /api/auth/session | FP — /api/auth/session is a session status endpoint, not an OAuth authorization endpoint. |
| Race Condition on /register | FP — Scanner sent 10 concurrent GET requests to a registration PAGE (not form submission). Of course all 10 return 200. Real test requires concurrent POST with same registration data. |
| SRI missing on external scripts | Informational — Cal.com is open-source; source map exposure is by design. Not a bounty finding. |
| Missing HSTS | Informational — Low bounty potential as standalone header finding on a mature SaaS. |

### Moneybird — 2026-03-22 scan

| Finding | Reason |
|---------|--------|
| postMessage handlers missing origin validation | FP — moneybird.com homepage includes third-party chat/marketing widgets (Intercom/Drift pattern). postMessage handlers from embedded widgets are by design, not a vulnerability (CLAUDE.md FP pattern). |
| Mixed Content: http://www.moneybird.com/artikelen/ | Informational — This is a plain `<a href>` link, not a subresource (script/CSS/image). Modern browsers don't block passive mixed content for link elements. CVSS overstated. Not bounty-worthy. |
| Missing CSP | Supporting evidence only — not a standalone bounty finding. Include as context if submitting DOM XSS report. |

### Neon.tech — 2026-03-26 scan (NOT in bounty registry)

| Finding | Assessment |
|---------|------------|
| SQLi on /unify (CRITICAL/MEDIUM, error-pattern) | Needs program discovery before any report. Also needs manual verification — error-pattern on a Next.js/marketing tech site is often a FP from framework error messages. |
| Directory Traversal on /unify (CRITICAL/MEDIUM) | Same — needs manual curl test: does the response actually contain /etc/passwd content? |
| Prototype Pollution via query param (CRITICAL/MEDIUM) | Same — property-injection detection is medium confidence; verify whether `__proto__[secbot_pp]` is actually reflected in responses. |
| Open Redirect on /login (MEDIUM/MEDIUM) | Same — verify that the redirect actually follows to evil.example.com. |
| Missing HSTS, SRI, neon_consent cookie | Informational / FP (neon_consent = analytics cookie). |

**Action:** Check if neon.tech has a public bug bounty program before proceeding. If yes, manually verify the critical findings.

### Kredivo (blog.kredivo.com) — 2026-03-22 scan

| Finding | Reason |
|---------|--------|
| Missing CSP on blog | Informational — blog subdomain, low bounty potential standalone. |
| Cookie `_hcc` missing HttpOnly/Secure | FP — `_hcc` is a third-party tracking/analytics cookie (HubSpot CTA cookie pattern). Not security-sensitive. |

### OpenProject (community.openproject.org) — 2026-03-26 scan

| Finding | Reason |
|---------|--------|
| Missing HSTS + CSP | Informational for a community forum — low standalone bounty potential on YesWeHack. May include as supporting context if submitting session fixation report. |

---

## OWN APPS — Fix These

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Unresolved — add Cloudflare rate limit + app throttle |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Unresolved — Docker rebuild or middleware debug |

---

## Honest Assessment (Apr 29)

**Bounty readiness: IMPROVING.** After Session 8 triage:
- 3 reports ready for submission (Kredivo WordPress, OpenProject rate limit, Indeed CSRF)
- 5 reports in T2 (need manual browser verification)
- FP rate remains 0% on confirmed submissions
- Active injection vulns (SQLi, XSS, traversal) still require authenticated scanning

**New this session:**
- 5 new draft reports created (Kredivo WordPress, OpenProject session fixation + rate limit, Cal.com rate limit + username enum)
- 24+ FPs correctly identified across 3 new scan targets
- Neon.tech flagged as potential new target (critical findings, needs program discovery + manual verification)

**Bottleneck unchanged:** Most interesting vulns (IDOR, injection) require authenticated scanning. WordPress admin brute-force (Kredivo) is the most concrete high-severity finding ready to ship.

## Next Steps (Priority Order)
1. **Submit Kredivo WordPress login report** — verify curl first, then submit to RedStorm
2. **Submit OpenProject rate limiting** — high confidence, ready now
3. **Manually verify T2 finds** — session fixation (OpenProject) and username enum + rate limit (Cal.com) need browser confirmation
4. **Check neon.tech program** — look up on H1/Bugcrowd/direct for bounty program, then manually verify SQLi/traversal/prototype pollution
5. **Fix own app** — rate limiting + HSTS on finance.atmando.app
6. **Indeed CSRF** — only submit if Dio confirms willingness (JS-set cookie, tricky to reproduce)
7. **Get test credentials** — Twitch account for auth scan to unlock T2 findings there

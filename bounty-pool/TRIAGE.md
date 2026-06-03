# Bounty Pool Triage — Updated 2026-06-03 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `pending/2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | app.cal.com | HTTP Method Override accepted on tRPC endpoints | High | `X-HTTP-Method-Override: DELETE` accepted on `/api/trpc/me/myStats` and slots endpoints. **Needs auth scan** — unauthenticated probe can't confirm whether override routes to a real DELETE handler. Cal.com uses tRPC and may not have method-override middleware. Low-confidence FP until auth-verified. |
| 5 | app.cal.com | Web Cache Deception on /admin/30min | High | `?month=2026-04/nonexistent.css` with WCD probe. Needs manual 2-session verification (confirm one user's cached auth'd response is served to another). The `/admin/30min` path appears to be a public booking page, not a protected admin page — likely FP. |

### TIER 3 — Archived (non-bounty / confirmed FPs)

Moved to `bounty-pool/archived/` or pending archive:

**Moneybird pending reports — all FPs:**
- `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` — **FALSE POSITIVE** confirmed in git commit 6aef881: browser URL-encodes the hash fragment (`#<img>` → `#%3Cimg%3E`), so innerHTML write is safe. No alert fired in Playwright verification. Report description was incorrect. Prompted a SecBot FP-fix in cycle 18.
- `pending/moneybird/09dd5267-missing-content-security-policy-header.md` — **INFORMATIONAL** — No CSP is informational for HackerOne programs without an active XSS to pair it with. Not bounty-worthy standalone.
- `pending/moneybird/8c0823c1-postmessage-handlers-missing-origin-validation.md` — **FP** — postMessage handlers without origin check match known FP pattern; likely Intercom/analytics chat widget handlers. Impact unverified; manual inspection required before any submission.

**Already archived (from Session 7):**
- shopify.com CORS /__dux — Non-exploitable (SameSite + empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

**New scans (2026-03-22 and 2026-03-26) — full FP sweep:**

| Target | Finding | Reason |
|--------|---------|--------|
| neon.tech | SQLi in /unify?a= | Analytics/tracking endpoint (a= is an anonymous ID). No error evidence. FP. |
| neon.tech | Directory traversal on /unify | Windows-style traversal (`\..\`) on Linux server. FP. |
| neon.tech | Prototype pollution /unify | Analytics endpoint, no reflection evidence. FP. |
| neon.tech | HSTS missing | Evidence URL is `neon.com` not `neon.tech` — wrong domain. FP. |
| neon.tech | Cookie neon_consent flags | Consent cookie — intentionally JS-accessible. FP. |
| neon.tech | SRI missing | Informational. |
| app.cal.com | XPath injection (month, user, _rsc params) | Next.js/Node.js app doesn't use XPath. `_rsc` is a React Server Components param. FPs. |
| app.cal.com | XXE injection | Node.js app, no XML processing. FP. |
| app.cal.com | LDAP injection | Cal.com has no LDAP integration. FP. |
| app.cal.com | Source maps exposed | Cal.com is open source (github.com/calcom/cal.com). Source map exposure is not a vulnerability. FP. |
| app.cal.com | OAuth state parameter missing on /api/auth/session | `/api/auth/session` is NextAuth's session check, not an OAuth authorization endpoint. FP. |
| app.cal.com | Rate limit missing on /api/auth/session | Session check endpoints don't require rate limiting. FP. |
| app.cal.com | Race condition on /register | Concurrent page loads detected, not actual account creation race. FP. |
| app.cal.com | Username enumeration (login form) | Low impact for scheduling app; public calendar links already reveal usernames. |
| app.cal.com | Cookie __Secure-next-auth.callback-url missing HttpOnly | SameSite=Lax + Secure prefix mitigates. Low impact. |
| blog.kredivo.com | WordPress login exposed (/wp-login.php) | Default WordPress behavior on a blog subdomain. Out of scope for Kredivo BBP; informational even if in scope. |
| blog.kredivo.com | Cookie _hcc missing flags | HubSpot chat cookie (`_hcc`). Third-party analytics FP. |

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Session 8 Summary (2026-06-03)

**Scans triaged this session:** 7 scan results (moneybird, cal-com, calcom-v2, kredivo, neon-v2, openproject, openproject-v2)

**Bounty readiness: LOW (unchanged from Session 7).**

- 0 new critical/high vulnerabilities on external targets
- Moneybird DOM XSS (the most promising-looking pending report) confirmed FP in cycle 18 fix
- neon.tech "critical" findings are analytics-endpoint FPs from v2 engine — need tuning
- cal.com has interesting method-override and WCD signals but both require auth verification
- All passive findings (headers, cookies, SRI) across all targets remain non-bounty-worthy

**Root cause of FP-heavy results:**
The v2 scan engine (fast HTTP engine + template-based checks) is generating more FPs than v1 on these targets. Checks that trigger on response patterns without actual proof of exploitation (no error message shown, no data leak confirmed) need to be tightened.

**What we learned:**
- `/unify` endpoints with analytics params (`a=UUID&n=pagename`) will trigger SQLi/traversal/PP FPs — add to pre-filter
- tRPC endpoints (`/api/trpc/*`) will accept any POST body, making method-override appear "accepted" — need to verify route actually changes
- Moneybird DOM XSS: hash fragment encoding behavior was a genuine SecBot bug, now fixed (cycle 18)

---

## Next Steps (Priority Order)
1. **Submit Indeed CSRF report** — only if Dio confirms willingness (reproduction requires browser, not curl)
2. **Auth scan on cal.com** — verify method override impact with a real account (free signup available)
3. **Auth scan on Twitch** — need Twitch account, unlock T2 findings
4. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
5. **Tune v2 engine FP patterns** — `/unify`-style analytics endpoints, tRPC method override, race condition on page loads
6. **OpenProject local Docker testing** — see OPENPROJECT-CVE-ANALYSIS.md for CVE test plan; Docker setup ready

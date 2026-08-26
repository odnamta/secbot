# Bounty Pool Triage — Updated 2026-08-26 (Session 9)

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
| 4 | openproject | Session Fixation: _open_project_session not regenerated | Medium | Scan detected same session cookie pre/post login on `community.openproject.org/login?layout=1`. **CAVEAT:** Scanner had no credentials — POST without valid credentials = failed login = session regeneration not triggered. Need authenticated test to confirm. Community instance is fully patched — test against local Docker (see OPENPROJECT-CVE-ANALYSIS.md). |

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

## Session 8 Analysis — March 26, 2026 Scans (Triaged 2026-06-13)

Three new v2 scans processed: **cal.com**, **neon.tech**, **openproject** (all 2026-03-26).
Also reviewed: moneybird (2026-03-22).

### Cal.com (HackerOne) — `scan-results/calcom-v2/secbot-2026-03-26T08-17-21-602Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| `__Secure-next-auth.callback-url` missing HttpOnly | **FP** | Stores post-login redirect URL, not auth token. Not sensitive. |
| Missing CSP on /signup | **Informational** | Auth pages (login) have nonce-CSP; /signup inconsistently missing. Not exploitable standalone, but noteworthy inconsistency. Not submittable without XSS proof. |
| Missing HSTS on /administrator | **FP** | /administrator returns 404; 404 handler has different header set. |
| Source Map Exposure on `_next/static/chunks/` | **FP** | Cal.com is MIT open source on GitHub. Source maps expose nothing not already public. |
| Missing SRI for Intercom widget | **FP** | Third-party analytics/chat widget. SRI not applicable for CDN scripts that auto-update. |
| Rate limiting on GET /auth/login, /login, /signup, /register, /forgot-password, /api/auth/session | **FP** | Scanner fires 15 GET requests at page-load endpoints. Rate limiting applies to POST auth submissions, not page loads. No POST credential test performed. |
| OAuth missing state on /api/auth/session | **FP** | Wrong endpoint — `/api/auth/session` is NextAuth's current-session getter, not an OAuth authorization endpoint. |
| Web Cache Deception via /admin/30min | **FP** | Response shows `cf-cache-status: DYNAMIC`. DYNAMIC = not cached by Cloudflare = WCD not exploitable. |

### Neon.tech (NOT in hunt registry) — `scan-results/neon-v2/secbot-2026-03-26T13-22-18-825Z.json`

**Note:** neon.tech is not in `hunt-registry.yaml`. Findings noted for completeness but no bounty action.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Open redirects via url/redirect/next/return/returnTo/redirect_uri/goto/dest params on /login | **FP** | Evidence: `Location: https://neon.com/login?url=...evil...` — redirect target is `neon.com` (same org), NOT `evil.example.com`. Scanner detects redirect parameter being forwarded, not an actual open redirect. |
| `neon_consent` cookie missing HttpOnly/Secure | **FP** | `_consent` suffix = GDPR consent cookie. Consent widgets intentionally expose these to JS for state management. Classic FP pattern. |
| Missing CSP on neon.com marketing page | **FP** | Marketing site homepage. Auto-rejected as informational by triagers. |
| Missing HSTS on `neon.com/?chatId=1` | **FP** | Parameterized chat widget URL. If other pages have HSTS, this is a scanner artifact not a real gap. |
| Missing SRI (24 external resources) | **FP** | 24 external scripts without SRI = common pattern for SaaS marketing sites. Not exploitable without a XSS vector. |
| Verbose error on `/undefined` endpoint | **Artifact** | URL is literally "undefined" — JavaScript `undefined` leaking into a URL during crawl. Not a real endpoint. Response details are scanner noise, not real server error exposure. |

### OpenProject (YesWeHack) — `scan-results/openproject-v2/secbot-2026-03-26T08-07-04-707Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing HSTS/CSP on /login.php | **FP** | OpenProject is a Rails app. `/login.php` → 404. 404 handler doesn't include security headers set on main app. Scanner is probing non-existent PHP page. |
| Rate limiting on GET /login, /login?back_url=..., /login?layout=1 | **FP** | GET page-load probes only. Same false-positive as cal.com rate limit findings. |
| Session Fixation: `_open_project_session` not regenerated | **HOLD** | Pre-login and post-login cookie values match. BUT: scanner had no credentials — failed login (no creds) = session not regenerated by design. Need authenticated test to confirm. Move to Tier 2. |

### Moneybird (HackerOne) — `scan-results/moneybird/secbot-2026-03-22T12-37-45-339Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP on www.moneybird.com | **FP** | Marketing homepage. Triagers auto-reject header findings on marketing pages. |
| Mixed Content: http://www.moneybird.com/artikelen/ (and 10+ others) | **Informational** | Same-domain http:// href links on HTTPS page. If Moneybird has HSTS (they do), browser auto-upgrades. No actual insecure request made. Weak finding, likely informational. |

---

## Session 9 Analysis — Aug 26, 2026 (No new scans; catch-up triage)

Two previously unreviewed datasets processed: **kredivo** (scan from 2026-03-22, missed in all prior sessions) and **cal.com v2** (injection-type findings missed by session 8's triage of the same calcom-v2 JSON). Moneybird pending reports also reassessed.

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `blog.kredivo.com` (Kredivo's WordPress blog subdomain, NOT the main app)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP, X-Frame-Options, other headers | **FP** | All header findings are on HTTP 403 responses from nginx WAF. Headers measured on the WAF block page, not the real application. |
| Cookie `_hcc` missing HttpOnly/Secure | **FP** | `_hcc` is an internal CDN/WAF session cookie (Cloudflare or similar). Not an auth token. Matches known CDN cookie naming patterns. |
| Rate limiting on `GET /login` | **FP** | GET page-load probe only. Standard scanner FP — same pattern as cal.com session 8. |
| WordPress login at `/wp-login.php` | **Informational / Out-of-scope** | `blog.kredivo.com` is a blog subdomain running WordPress. Exposed WordPress login is expected behavior for any WP site. Not in Kredivo's main app scope (RedStorm program targets financial app, not blog). |

**Verdict for kredivo scan: 0 submittable findings. All noise.** Scan targeted the wrong subdomain (blog vs. main app).

---

### Cal.com v2 — Missed injection findings (session 8 gap)

Session 8 reviewed only the passive/header findings from `calcom-v2/secbot-2026-03-26T08-17-21-602Z.json`. The following active-check findings were missed and are now triaged:

| Finding | [Sev][Conf] | Verdict | Reason |
|---------|-------------|---------|--------|
| LDAP Injection — Error-Based, `user` param | [HIGH][high] | **FP** | Payload `*)(objectClass=*` on `auth/login?user=1`. Response is standard Next.js HTML — the regex pattern `invalid.*dn\|invalid.*filter` matched UI text or Next.js build artifacts in the page body, NOT an actual LDAP error. Cal.com uses NextAuth.js + database auth, not LDAP. No LDAP error in response. |
| XPath Injection — Boolean-based, `month` param | [HIGH][medium] | **FP** | 17% response size difference between tautology and contradiction payloads. The `month` parameter controls the calendar view (`?month=2026-04`) — different months render different booking data, naturally producing large response size deltas. Not injection. |
| XPath Injection — Boolean-based, `user` param | [HIGH][medium] | **FP** | 12% size difference on `/auth/login?user=1`. Dynamic login page content varies by user presence; size diff is normal for a Next.js SSR app, not injection. |
| XPath Injection — Boolean-based, `_rsc` param | [HIGH][medium] | **FP** | `_rsc` is a Next.js React Server Components internal routing parameter. Scanner injected SQL into a framework-internal param. Size difference is RSC route behavior. |
| HTTP Method Override — DELETE via `X-HTTP-Method-Override` | [HIGH][medium] | **FP** | Baseline POST → 403, probe POST+method-override → 403. No change in response status — server blocks both. Different response body size is from different error messages, not a bypass. |
| HTTP Method Override — PUT/DELETE via body params | [HIGH][medium] | **FP** | Baseline POST → 404, probe → 403. Server recognizes the override header/param and correctly returns 403 (auth check fires). This is intended behavior, not privilege escalation. |
| XXE — Parameter entity, `/api/trpc/features/map` | [HIGH][medium] | **FP** | Response is HTTP 403 Cloudflare HTML error page. The `<!DOCTYPE html>` and IE conditional comments (`<!--[if lt IE 7]>`) in the Cloudflare 403 page triggered the DTD/XXE detection regex. Not real XXE. |
| Username Enumeration — content-based | [MEDIUM][high] | **Informational** | Pattern `wrong\s*password` detected in login response for probe username `admin`. Likely real (login form distinguishes wrong password from unknown user) but accepted as informational on HackerOne. Low bounty priority. |

**Cal.com v2 injections: All FP.** Session 8 was correct to triage the surface findings; these active-check findings confirm no exploitable injection on app.cal.com.

---

### Moneybird Pending Reports — Reassessment

Three pending reports in `bounty-pool/pending/moneybird/`:

| Report | Verdict | Reason |
|--------|---------|--------|
| DOM XSS via URL Fragment | **FP — Archived** | Browser URL-encodes fragment content: `#<img...>` → `#%3Cimg...>`. The `innerHTML` sink receives `%3C` (encoded), not `<` (raw). `xss.ts:1290-1294` (commit `6aef881`) explicitly requires unencoded `<>` in innerHTML sinks before reporting XSS — this finding was generated before that fix. Not a real XSS. Report moved to `archived/`. |
| postMessage Without Origin Check | **FP — Archived** | [LOW][medium]. No evidence of handler impact. Likely a third-party widget (HubSpot/Intercom). Too vague to submit. Pending copy deleted; archived copy retained for reference. |
| Missing CSP (moneybird) | **Informational** | Marketing homepage. If DOM XSS is confirmed and submitted, include missing CSP as supplementary evidence of elevated severity. Do not submit standalone — triagers auto-reject header findings on marketing pages. |

---

## Honest Assessment (Aug 2026, Session 9)

**Bounty readiness: Still LOW.** No new scans since March 2026 (5 months of no data). This session caught up on untriaged data from existing scans:
- Kredivo blog scan: 0 findings (wrong subdomain + WAF)
- Cal.com v2 injection findings (missed by session 8): All confirmed FP
- Moneybird DOM XSS: Unconfirmed, needs browser test

**The pattern holds:** Unauthenticated scans against hardened targets yield passive findings only. Injection findings from these scans are all FP from pattern-matching on dynamic content or WAF error pages.

**One actionable item:** The Moneybird DOM XSS report in pending/ could be worth submitting if manually verified. This requires 5 minutes in a browser tab — low effort, possible medium bounty.

---

## Next Steps (Priority Order)

1. **Submit Indeed finding** — CSRF cookie inconsistency (unchanged). Cookie is JS-set so needs Playwright reproduction before submitting.
3. **Run new scans** — Hunt registry targets haven't been scanned since March 2026. Schedule `secbot hunt` or manual scan of kredivo.com (main app, not blog), moneybird.com/app, cal.com (authenticated).
4. **Authenticate Twitch** — Twitch Tier 2 cookie findings remain on hold pending credentials.
5. **OpenProject Docker test** — Highest ROI path to a confirmed finding (22 documented CVEs with exact endpoints). Still unchanged from March.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

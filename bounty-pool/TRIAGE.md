# Bounty Pool Triage — Updated 2026-08-29 (Session 9)

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

## Session 9 Analysis — Moneybird Pending Files + Kredivo (Triaged 2026-08-29)

Three auto-generated pending files in `bounty-pool/pending/moneybird/` were not addressed in Session 8.
Also triaging the Kredivo scan (`scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`) for the first time.

### Moneybird Pending Files — `bounty-pool/pending/moneybird/`

| File | Finding | Verdict | Reason |
|------|---------|---------|--------|
| `09dd5267-missing-content-security-policy-header.md` | Missing CSP on www.moneybird.com | **FP** | Marketing homepage. Already noted in Session 8. Auto-rejected by triagers. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | postMessage handlers without origin check | **FP** | Handler snippet: `pageX/pageY/clientX/clientY/preventDefault/stopPropagation` — this is a mouse-event polyfill (pointer events compatibility shim), not a sensitive data handler. CLAUDE.md FP pattern matches. |
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | DOM XSS via URL fragment on www.moneybird.com | **HOLD** | SecBot Playwright detected `innerHTML-set` sinks firing on `#<img src=x onerror=alert("secbot-xss-37")>`. Detection method: `dom-sink` (auto-verified in browser). However: (1) confidence=medium in scan JSON (pending file incorrectly shows "high"), (2) www.moneybird.com is marketing page — impact depends on cookie scope, (3) needs manual browser verification. Keep in pending. |

**Moneybird open redirects** (found in scan, not auto-drafted into pending):

| Finding | Verdict | Reason |
|---------|---------|--------|
| Open Redirect via "url"/"redirect"/"next"/"return"/"returnTo"/"redirect_uri"/"goto"/"dest" params [medium/high] on /login | **FP** | Evidence shows `Location: https://moneybird.com/login?url=https%3A%2F%2Fevil.example.com` — the evil URL is forwarded as a *query parameter to the login page*, not as the redirect destination. Same FP pattern as neon.tech (Session 8). |
| Race Condition on /features/bookkeeping/ [medium/medium] | **FP** | 10 concurrent GET requests to a static marketing page all return 200 with identical content. Expected behavior for a CDN-served static page. Race conditions only apply to state-changing endpoints. |

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Target:** `blog.kredivo.com` (their marketing blog, not the main lending app)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP [high/medium] on blog.kredivo.com | **FP** | All requests returned **HTTP 403** (WAF/CDN block). Security headers are missing from the 403 error page, not from the actual application. Scanner is measuring the CDN block page, not the app. |
| Missing X-Frame-Options [medium/low] | **FP** | Same as above — 403 block page artifact. |
| Missing X-Content-Type-Options [low/low] | **FP** | 403 block page artifact. |
| Missing Referrer-Policy [low/low] | **FP** | 403 block page artifact. |
| Missing Permissions-Policy [info/low] | **FP** | 403 block page artifact. |

**Note:** `blog.kredivo.com` blocked the scanner entirely (HTTP 403 on all requests, including root). All 10 pages crawled were error/sitemap responses. No app functionality was reachable. The Kredivo main app (`app.kredivo.com` or `kredivo.com`) was not in this scan — the hunt runner targeted the blog subdomain. Update the scope file to point at the actual app.

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

## Honest Assessment (Aug 2026, Session 9)

**Bounty readiness: Still LOW.** Session 9 cleared the backlog of auto-generated pending files — 4 more FPs identified, 1 HOLD confirmed (moneybird DOM XSS). Pattern unchanged:
- 0 injection vulnerabilities confirmed submittable
- Kredivo blog blocked scanner entirely — wrong subdomain targeted
- Moneybird DOM XSS on marketing page is technically real but needs human validation
- All open redirect findings continue to be same-domain redirect FPs

**Root cause unchanged:** Unauthenticated scan + wrong subdomains (blog/marketing) = passive findings only.

**Session 9 net result:** 0 new drafts. 1 HOLD (moneybird XSS). 4 FPs cleared.

**Bright spot:** OpenProject CVE analysis (`OPENPROJECT-CVE-ANALYSIS.md`) documents 22 real CVEs
with exact endpoints and payloads. The path forward is a local Docker test → authenticated scan.

---

## Next Steps (Priority Order)

1. **Verify moneybird DOM XSS manually** — Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in a browser and confirm alert fires. If confirmed, check whether `.moneybird.com` cookies are accessible (check DevTools → Application → Cookies for domain scope). Submit as Low if cookies not accessible, Medium if they are.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Fix Kredivo scope** — Update `scopes/kredivo.txt` to target `kredivo.com` or the main lending app, not `blog.kredivo.com`. The blog subdomain is 403-blocked by the CDN.
4. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
5. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

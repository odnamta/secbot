# Bounty Pool Triage — Updated 2026-07-01 (Session 9)

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

## Session 9 Analysis — Kredivo Scan (Triaged 2026-07-01)

One previously unprocessed scan: **blog.kredivo.com** (scan date 2026-03-22).
File: `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`
Target is IN SCOPE per `scopes/kredivo.txt`. Program: RedStorm.

14 raw findings, 3 interpreted findings. Scan was unauthenticated. No new bounty reports drafted.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP header on blog.kredivo.com | **FP** | WordPress blog/marketing site. Triagers auto-reject header findings on blog/marketing subdomains. |
| Missing X-Frame-Options on blog.kredivo.com | **FP** | Same as above — blog, not the app. |
| Missing X-Content-Type-Options / Referrer-Policy / Permissions-Policy | **FP** | Blog headers. Informational only. |
| Missing COOP / COEP / CORP headers | **FP** | Blog. These cross-origin isolation headers are informational for non-app pages. |
| Cookie `_hcc` missing HttpOnly and Secure | **FP** | `_hcc` = HubSpot chat cookie (third-party analytics/marketing widget). JS-accessible by design. Classic FP pattern. |
| HSTS not eligible for preload | **Informational** | HSTS exists (`max-age=31536000`) but lacks `includeSubDomains; preload`. Not a vulnerability. |
| WordPress login page (/wp-login.php) exposed | **FP** | WordPress login pages are publicly accessible by design. Exposure alone is not a vulnerability. Submitting "wp-login.php returns 200" is auto-rejected by every program. |
| Missing rate limiting on /login | **FP** | Scanner fired 15 GET requests at `/login` (a redirect, not an auth endpoint). WordPress auth happens via POST `/wp-login.php`. GET page-load probe returning 200 does not prove missing brute-force protection. No POST credential stuffing test performed. |

**Key observations:**
- All 8 finding categories are FP or informational
- Scan hit `blog.kredivo.com` (WordPress blog), NOT the high-value targets: `app.kredivo.com` or `mysandbox.kredivo.com`
- The AI reporter over-rated the WordPress login finding as CVSS 8.1 — actual standalone severity is informational
- Real vulnerabilities require authenticated scan of `app.kredivo.com` (fintech BNPL app)

---

## Honest Assessment (Jul 2026, Session 9)

**Bounty readiness: Still LOW.** Session 9 processed the kredivo blog scan — same pattern as all previous sessions:
- 0 injection vulnerabilities found across all 9 sessions
- All findings are passive (headers, cookies on blog/marketing pages) — none submittable
- Kredivo blog scan: 8 FP/informational findings, 0 bounty-worthy
- No authenticated scanning performed on any target (again)

**Cumulative status across Sessions 1–9:**
- Targets scanned: indeed, twitch, bugcrowd, shopify, konghq, gitlab, cal.com, neon.tech, openproject ×2, moneybird ×2, kredivo (blog)
- Tier 1 pipeline: 1 finding (Indeed CSRF cookie — drafted, awaiting Dio's submit decision)
- Tier 2 holds: 3 findings (Twitch tokens, Bugcrowd cookies, OpenProject session fixation — all need auth)
- Injection-class vulnerabilities found: 0

**Pattern diagnosis:** Unauthenticated stealth scans consistently surface only passive header/cookie findings. These score high on CVSS in the AI report but are universally rejected by triagers. Real bounties require app-level access with valid session cookies.

**Bright spot:** OpenProject CVE analysis (`OPENPROJECT-CVE-ANALYSIS.md`) documents 22 real CVEs with exact endpoints and payloads. Local Docker test is still the highest-ROI unblocked action.

---

## Next Steps (Priority Order)

1. **Submit Indeed finding** — CSRF cookie inconsistency. Draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md`. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
2. **Scan app.kredivo.com** — Blog was scanned (all FP), but the actual BNPL app was not. Free account creation → `secbot scan https://app.kredivo.com --auth-cookie "..."`. BNPL apps often have IDOR in loan/transaction APIs.
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to determine if `server_session_id`/`api_token` cookies are real auth tokens (Tier 2 hold).
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. Highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Active HackerOne program with real auth (console.neon.tech). PostgreSQL-as-a-service = API surface with potential IDOR in project/database management.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March, carried forward 3 sessions).

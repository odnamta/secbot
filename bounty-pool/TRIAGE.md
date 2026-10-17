# Bounty Pool Triage — Updated 2026-10-17 (Session 9)

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

## Session 9 Analysis — March 2026 Kredivo Scan (Triaged 2026-10-17)

**Context:** No new scans have been run since March 2026. This session processes the previously unreviewed Kredivo scan (`scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`). Scan gap: 7 months (March → October 2026). AnyTask was in `hunt-registry.yaml` but has no scan results — was never scanned.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `blog.kredivo.com` (WordPress blog, in scope per `scopes/kredivo.txt`). Scanner was partially WAF-blocked (root returns HTTP 403), 10 pages scanned.

| Finding | Severity | Verdict | Reason |
|---------|----------|---------|--------|
| Exposed WordPress Login Page (/wp-login.php) Without Protection | High (CVSS 8.1) | **FP** | Standard WordPress behavior — `/wp-login.php` is publicly accessible on virtually all WordPress installs. This is a blog site, not the main fintech app. RedStorm triagers would reject as "by design" / informational. Not worth submitting. |
| Missing Content-Security-Policy Header | High (CVSS 7.0) | **FP** | Marketing/blog site. Auto-rejected as informational. Same pattern as moneybird, konghq, cal.com marketing pages. |
| Cookie `_hcc` Missing HttpOnly and Secure | Medium (CVSS 5.3) | **FP** | `_hcc` is an Automattic CDN anti-bot challenge cookie (`server-timing: a8c-cdn`, 30-second expiry, value encodes requester IP + timestamp). Issued only on the HTTP 403 WAF block; JS must read it to solve the challenge, so no HttpOnly is by design. Not an application auth cookie; not bounty-worthy. |

**Kredivo scan summary: 0 submittable findings.** The scanner was probing a WordPress blog (not the main fintech app at `app.kredivo.com`). All findings are either standard WordPress/blog-site patterns or third-party CDN/analytics cookies. The main app and sandbox (`mysandbox.kredivo.com`) remain unscanned — those are the actual targets with bounty potential.

---

## Honest Assessment (Oct 2026, Session 9)

**Bounty readiness: Still LOW.** Seven months since last scan, same structural problem:
- 0 injection vulnerabilities found across all scans (XSS, SQLi, SSTI, SSRF, RCE)
- All "high/medium" findings are passive (headers, cookies) — none submittable
- Rate limiting findings continue to be GET-probe FPs (scanner probes page loads, not POST auth)
- Open redirect findings continue to be same-org redirect FPs
- No authenticated scanning performed on any target (ever)
- AnyTask has never been scanned despite being in hunt-registry.yaml since March 2026

**Root cause unchanged:** Unauthenticated scan + hardened targets = passive findings only. The scan surface is the login page, not behind it.

**7-month scan gap is the real problem.** The hunt agent hasn't run new scans since March 2026. Weekly scans are scheduled in the registry but not executing. This needs to be investigated.

**Bright spot:** OpenProject CVE analysis (`OPENPROJECT-CVE-ANALYSIS.md`) documents 22 real CVEs
with exact endpoints and payloads. The path forward is a local Docker test → authenticated scan.

---

## Next Steps (Priority Order)

1. **Set up an external scan scheduler** — No scans since March 2026 (7 months). `schedule: weekly` in `hunt-registry.yaml` only gates the `isDue()` check inside `secbot hunt`; it does not self-schedule the command. There is no cron or GitHub Actions workflow running `secbot hunt`. Configure one: a GitHub Actions schedule (`cron: '0 1 * * 1'`) or a VPS cron that runs `npx secbot hunt --registry hunt-registry.yaml` weekly. This is the top priority.
2. **Scan main Kredivo app** — `app.kredivo.com` and `mysandbox.kredivo.com` are the actual fintech targets. The scanner only hit the blog. Update the scope file or run a targeted scan: `npx secbot scan https://app.kredivo.com --profile stealth`.
3. **Scan AnyTask** — Never been scanned. `anytask.com` is a freelancer marketplace (Bugcrowd, $250-$5,000). Run: `npx secbot scan https://anytask.com --profile stealth`.
4. **Submit Indeed finding** — CSRF cookie inconsistency. Draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md`. Needs Playwright browser verification (cookie is JS-set, curl won't reproduce). Pending Dio's decision.
5. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
6. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. Highest-ROI path to real findings.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
7. **Add neon.tech to hunt registry** — Active HackerOne program. Auth scan on `console.neon.tech` could find IDOR/BAC in the API.
8. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March 2026).

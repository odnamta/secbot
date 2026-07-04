# Bounty Pool Triage — Updated 2026-07-04 (Session 9)

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
| 5 | kredivo | Unprotected WordPress Login on blog.kredivo.com | Medium | Draft ready: `2026-07-04-kredivo-wordpress-login.md`. blog.kredivo.com is explicitly in scope. No rate limiting → credential stuffing risk. **CAVEAT:** Needs manual verification of lockout behavior + WordPress version check + XML-RPC probe. Realistic payout: Rp 500k–1.5M ($32–$95). |

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

---

## Session 9 Analysis — March 2026 Scans (Triaged 2026-07-04)

Three previously untriaged scan files processed: **kredivo** (2026-03-22), **cal.com v1** (2026-03-22), **openproject v1** (2026-03-22).

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login /wp-login.php | **TIER 2** | blog.kredivo.com is explicitly in scope. No rate limiting = credential stuffing risk. Meaningful impact (admin → JS injection on blog). Draft: `2026-07-04-kredivo-wordpress-login.md`. Needs manual lockout + XML-RPC verification before submit. |
| Missing CSP on blog.kredivo.com | **FP** | Header absence on a marketing/company blog. Auto-rejected as informational by triagers. |
| `_hcc` cookie missing HttpOnly/Secure | **FP** | `_hcc` is HubSpot's contact-tracking cookie. Third-party analytics cookie = classic FP pattern. Not bounty-worthy. |

### Cal.com v1 — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

Note: This is the older March 22 scan; the March 26 v2 scan was already triaged in Session 8. Both v1 critical findings have empty evidence fields and the scanner's own descriptions flag them as potential FPs.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation [critical][medium] | **FP** | Empty evidence. Next.js API routes don't resolve URL paths via the filesystem. The v2 scan (4 days later) found zero critical/high findings on the same target. URL path traversal (`/api/../../../etc/passwd`) is normalized by Cloudflare before reaching the app. |
| XXE on /api/geolocation [critical][medium] | **FP** | Empty evidence. A geolocation API endpoint wouldn't process XML input. The scanner probed with XML POST and interpreted a generic error/404 as entity expansion. Scanner description itself flags this as likely FP. |
| Exposed Admin Routes [high][low] | **FP** | Confidence: LOW. `/admin` in Next.js app redirects unauthenticated users server-side. Standard NextAuth.js middleware behavior. |
| Sensitive Token in URL (/api/web_experiments/?token=) [high][medium] | **Informational** | The `token` in web_experiments is a public feature-flag/experiment read key (PostHog or similar), not an auth secret. Not exploitable. |
| Missing Rate Limiting on /api/auth/session | **FP** | Same pattern as v2 triage — GET probe on a session-getter endpoint, not an auth submission endpoint. |
| OAuth State Not Enforced | **FP** | Same pattern as v2 triage — wrong endpoint probed (`/api/auth/session` is not an OAuth authorization endpoint). Confidence: LOW. |
| Missing SRI (7 external scripts) | **FP** | Same pattern as v2 triage — third-party analytics scripts (PostHog, Twitter Ads). SRI not applicable for CDN scripts that auto-update. |

### OpenProject v1 — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

Same target as v2 (community.openproject.org), same pattern of GET-probe FPs.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing Rate Limiting on /login | **FP** | GET page-load probe. Same false-positive as all other rate-limit findings. |
| Missing SRI on external scripts | **FP** | Same pattern as v2 triage. |

---

## Honest Assessment (Jul 2026, Session 9)

**Bounty readiness: Still LOW, one Tier 2 draft added.**
- 1 new Tier 2 draft (Kredivo WordPress login) — needs manual verification
- All other new findings are FPs (empty evidence, GET-probe rate limit FPs, tracking cookies)
- The critical-severity cal.com findings (directory traversal + XXE) are scanner artifacts — zero evidence, scanner itself flags them as potential FPs

**Root cause unchanged:** Unauthenticated scans on hardened targets yield passive findings only. The Kredivo WordPress login is the first structurally-real finding since Indeed (March 14 session).

---

## Honest Assessment (Jun 2026, Session 8)

**Bounty readiness: Still LOW.** Three more scans, same pattern:
- 0 injection vulnerabilities found (XSS, SQLi, SSTI, SSRF, etc.)
- All "high/medium" findings are passive (headers, cookies) — none submittable
- Rate limiting findings are all GET-probe FPs
- Open redirect findings are same-org redirect FPs
- No authenticated scanning performed on any target

**Root cause unchanged:** Unauthenticated scan + hardened targets = passive findings only.

**Bright spot:** OpenProject CVE analysis (`OPENPROJECT-CVE-ANALYSIS.md`) documents 22 real CVEs
with exact endpoints and payloads. The path forward is a local Docker test → authenticated scan.

---

## Next Steps (Priority Order)

1. **Verify + Submit Kredivo WordPress login** — Manual steps: (a) check XML-RPC at `/xmlrpc.php`, (b) check WordPress version from meta generator tag, (c) run 25 rapid POST attempts and confirm no lockout. If confirmed: submit to RedStorm. Realistic payout: Rp 500k–1.5M.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

# Bounty Pool Triage — Updated 2026-07-25 (Session 9)

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
| 5 | blog.kredivo.com | WordPress Admin Login (/wp-login.php) Publicly Accessible | High | HOLD — real finding, wp-login.php returns HTTP 200 while homepage returns 403 (bot protection bypass). However, `blog.kredivo.com` is a WordPress blog subdomain, not the main Kredivo fintech app. Scope uncertain for RedStorm program. Before submitting: verify blog.kredivo.com is in RedStorm scope, and confirm no IP allowlist or reCAPTCHA blocks exploitation. reCAPTCHA v3 is present on the login form. |

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

---

## Session 9 Analysis — July 25, 2026

Two sets of findings processed: (1) three auto-generated pending reports from the March 2026 Moneybird scan that were never formally triaged, (2) the Kredivo scan from March 22, 2026 which was missing from all prior triage sessions.

### Moneybird Pending Reports (bounty-pool/pending/moneybird/) — Cleaned Up

Three files were auto-generated by the report pipeline but not evaluated. All three archived as FP:

| File | Verdict | Reason |
|------|---------|--------|
| `09dd5267-missing-content-security-policy-header.md` | **FP** | Response includes `content-security-policy-report-only` header — Moneybird IS deploying CSP, just in report-only mode. Marketing homepage. Already called FP in Session 8. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP** | postMessage listeners on marketing homepage. CSP explicitly whitelists `intercom.io`, `intercomcdn.eu`, `freshworks.com` (Freshdesk). These are Intercom/Freshdesk chat widget listeners — known FP pattern. Not exploitable cross-origin, design intent. |
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | **FP** | Claimed DOM XSS via URL fragment on www.moneybird.com (marketing homepage). XSS check listed as "passed" in the full scan summary. The curl reproduction command doesn't execute JS (fragments aren't sent to server). Evidence insufficient — no screenshot, no runtime confirmation. Marketing homepage not in HackerOne scope (app is app.moneybird.com). Archived. |

All three moved to `bounty-pool/archived/` with `2026-07-25-` prefix.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Target:** `blog.kredivo.com` (WordPress blog). First-ever triage of this scan.

Note: homepage returns **HTTP 403** (bot protection with `_hcc` challenge cookie). All header findings are from this 403 error page — they are structural FPs.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP/X-Frame-Options/X-Content-Type-Options (HTTP 403 pages) | **FP** | Detected on bot-protection 403 responses, not real app responses. Standard for Akamai/Cloudflare challenge pages. |
| `_hcc` cookie missing HttpOnly/Secure | **FP** | `_hcc` = HubSpot Click Cookie or bot-protection challenge token. `Max-Age=30` (30 seconds) confirms transient challenge use, not an auth token. Not exploitable. |
| Missing rate limiting on `/login` (GET) | **FP** | GET page-load probe only. Same false-positive pattern as cal.com, openproject. Real rate limiting applies to POST auth submissions. |
| **WordPress Login `/wp-login.php` Accessible (HTTP 200)** | **HOLD → Tier 2** | Homepage returns 403 (bot protection), but wp-login.php returns 200 — effectively a bot-protection bypass. Real finding: reCAPTCHA v3 present, but no apparent brute-force throttle. **CAVEAT:** `blog.kredivo.com` is a WordPress blog, not the main Kredivo financial app. Verify blog subdomain is in RedStorm scope before submitting. If in scope, this is a legitimate medium-high finding given the reCAPTCHA can be bypassed with a valid token. |

---

## Honest Assessment (Jul 2026, Session 9)

**Bounty readiness: Still LOW.** Session 9 cleaned up the backlog — no net new submittable findings.

The kredivo blog WordPress exposure is real but likely out of scope for the main RedStorm program (which targets the fintech product, not the marketing blog). Submitting it risks wasted effort or a "not applicable" closure.

**Pattern:** All unauthenticated scans yield only passive findings. The authenticated path (OpenProject Docker, Twitch login) remains the highest-ROI next step.

---

## Next Steps (Priority Order)

1. **Verify Kredivo blog scope** — Check RedStorm's scope list for `blog.kredivo.com` or `*.kredivo.com`. If in scope, submit the WordPress login exposure (Tier 2, item #5).
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

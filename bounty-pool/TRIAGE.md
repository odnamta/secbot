# Bounty Pool Triage — Updated 2026-10-24 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | kredivo (blog) | Unprotected WordPress admin login (/wp-login.php) — no IP restriction, no rate limiting | High | blog.kredivo.com is explicitly in-scope. Real finding, high confidence. Draft ready: `2026-10-24-kredivo-wordpress-admin-exposure.md`. **CAVEAT:** Programs sometimes rate WP login exposure as Medium or Informational — frame around brute-force + admin takeover risk. |

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

1. **Submit Kredivo WordPress login draft** — `2026-10-24-kredivo-wordpress-admin-exposure.md`. Real finding, in-scope, High confidence. Review draft and submit to RedStorm. Potential ~Rp 1,500,000 (~$95).
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

---

## Session 9 Analysis — March 22, 2026 Scans (Triaged 2026-10-24)

Three previously unprocessed scans from March 22 2026 (pre-Session 8): **kredivo** (blog.kredivo.com), **openproject** (community.openproject.org), **cal.com** (cal.com marketing site).

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login (/wp-login.php) — no IP restriction, no rate limiting | **DRAFT READY** | blog.kredivo.com is explicitly in-scope. Real endpoint, HTTP 200 + WP login form, HIGH/HIGH confidence. No login attempted. Brute-force + admin takeover risk. Draft: `2026-10-24-kredivo-wordpress-admin-exposure.md` |
| Missing Content-Security-Policy header | **FP** | Marketing/company blog. Header findings on blogs auto-rejected as informational by triagers. |
| Cookie `_hcc` missing HttpOnly + Secure | **FP** | `_hcc` = HubSpot Click Count cookie (third-party analytics/marketing). Intentionally JS-accessible. Classic FP pattern. |

### OpenProject — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing Rate Limiting on /login (and API endpoints) | **FP** | Scanner fires 15 GET requests at page-load endpoints. Rate limiting applies to POST credential submissions, not page loads. No POST login probing performed. Identical FP pattern as all prior scans. |
| Missing SRI on External Scripts | **FP** | Community forum/app with third-party scripts. SRI not practical for frequently-updated CDN scripts. Not submittable without a concrete supply-chain attack vector. |

### Cal.com — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Note:** Scan target was `cal.com` (marketing homepage). Per the calcom.txt scope file, only `app.cal.com` and `*.companyhub.com` are in scope — **`cal.com` is explicitly out of scope.** All findings are on the marketing site.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation (CRITICAL/MEDIUM) | **FP + OOS** | Out of scope (marketing site). Additionally, URL path traversal on modern Next.js + Cloudflare WAF stack is blocked by URL normalization at proxy level. Detection method `path-traversal-response` likely triggered on redirect behavior, not actual file read. |
| XXE Injection on /api/geolocation (CRITICAL/MEDIUM) | **FP + OOS** | Out of scope. A geolocation API endpoint in Next.js returns JSON regardless of Content-Type sent. Entity expansion detection on a non-XML API is a scanner FP. |
| Exposed Admin Routes (HIGH/LOW) | **FP + OOS** | Out of scope + LOW confidence. Cal.com is MIT open-source; `/admin` is a user admin dashboard that redirects to login, not an unprotected admin panel. |
| Sensitive Token in URL /api/web_experiments/?token= (HIGH/MEDIUM) | **FP + OOS** | Out of scope. Token is for A/B testing/feature flags (web_experiments), not an auth token. Public experiment config tokens in URL params are common SaaS practice and not bounty-worthy. |
| Missing Rate Limiting on /api/auth/session (MEDIUM/MEDIUM) | **FP + OOS** | Out of scope. `/api/auth/session` is NextAuth.js session getter endpoint, not a login submission endpoint. |
| OAuth State Parameter on /api/auth/session (MEDIUM/LOW) | **FP + OOS** | Out of scope + LOW confidence. `/api/auth/session` is not an OAuth authorization endpoint. Scanner tested wrong endpoint. |
| Missing SRI on External Scripts (MEDIUM/HIGH) | **FP + OOS** | Out of scope. Standard FP for marketing sites with analytics scripts. |
| Auth Cookie Missing HttpOnly (LOW/HIGH) | **FP + OOS** | Out of scope. Same `__Secure-next-auth.callback-url` cookie assessed as FP in Session 8 — stores redirect URL, not auth token. |

---

## Honest Assessment (Oct 2026, Session 9)

**Bounty readiness: IMPROVING.** Session 9 found 1 new draftable finding (Kredivo WordPress admin exposure), bringing Tier 1 to 2 items.

Pattern continues: most scanner findings on unauthenticated scans are passive/header issues or FPs on well-hardened targets. The Kredivo finding stands out because it targets attack surface reduction (unprotected admin login) rather than misconfigured headers.

**Cal.com scope issue:** The hunt registry runs scans on `cal.com` but the scope only covers `app.cal.com`. The scanner's `crawl` phase starts at the marketing site. Consider updating `hunt-registry.yaml` to target `https://app.cal.com/` directly to avoid wasting scan cycles on out-of-scope pages and generating noisy critical FPs.

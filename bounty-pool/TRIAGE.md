# Bounty Pool Triage — Updated 2026-08-12 (Session 9)

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

## Session 9 Analysis — March 22, 2026 v1 Scans (Triaged 2026-08-12)

Three v1 scans from March 22 (pre-dating the v2 re-scans triaged in Session 8) were not previously reviewed: **cal.com v1**, **openproject v1**, **kredivo**.

### Cal.com v1 (HackerOne) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

This scan pre-dates the calcom-v2 scan (March 26, triaged in Session 8). Headline severity looked alarming (2 critical, 2 high) — all FPs.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on `/api/geolocation` (critical, medium) | **FP** | Scanner sends `https://cal.com/api/../../../etc/passwd` — Cloudflare + Next.js normalize/block path traversal in URL at the infrastructure layer. `/api/geolocation` is a JSON endpoint returning IP geolocation data; it has no `path` file-read parameter. No actual file content confirmed in response. |
| XXE on `/api/geolocation` (critical, medium) | **FP** | Scanner posts `Content-Type: application/xml` + XXE payload to what is a JSON/REST GET endpoint. Cal.com is Next.js — no server-side XML parser on this route. Payload ignored or rejected. |
| Exposed Admin Routes `/admin`, `/administrator` (high, low) | **FP** | Scanner itself notes: "suggesting these may be legitimate public-facing routes…rather than unprotected admin pages." Cal.com's `/admin` requires NextAuth session — Next.js SPA returns HTTP 200 for all client-side routes, auth enforced client-side. Low confidence confirmed by scanner. |
| Sensitive Token in URL `/api/web_experiments/?token=` (high, medium) | **FP** | This is a Statsig A/B testing client key, not an auth/session token. Public experiment assignment tokens are intentionally passed in URLs across all Statsig customers. Not sensitive or exploitable. |
| Missing Rate Limiting on Auth Endpoints (medium) | **FP** | GET probe FP — same pattern as all prior rate-limit findings. |
| OAuth State Not Enforced (medium, low) | **FP** | Low confidence. Wrong endpoint — `/api/auth/session` is NextAuth's session getter, not an OAuth authorization URL. |
| Missing SRI on External Scripts (medium, high) | **FP** | Third-party CDN scripts (same finding triaged in calcom-v2 Session 8). |
| Auth Cookie Missing HttpOnly (low, high) | **FP** | `__Secure-next-auth.callback-url` stores redirect URL post-login, not an auth token. Same FP as calcom-v2 triage. |

### OpenProject v1 (YesWeHack) — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

Superseded by openproject-v2 scan (March 26, triaged in Session 8). Findings are a subset of v2 findings.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing Rate Limiting (medium) | **FP** | GET probe FP. |
| Missing SRI on External Scripts (medium, high) | **FP** | CDN assets (Chargebee, OpenProject CDN). Not exploitable without XSS chain. |

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

First Kredivo scan, targeting `blog.kredivo.com` (in-scope per `scopes/kredivo.txt`).

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP, X-Frame-Options, etc. (high/medium, from HTTP 403) | **FP/Artifact** | All header findings detected against HTTP 403 responses — the CDN/WAF blocked the scanner. Headers on 403 error pages are not representative of app security posture. |
| `_hcc` cookie missing HttpOnly + Secure (medium, medium) | **FP** | Cookie has `Max-Age=30` (30-second lifetime) — definitively a short-lived tracking/analytics token, not a WAF state or auth cookie (those use session-length or long-lived lifetimes). Set on a 403 CDN error response, not the app itself. Even if the purpose were unknown, a 30s Max-Age cookie with no session-critical function is not bounty-worthy. |
| WordPress `/wp-login.php` accessible, HTTP 200 (high, high) | **Informational** | Blog subdomain running WordPress. Login page is accessible (normal WordPress default) BUT has Google reCAPTCHA v3 (`api.js?render=6Lcq-sgZ...`) protecting it. With reCAPTCHA active, brute-force threat is mitigated. Marketing blog wp-admin exposure is typically Out Of Scope or Informational on RedStorm. Scope is `blog.kredivo.com` but bounty targets are typically app/API surfaces. Not submittable. |
| Missing Rate Limiting on GET `/login` (medium) | **FP** | GET probe FP. |

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

**Bounty readiness: Still LOW.** Three more v1 scans cleared — all FPs.

Session 9 closed out the last untriaged scans. All March 2026 scan results are now fully triaged.

**Pattern holds:**
- Scanner produces FP "critical" findings (path traversal, XXE) via pattern-matching against JSON endpoints — no actual payload confirmation
- All real-looking high/medium findings remain passive (headers, cookies) — not submittable
- GET-probe rate limit FPs continue across all targets
- Kredivo blog scan was WAF-blocked (403 responses) — no real app surface reached

**No new bounty reports drafted in this session.** 0 of 8 new findings pass triage.

**Current submittable queue: 1 item** — Indeed CSRF cookie inconsistency (Tier 1, needs Dio's go-ahead).

---

## Next Steps (Priority Order)

1. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
2. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
3. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
4. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
5. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

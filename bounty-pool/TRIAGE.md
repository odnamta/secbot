# Bounty Pool Triage — Updated 2026-09-19 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------| ------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------| ------|
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
|---|--------|---------|----------| ------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Session 9 Analysis — Backlog Triage (2026-09-19)

Two previously un-reviewed March 2026 scans processed: **cal.com** (March 22) and **blog.kredivo.com** (March 22).
Also formally closed: three staged moneybird pending files from commit 6aef881.
No new scans have run since March 26, 2026.

### Cal.com (HackerOne) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

Target: `https://cal.com/` (marketing homepage, not `app.cal.com`).

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on `/api/geolocation` (critical/medium) | **FP** | Geolocation endpoint does not parse file paths. Scanner injected traversal sequences into URL but no file content was returned. Confidence is `medium` and scanner itself flags potential FP. AWS WAF + Cloudflare in place. |
| XXE on `/api/geolocation` (critical/medium) | **FP** | Same endpoint. A geolocation lookup does not process XML. No OOB callback received. Medium confidence, scanner flags as potential FP. |
| Exposed Admin Routes /admin, /manager, /manage (high/low) | **FP** | Low confidence. Scanner description states "response snippets show a standard Next.js app shell" — these are likely user-facing pages (username `/admin`), not unprotected admin panels. |
| Sensitive Token in `/api/web_experiments/?token=` (high/medium) | **Informational** | A/B testing endpoint. `token=` parameter is a PostHog/Optimizely feature-flag key, publicly loaded by all frontend visitors. Not an auth token. No session context. Auto-rejected by bug bounty triagers. |
| Rate Limiting on `/api/auth/session` (medium/medium) | **FP** | GET page-load endpoint, not a POST credential submission. Same false-positive pattern as calcom-v2 rate limit findings in Session 8. |
| OAuth State Not Enforced (medium/low) | **FP** | Low confidence. Scanner confirms `/api/auth/session` is NextAuth's session getter, not an OAuth authorization endpoint. No state parameter is required here. |
| Missing SRI on External Scripts (medium/high) | **FP** | Third-party analytics (PostHog, Twitter Ads, CloudFront CDN). Same SRI FP pattern as calcom-v2 Session 8 triage. |
| `__Secure-next-auth.callback-url` missing HttpOnly (low/high) | **FP** | Already reviewed in Session 8 calcom-v2 triage: stores post-login redirect URL, not an auth token. |

### blog.kredivo.com (NOT in hunt registry) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Note:** Hunt registry target is `kredivo.com` main app. Scan ran against `blog.kredivo.com` (WordPress marketing blog). Blog findings are not in scope for Kredivo's HackerOne program.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login `/wp-login.php` (high/high) | **Out of Scope** | Blog subdomain, not main app. WordPress blogs are typically excluded from fintech bounty programs. Automated scanning on main fintech app endpoints is what generates bounty-worthy findings. |
| Missing CSP header (high/high) | **FP** | Marketing blog. Auto-rejected as informational by triagers. |
| `_hcc` cookie missing HttpOnly/Secure (medium/high) | **FP** | `_hcc` = HubSpot Click Counter cookie — a third-party tracking cookie intentionally exposed to JS. Classic FP pattern from CLAUDE.md known FP list. |

### Moneybird Pending Files (commit 6aef881, Staged 2026-03-22)

These three files were staged to `bounty-pool/pending/moneybird/` in the same commit that patched the DOM XSS scanner FP. They are now formally closed.

| File | Verdict | Reason |
|------|---------|--------|
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | **FP** | Confirmed FP in commit 6aef881: "DOM XSS finding verified as FP in browser — no alert fired, payload was URL-encoded." Browser URL-encodes `#<img src=x>` → `#%3Cimg%20src%3Dx%3E` before innerHTML write; encoded string is safe. Scanner fix applied. |
| `09dd5267-missing-content-security-policy-header.md` | **FP** | Marketing homepage, www.moneybird.com. Already reviewed Session 8 as FP. Auto-rejected by HackerOne triagers. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP** | postMessage handlers on marketing homepage. No named sensitive action. Matches CLAUDE.md known FP pattern: postMessage from chat/marketing widgets (Intercom, Drift, Zendesk) is by design. Medium confidence. |

---

## Honest Assessment (Sep 2026, Session 9)

**Bounty readiness: Still LOW.** Session backlog fully cleared — all March 2026 scan results now triaged.

- 0 critical/high injection findings survived triage across 7 total scans
- "Critical" findings (directory traversal, XXE on cal.com) were scanner FPs with medium confidence
- No new scans have run since March 26, 2026 — hunt loop may be stalled
- Moneybird staged files formally closed as FP (DOM XSS was a scanner bug, now fixed)

**Root cause unchanged:** Unauthenticated scan + hardened production targets = passive/header findings only.

**Recommended action:** Check why hunt loop hasn't produced new scans in 6 months. Then prioritize OpenProject Docker test and authenticated scanning.

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

1. **Investigate stalled hunt loop** — No new scans since March 26, 2026 (6 months). Check whether `secbot hunt` is running on schedule, whether targets are being blocked (WAF, rate limit), or whether the hunt daemon needs a restart. Without fresh scans, triage backlog will stay empty.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

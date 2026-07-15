# Bounty Pool Triage — Updated 2026-07-15 (Session 9)

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

---

## Session 9 Analysis — July 15, 2026 (Triaged 2026-07-15)

Two scans and one set of pending drafts missed by Session 8 are resolved here. No new scans exist beyond March 2026.

### Kredivo (blog.kredivo.com) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Note:** `blog.kredivo.com` is in scope per `scopes/kredivo.txt` but is a WordPress marketing blog, not the core financial app.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login Page (/wp-login.php) [High, High] | **FP** | Publicly accessible /wp-login.php is standard WordPress default behavior — it is not a configuration vulnerability, it's the default install state. The program focus is on financial/app endpoints (app.kredivo.com, mysandbox.kredivo.com). Rate limiting finding (no 429 on GET page-load) is same GET-probe FP as documented in session 8. Not worth submitting. |
| Missing CSP [High, High] | **FP** | WordPress marketing blog homepage. Triagers auto-reject header findings on marketing/blog sites. |
| Cookie `_hcc` missing HttpOnly + Secure [Medium, High] | **FP** | `_hcc` is the HubSpot analytics/tracking cookie (third-party, set by HubSpot JS SDK). Third-party analytics cookies are a documented FP pattern. Not bounty-worthy. |

**Kredivo verdict: 0 submittable findings.** All 3 are FPs.

### Cal.com v1 (cal.com) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Note:** This is the v1 scan of cal.com (the marketing site root). cal-com v2 (`app.cal.com`) was triaged in Session 8. These are session 8 leftovers.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation [Critical, Medium] | **FP** | Geolocation lookup endpoints don't read filesystem. Scanner misread a generic error/redirect as traversal confirmation — the finding description itself flagged this. |
| XXE on /api/geolocation [Critical, Medium] | **FP** | Same endpoint. Geolocation APIs don't consume XML. Scanner sent XML payloads to a non-XML endpoint and misread the response. |
| Exposed Admin-Like Routes /admin, /administrator, etc. [High, Low] | **FP** | Low confidence. Description notes these return the standard Next.js app shell — they are SPA routes, not unprotected admin panels. |
| Sensitive Token in URL (/api/web_experiments/?token=) [High, Medium] | **FP** | `token=` has an empty value — this is a scanner artifact from probing the URL with an empty param, not a real token exposed in a URL. Cal.com is MIT open source; this pattern is likely an intentional feature flag endpoint. |
| Rate Limiting on /api/auth/session [Medium, Medium] | **FP** | Same GET-probe false positive documented in Session 8 cal-com v2 analysis. /api/auth/session is a session-check GET endpoint, not a credential submission endpoint. |
| OAuth State on /api/auth/session [Medium, Low] | **FP** | Low confidence. The finding itself notes this is the wrong endpoint (NextAuth session getter, not an OAuth authorization endpoint). |
| Missing SRI for external scripts [Medium, High] | **FP** | Third-party CDN scripts (analytics, ads). SRI not applicable to third-party scripts that auto-update. Documented FP pattern. |
| Auth cookie `__Secure-next-auth.callback-url` missing HttpOnly [Low, High] | **FP** | Low severity, same as cal-com v2. Stores post-login redirect URL, not an auth token. |

**Cal.com v1 verdict: 0 submittable findings.** All 8 are FPs.

### Moneybird Pending Drafts (bounty-pool/pending/moneybird/) — Drafted pre-Session 8, not triaged

Session 8's Moneybird analysis only noted Missing CSP and Mixed Content. Three draft files exist in `pending/moneybird/` that weren't resolved. Triaged here:

| Draft File | Finding | Verdict | Reason |
|------------|---------|---------|--------|
| `6d09cce8-dom-based-xss-via-url-fragment.md` | DOM XSS via URL fragment [High, High] | **HOLD — manual verification needed** | Scanner claims Playwright triggered `alert("secbot-xss-37")` at two innerHTML sinks on `www.moneybird.com/#<img src=x onerror=...>`. Confidence is "high" (auto-verified). BUT: the curl command in the draft won't reproduce this — URL fragments are never sent to the server by browsers. The finding is DOM-side only and requires a live browser. Needs Dio to manually open the URL in a browser and confirm JS fires. If real: scope is `www.moneybird.com` (marketing homepage), not `app.moneybird.com` (the app). XSS on the marketing site likely doesn't expose session cookies — but could enable phishing. Still worth submitting if confirmed. **Action: verify in browser before deciding.** |
| `09dd5267-missing-content-security-policy-header.md` | Missing CSP [High, High] | **FP** | Already triaged as FP in Session 8. Marketing homepage. Archive this draft. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | postMessage Missing Origin Validation [Medium, Medium] | **FP** | Marketing homepage postMessage handlers are analytics/chat widgets (Intercom/HubSpot pattern). Documented FP. Archive this draft. |

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

1. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
2. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
3. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
4. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
5. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

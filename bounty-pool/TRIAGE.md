# Bounty Pool Triage — Updated 2026-07-08 (Session 9)

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

## Session 9 Analysis — Unreviewed Scans + Pending Reports Review (Triaged 2026-07-08)

Three datasets reviewed: **kredivo** (blog, 2026-03-22), **cal.com v1** (2026-03-22), and **moneybird pending drafts** (auto-generated, undated).

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Context:** Target was `blog.kredivo.com`. Nearly all responses returned HTTP 403 — the scanner was geo-blocked (server-timing shows Singapore CDN; scanner IP was blocked at edge). All header findings are from the 403 error page, not the real application.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP/X-Frame-Options/XCTO/Referrer-Policy | **FP** | Assessed on HTTP 403 error page, not the application. Headers on WAF block pages are irrelevant. |
| Cookie `_hcc` missing HttpOnly/Secure | **FP** | `_hcc` is the HubSpot Click Cookie — a third-party marketing tracker. Classic third-party cookie FP pattern. Not a session token. |
| WordPress login `/wp-login.php` exposed (HTTP 200) | **FP** | HTML body confirms reCAPTCHA v3 is active (`render=6Lcq-sgZAAAAAKO4bLDFjEvdj3ItNQopxmyb3LHq`). Brute-force protection is present. Exposed login page without brute-force protection would be interesting; with reCAPTCHA it's informational. |
| Rate limiting on GET `/login` | **FP** | GET page-load probe, same FP pattern as all previous targets. Not a POST credential test. |
| HSTS not eligible for preload | **Info** | HSTS present but missing `includeSubDomains`. Informational, not bounty-worthy. |

**Net: 0 submittable findings.** All FP or blocked-at-edge artifacts.

---

### Cal.com v1 — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Context:** Earlier scan of `cal.com` (the marketing/landing page, 5 pages). Not to be confused with `app.cal.com`. Cal.com has a HackerOne program and is MIT open source — heavily security-tested.

| Finding | Verdict | Reason |
|---------|---------|--------|
| **[CRITICAL]** Directory Traversal on `/api/geolocation` | **FP** | `/api/geolocation` is a simple IP-to-location lookup endpoint in Next.js. It does not accept file paths as parameters. The curl `https://cal.com/api/../../../etc/passwd` would be normalized/rejected by any web server before it reaches app code. AI itself noted "may be false positive due to WAF." Open-source review confirms no path traversal risk here. |
| **[CRITICAL]** XXE on `/api/geolocation` | **FP** | Same endpoint — a Next.js geolocation API written in TypeScript/Node.js has zero XML parsing. Scanner fired a generic XXE payload at a JSON endpoint and misinterpreted a generic error response as evidence of XXE. AI self-flagged as potential FP. |
| **[HIGH]** Exposed admin routes `/admin`, `/administrator` etc. | **FP** | Confidence: low. AI noted responses contain standard Next.js app shell. `cal.com/admin` is a legitimate Next.js route that redirects unauthenticated users to login. Not unprotected. |
| **[HIGH]** Sensitive token in `/api/web_experiments/?token=` | **FP** | This is Cal.com's internal A/B experimentation API. The `token=` parameter appears empty in the evidence URL. Even if populated, it's an analytics/experiment token, not an auth token. Not bounty-worthy. |
| Missing rate limiting on GET auth endpoints | **FP** | Same GET page-load probe FP as all previous targets. |
| OAuth state not enforced on `/api/auth/session` | **FP** | Same FP as cal.com v2: wrong endpoint (session getter, not OAuth authorization). |
| Missing SRI (PostHog, Twitter Ads, CloudFront) | **FP** | Third-party analytics/ads scripts. SRI not applicable for CDN-hosted scripts that auto-update. |
| Auth cookie missing HttpOnly | **FP/Informational** | Without auth context (no login performed), scanner can't identify session tokens vs tracking cookies. |

**Net: 0 submittable findings.** All high/critical findings are scanner artifacts or known FP patterns. Cal.com v1 scan is equivalent in quality to cal.com v2 — both produce passive-only findings.

---

### Moneybird Pending Reports Review — `bounty-pool/pending/moneybird/`

Three auto-drafted reports reviewed for submission readiness:

| Report File | Finding | Verdict | Reason |
|-------------|---------|---------|--------|
| `09dd5267-missing-content-security-policy-header.md` | Missing CSP on `www.moneybird.com` | **Archive** | Marketing homepage. Triagers auto-reject header findings on marketing pages. Consistent with session 8 decision. Move to `bounty-pool/archived/`. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | postMessage missing origin check | **HOLD — needs manual verification** | On marketing homepage. Impact depends entirely on what the handlers *do* — automated scanner can't enumerate business logic. Needs manual review of handler code in browser DevTools before submitting. Medium confidence. |
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | DOM XSS via URL fragment `#<img src=x onerror=...>` | **HOLD — needs browser verification before submit** | Confidence: high, scanner reports Playwright confirmed alert. IF real, this is submittable. However: (1) on `www.moneybird.com` marketing page, not `app.moneybird.com` — limited session cookie impact; (2) modern browsers may mitigate hash-based XSS; (3) needs manual verification in Chrome before filing. Severity should be downgraded from HIGH to MEDIUM in submission (limited real-world exploitability on a marketing page). |

**Action required:** Dio should manually verify the DOM XSS in Chrome (visit `https://www.moneybird.com/#<img src=x onerror=alert(1)>` and check if alert fires). If confirmed, submit with severity MEDIUM.

---

## Session 9 Summary

**Bounty readiness: Still LOW.** Two additional scans processed, zero new submittable findings.

- Kredivo blog was geo-blocked (403 everywhere) — scanner couldn't reach real application
- Cal.com v1 critical findings are all scanner artifacts (XXE/traversal on a JSON geolocation endpoint)
- Moneybird DOM XSS draft needs human browser verification before submission

**Pattern remains unchanged:** Unauthenticated stealth scans + hardened SaaS targets = passive/header findings + scanner artifact "criticals" that evaporate under manual review.

---

## Session 9 Next Steps (Priority Order)

1. **Manually verify Moneybird DOM XSS** — visit `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome. If alert fires, submit `6d09cce8-dom-based-cross-site-scripting.md` with severity downgraded to Medium.
2. **Verify postMessage handlers** — open `www.moneybird.com` in Chrome DevTools → Sources → search for `addEventListener('message'`. Read the handler code and assess impact before submitting `8c0823c1`.
3. **Submit Indeed finding** (pre-existing) — CSRF cookie inconsistency, Tier 1. Requires Playwright reproduction (JS-set cookie).
4. **OpenProject Docker test** — still highest-ROI path to first bounty payout.
5. **Archive Moneybird CSP report** — move `09dd5267-missing-content-security-policy-header.md` to `bounty-pool/archived/`.

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

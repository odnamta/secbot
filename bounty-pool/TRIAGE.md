# Bounty Pool Triage — Updated 2026-07-11 (Session 9)

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
| 5 | moneybird | DOM XSS via URL fragment on www.moneybird.com | High | Playwright-detected (high confidence): `https://www.moneybird.com/#<img src=x onerror=alert(1)>` triggered alert. Marketing homepage scope — impact depends on whether `.moneybird.com` session cookies are shared with app.moneybird.com. Needs browser verification before submitting. Draft: `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` |

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

## Session 9 Analysis — 2026-07-11 (Triaged 2026-07-11)

Two previously un-triaged scans processed: **cal.com v1** (2026-03-22), **openproject v1** (2026-03-22).
Also processed: **moneybird pending files** from `bounty-pool/pending/moneybird/` (created by prior session but not triaged in TRIAGE.md).

### Cal.com v1 (HackerOne) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| CRITICAL — Directory Traversal on `/api/geolocation` | **FP** | URL path traversal (`/api/../../../etc/passwd`) is normalized before reaching the app by both Next.js router and AWS WAF + Cloudflare. The `/api/geolocation` endpoint serves IP-based geo data — no file system interaction. |
| CRITICAL — XXE Injection on `/api/geolocation` | **FP** | Geolocation endpoint is a JSON/REST API; it does not accept `Content-Type: application/xml`. Probe returned error/ignored. No evidence of XML parser exposure. |
| HIGH — Exposed Admin Routes (low confidence) | **FP** | `/admin`, `/administrator`, `/manage` etc. return Next.js app shell (302 → login or 200 app shell for logged-out users). This is standard auth-gated Next.js routing, not exposed admin functionality. Confidence was LOW. |
| HIGH — Sensitive Token in URL `/api/web_experiments/?token=` | **Informational** | Token is an A/B testing configuration identifier (Bucket/web-experiments platform), not an auth credential. No auth impact. Same-origin use only. |
| MEDIUM — Missing Rate Limiting on `/api/auth/session` | **FP** | GET page-load probe only. Same false-positive as calcom-v2 analysis (Session 8). Rate limiting applies to POST credential submissions. |
| MEDIUM — OAuth State Not Enforced | **FP** | Wrong endpoint — `/api/auth/session` is NextAuth's session getter. Same false-positive as calcom-v2 (Session 8). |
| MEDIUM — Missing SRI on External Scripts | **FP** | PostHog, Twitter Ads, CloudFront CDN scripts. Same pattern as calcom-v2 (Session 8). SRI not applicable for auto-updating CDN scripts. |
| LOW — `__Secure-next-auth.callback-url` missing HttpOnly | **FP** | Stores post-login redirect URL, not auth token. Same as calcom-v2 (Session 8). |

**Net new bounty findings from cal.com v1: 0**

### OpenProject v1 (YesWeHack) — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| MEDIUM — Missing Rate Limiting on auth endpoints | **FP** | GET page-load probes. Same pattern as openproject-v2 (Session 8). |
| MEDIUM — Missing SRI on External Scripts | **FP** | Third-party scripts. Same pattern as all other scans. |

**Net new bounty findings from openproject v1: 0**

### Moneybird Pending Files — `bounty-pool/pending/moneybird/`

Three files existed in pending but were not addressed in Session 8 TRIAGE:

| File | Verdict | Action |
|------|---------|--------|
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | **TIER 2** | Playwright detected alert firing on `www.moneybird.com/#<img src=x onerror=alert(1)>`. HIGH confidence. Needs browser verification. Fixed incorrect curl reproduction command — DOM XSS requires browser, added JS PoC. Moved to Tier 2 pending submission. |
| `09dd5267-missing-content-security-policy-header.md` | **FP** | Missing CSP on marketing homepage — already classified FP in Session 8. Archived. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP** | postMessage handlers on www.moneybird.com likely from third-party widget (chat/analytics). Pattern matches known FP: "postMessage from known widgets (Intercom, Drift, Zendesk) — by design". Archived. |

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

0 interpreted findings. Nothing to triage.

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

1. **Verify Moneybird DOM XSS** — Open `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` in a browser. If alert fires: check `document.cookie` output — if it contains a `.moneybird.com` session/auth cookie the impact is HIGH and worth submitting to HackerOne. Draft: `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction). Draft: `bounty-pool/pending/2026-03-14-indeed-csrf-cookie-SUBMISSION.md`.
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

# Bounty Pool Triage — Updated 2026-08-22 (Session 9)

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
| 5 | moneybird.com | DOM XSS via URL fragment on www.moneybird.com | High | Playwright auto-verify fired alert dialog — high confidence. But www.moneybird.com is the **marketing site**, not the app (app.moneybird.com). Need: (1) manual browser confirmation that alert fires, (2) verify HackerOne scope includes www.moneybird.com, (3) write proper report with Playwright steps (curl won't reproduce DOM XSS). Pending file: `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. |

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

1. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
2. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
3. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
4. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
5. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

---

## Session 9 Analysis — August 22, 2026 (Report Drafter Run)

**Items reviewed this session:**
1. `bounty-pool/pending/moneybird/` — 3 new auto-generated finding files
2. `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json` — not previously triaged
3. `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json` — not previously triaged (cal.com v1)
4. `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json` — not previously triaged (openproject v1)

**New bounty reports drafted: 0**

### Moneybird — `bounty-pool/pending/moneybird/` (3 files)

| Finding | File | Verdict | Reason |
|---------|------|---------|--------|
| DOM XSS via URL fragment | `6d09cce8-*.md` | **HOLD (Tier 2)** | Playwright confirmed alert fires (high confidence). Marketing site (www.moneybird.com), not app. Needs human browser verification + HackerOne scope check before submitting. curl cannot reproduce DOM XSS — client-side only. |
| Missing CSP | `09dd5267-*.md` | **FP** | Marketing homepage. Informational, auto-rejected by triagers. Already noted in Session 8 triage. |
| postMessage without origin validation | `8c0823c1-*.md` | **FP** | Classic third-party widget pattern (likely Intercom/HubSpot/Drift on marketing page). Medium confidence. The reproduction steps show no actual impact — scanner cannot determine what the handler does with received data. |

**Action:** Moved DOM XSS to Tier 2. The other two remain in `pending/` but are marked FP here. Do not submit.

### Kredivo v1 — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `https://blog.kredivo.com/` (WordPress blog subdomain)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login Page (`/wp-login.php`) | **Informational** | blog.kredivo.com is a marketing blog, not the financial platform. WP login exposure is commonly rejected as informational. Not in Kredivo/RedStorm's main scope. |
| Missing CSP | **FP** | Blog marketing subdomain. Informational, auto-rejected. |
| `_hcc` cookie missing HttpOnly/Secure | **FP** | `_hcc` is the HubSpot Chat cookie — a third-party marketing tool. Classic analytics/marketing cookie FP pattern. Not in-scope for cookie flag findings. |

### Cal.com v1 — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

Target: `https://cal.com/` (marketing/landing page scan)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on `/api/geolocation` (critical/medium) | **FP** | AI report itself flags it as likely FP with WAF in place. `/api/geolocation` is an IP lookup endpoint — it doesn't accept file paths or read from disk. Scanner got error response and misidentified it. |
| XXE Injection on `/api/geolocation` (critical/medium) | **FP** | Same endpoint as above. Geolocation APIs are JSON-based (they take an IP). Scanner sent XML at a JSON endpoint, got an error, flagged it as XXE. Not exploitable. |
| Sensitive token in URL (`/api/web_experiments/?token=`) | **Informational** | "web experiments" = feature flags / A/B testing API. The token is a public experiment configuration key, not an auth secret. Not bounty-worthy. |
| Missing rate limiting on auth endpoints | **FP** | GET page-load probe FP. Same pattern as calcom-v2 (Session 8). |
| OAuth missing state on `/api/auth/session` | **FP** | Same FP as calcom-v2 (Session 8) — wrong endpoint. |
| Missing SRI (24 external resources) | **FP** | Same SRI FP as calcom-v2 (Session 8). Cal.com is MIT open source. |
| Auth cookie missing HttpOnly (`__Secure-next-auth.callback-url`) | **FP** | Same cookie FP as calcom-v2 (Session 8) — callback URL redirect, not auth token. |
| Exposed admin routes without auth (high/low) | **FP** | Low confidence. 404s on admin-like paths. No actual auth bypass. |

### OpenProject v1 — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

Target: `https://community.openproject.org/`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing rate limiting on auth/API endpoints (medium/medium) | **FP** | GET page-load probe FP. Same pattern as openproject-v2 (Session 8). |
| Missing SRI on external scripts (medium/high) | **FP** | Open source project. SRI not required for CDN-hosted assets that auto-update. Same pattern noted in other scans. |

---

## Honest Assessment (Aug 2026, Session 9)

**Bounty readiness: Still LOW.** Four scan result batches processed, all FPs.

**One potential bright spot:** Moneybird DOM XSS (Tier 2) is the first finding where Playwright auto-verify actually confirmed execution. If it holds up under manual verification and scope covers www.moneybird.com, it would be the first valid active finding.

**Pattern holds:** All 2026-03-22 v1 scans (kredivo, cal.com, openproject) show same FP patterns as v2 scans. Unauthenticated stealth scans on hardened targets consistently yield headers/cookies/informational findings only.

---

## Next Steps (Priority Order, Updated Aug 2026)

1. **Verify moneybird DOM XSS** — Open https://www.moneybird.com/#<img src=x onerror=alert("test")> in browser. If alert fires: check HackerOne scope page for moneybird, write proper report with video/screenshot evidence + Playwright script as PoC. This could be first submittable active finding.
2. **Submit Indeed finding** — CSRF cookie inconsistency (Tier 1). Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged).

# Bounty Pool Triage — Updated 2026-10-28 (Session 9)

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
| 5 | moneybird.com | DOM XSS via URL Fragment on homepage | High | Scanner found 2 `innerHTML-set` sinks triggered by `#<img src=x onerror=alert("secbot-xss-37")>`. Evidence is stronger than most (two confirmed sink hits). Draft ready: `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. **ACTION NEEDED:** Open `https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>` in a browser and confirm alert fires. If confirmed, this is submittable to HackerOne for ~$200-500. |

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

## Session 9 Analysis — October 28, 2026

Two backlogs cleared: **kredivo** (blog.kredivo.com, 2026-03-22 scan) and **moneybird pending drafts** (3 draft files in `pending/moneybird/`).

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `blog.kredivo.com` — this is the **marketing blog subdomain**, not the main Kredivo financial app.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP on blog.kredivo.com | **FP** | Marketing blog. Auto-rejected by triagers. |
| Cookie `_hcc` missing HttpOnly + Secure | **FP** | `_hcc` is the HubSpot Contact Cookie — a first-party analytics/marketing cookie. Intentionally JS-accessible for CRM tracking. Classic known FP pattern. |
| WordPress login /wp-login.php exposed (CVSS 8.1) | **FP** | `blog.kredivo.com` is a WordPress blog. /wp-login.php is publicly accessible by default in WordPress — this is expected behavior, not a vulnerability. Additionally, blog subdomains are almost always out of scope for financial app bounty programs. |
| Rate limiting on /login GET (medium/high) | **FP** | Scanner fires 15 GET requests at page-load endpoint. Rate limiting applies to POST auth submissions, not page loads. Same FP pattern seen on cal.com, OpenProject. |
| Missing headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc.) | **FP** | Marketing blog, all low severity. Auto-rejected. |

**Verdict: 0 actionable findings.** blog.kredivo.com is a marketing blog and almost certainly out of scope for the Kredivo RedStorm program (which targets the financial app). Recommend scoping next kredivo scan to `app.kredivo.com` or API endpoints.

### Moneybird Pending Drafts Review — `pending/moneybird/`

Three draft files were created by a previous agent run but were not in TRIAGE.md. Assessed below:

| Draft File | Finding | Verdict | Reason |
|------------|---------|---------|--------|
| `09dd5267-missing-content-security-policy-header.md` | Missing CSP | **FP** | Marketing homepage. Consistent with Session 8 triage. Auto-rejected. Draft should be moved to archived or deleted. |
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | DOM XSS via URL Fragment | **HOLD** | Raw scan evidence shows 2 `innerHTML-set` sinks confirmed: `Sinks: innerHTML-set, innerHTML-set`. Stronger signal than typical scanner XSS claims. **Requires browser verification before submit.** See Tier 2 entry #5 above. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | postMessage without origin check | **FP** | Handler snippet reveals this is a mouse/scroll tracking analytics handler (`function(i){(i=i||window.event).pageX||i.pageY...`), repurposed as a postMessage listener by a third-party analytics library. Not a real message-processing handler. Matches known FP pattern for Intercom/Drift/analytics widgets. Draft should be moved to archived or deleted. |

### Moneybird Additional Raw Findings (from scan, not in drafted files)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Open Redirects on /login via url/redirect/next/return/returnTo/redirect_uri/goto/dest | **FP** | All 8 redirect findings show `Location: https://moneybird.com/login?param=...` — redirect target is moneybird.com (same org), NOT the evil.example.com payload. Identical FP pattern to neon.tech. |
| Mixed Content (80+ findings, same-domain http:// hrefs) | **Informational** | Consistent with Session 8 finding. Same-org HTTP hrefs auto-upgraded by HSTS. Not submittable. |
| Missing SRI (Google Tag Manager scripts) | **FP** | GTM/analytics CDN. SRI not applicable for auto-updating tag manager scripts. |
| Race Condition on /features/bookkeeping/ GET | **FP** | AI validator correctly identified this as FP in interpreted findings ("False Positive: Race Condition Finding on Static GET Endpoint"). |

---

## Honest Assessment (Oct 2026, Session 9)

**Bounty readiness: Still LOW with one exception.**

New session cleared the kredivo and moneybird backlogs. Result:
- Kredivo blog: 0 actionable findings. Wrong target — blog subdomain is out of scope.
- Moneybird: 1 HOLD (DOM XSS, needs browser verify). If confirmed, this would be the first real injection finding from any scan.

**The DOM XSS on moneybird.com is the single highest-priority item.** It has:
- Two confirmed innerHTML sinks in raw evidence (not just "sink detected")
- High confidence from AI validator
- Draft report already written (`pending/moneybird/6d09cce8...`)
- Plausible surface: marketing homepage reading URL fragment (common for SPA navigation)

The cursor hasn't moved on authenticated scanning. The OpenProject Docker test and Twitch auth scan remain the highest-ROI next steps after verifying the moneybird XSS.

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

1. **[NEW] Verify Moneybird DOM XSS** — Open `https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>` in a browser. If alert fires, submit the draft in `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` to Moneybird's HackerOne program. Estimated bounty: $200-500 for medium/high XSS on marketing page.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Scope Kredivo scan correctly** — Rescan `app.kredivo.com` or API endpoints (not blog subdomain). blog.kredivo.com is almost certainly out of scope.
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).
8. **Clean up FP drafts** — Move `pending/moneybird/09dd5267-missing-content-security-policy-header.md` and `pending/moneybird/8c0823c1-postmessage-handlers-missing-origin-validation.md` to `bounty-pool/archived/`.

# Bounty Pool Triage — Updated 2026-06-24 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | moneybird.com | DOM XSS via URL fragment on www.moneybird.com | High | Scanner (Playwright) observed URL fragment injected into 2 innerHTML sinks. Raw confidence was medium; AI promoted to high. **NEEDS BROWSER VERIFICATION** — visit `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` and confirm alert fires. Draft: `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` (improved 2026-06-24: fixed curl command, added verification checklist). |
| 3 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 4 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 5 | openproject | Session Fixation: _open_project_session not regenerated | Medium | Scan detected same session cookie pre/post login on `community.openproject.org/login?layout=1`. **CAVEAT:** Scanner had no credentials — POST without valid credentials = failed login = session regeneration not triggered. Need authenticated test to confirm. Community instance is fully patched — test against local Docker (see OPENPROJECT-CVE-ANALYSIS.md). |

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

**Correction from Session 8:** Session 8 only reviewed the 2 weakest findings (CSP + mixed content). The scan had 5 interpreted findings, including a DOM XSS and postMessage finding that were missed. Both reviewed here.

| Finding | Verdict | Reason |
|---------|---------|--------|
| DOM XSS via URL fragment on www.moneybird.com | **HOLD** | Playwright detected URL fragment reaching 2 innerHTML sinks. Raw confidence medium. Draft improved — see Tier 2 entry. Needs browser verification before submit. |
| Missing CSP on www.moneybird.com | **FP** | Marketing homepage. Triagers auto-reject header findings on marketing pages. Draft in pending/moneybird/ is companion to XSS but not standalone submittable. |
| postMessage handlers missing origin check | **FP** | Handler snippet analysis reveals mouse event normalization code (`clientX`/`pageX`/`pageY`) — this is a minified JS event polyfill, not a real message processing sink. Classic scanner false positive. Draft `8c0823c1-postmessage-handlers.md` should NOT be submitted. |
| Mixed Content: http://www.moneybird.com/artikelen/ (and 10+) | **Informational** | Same-domain http:// href links on HTTPS page. Moneybird has HSTS; browser auto-upgrades. No actual insecure request made. |
| Race condition finding (info/low) | **FP** | Scan already marked this as false positive in interpretedFindings. |

---

## Session 9 Analysis — Kredivo + Moneybird Pending Review (Triaged 2026-06-24)

Processed: **Kredivo** scan (2026-03-22, first triage ever) + review of **moneybird pending** drafts from previous sessions.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `blog.kredivo.com` (WordPress blog). In scope per `scopes/kredivo.txt`.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login at /wp-login.php (high/high) | **FP** | Expected WordPress behavior on any WP installation. Programs treat this as informational — the login page existing is not a vulnerability; an exploited brute-force or auth bypass would be. Blog subdomain only. No exploit demonstrated. |
| Missing CSP on blog.kredivo.com (high/high) | **FP** | Blog/marketing subdomain. CSP findings on blog pages are universally auto-rejected as informational by triagers. Not submittable standalone. |
| Cookie `_hcc` missing HttpOnly/Secure (medium/high) | **FP** | `_hcc` is a HubSpot analytics/CRM cookie (standard prefix used by HubSpot's Conversations widget). Third-party tracking cookie explicitly identified in FP patterns guide. Set on blog page only, not auth surface. |

**Kredivo verdict:** 0 submittable findings from this scan. Scan target (`blog.kredivo.com`) is a marketing blog, not the main app. **Need to re-scan `app.kredivo.com` and `mysandbox.kredivo.com`** — the sandbox domain is the highest-value target (purpose-built for security testing).

### Moneybird Pending Files Review

Files in `bounty-pool/pending/moneybird/`:

| File | Status | Action |
|------|--------|--------|
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | **IMPROVED** | Fixed curl command (curl cannot test DOM XSS). Added browser reproduction steps + verification checklist. Added raw confidence caveat. Moved to Tier 2. |
| `09dd5267-missing-content-security-policy-header.md` | **FP — do not submit standalone** | Marketing page CSP. Only useful as a companion finding IF the DOM XSS is confirmed. Keep for context; do not submit alone. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP — do not submit** | Handler snippet is mouse event normalization code, not a real message sink. Would be triaged as N/A immediately. |

---

## Honest Assessment (Jun 2026, Session 9)

**Bounty readiness: Still LOW, with one candidate worth manual verification.**

- Kredivo blog scan: 0 findings, wrong target (blog ≠ app)
- Moneybird: 1 plausible finding (DOM XSS) that needs 30 seconds of browser verification
- No authenticated scanning performed on any target
- No injection vulnerabilities confirmed by human yet

**First human-verifiable candidate in the pipeline:** The Moneybird DOM XSS (Tier 2) is the
closest thing to a real finding. If the alert fires in a browser, that's a submittable High on
an active H1 program. Takes 30 seconds to verify. Do it first.

---

## Next Steps (Priority Order)

1. **Verify Moneybird DOM XSS** — Open `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` in a clean browser (no extensions). If alert fires → submit `6d09cce8` draft. 30-second task, highest ROI.
2. **Re-scan kredivo app targets** — Run `secbot scan https://app.kredivo.com --profile stealth` and `secbot scan https://mysandbox.kredivo.com --profile stealth`. The sandbox domain is purpose-built for testing.
3. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
4. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
5. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

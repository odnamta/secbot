# Bounty Pool Triage — Updated 2026-08-05 (Session 9)

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

## Session 9 Analysis — Moneybird Pending Files + Kredivo (Triaged 2026-08-05)

### Moneybird Pending Files (`bounty-pool/pending/moneybird/`)

Three auto-drafted reports from a previous agent run, previously untriaged.

| File | Finding | Verdict | Reason |
|------|---------|---------|--------|
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | DOM XSS via URL Fragment | **HOLD — needs manual browser verification** | Evidence shows heuristic detection only: scanner found `innerHTML-set` sinks + `location.hash` reads in JS bundles, but no Playwright-confirmed alert execution. Draft claims "alert dialog fires" — this is NOT supported by the evidence (confidence stays at medium). Many static sites use `location.hash` for anchor navigation with no XSS. Verify manually in browser before submitting. `www.moneybird.com` marketing site, but DOM XSS still in-scope for HackerOne if confirmed. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | postMessage Without Origin Check | **FP — scanner bug** | Handler snippet in evidence: `function(i){(i=i||window.event).pageX||i.pageY...` is a **mouse/pointer event handler**, not a postMessage handler. Scanner confused `window.event` (pointer events API) with postMessage listeners. Classic FP. |
| `09dd5267-missing-content-security-policy-header.md` | Missing CSP | **FP — marketing page** | www.moneybird.com marketing homepage. Triagers auto-reject header findings on marketing/landing pages. Already assessed as FP in Session 8. |

**Open Redirect findings on moneybird.com/login** (from raw scan, 8 variants):
- All **FALSE POSITIVE** — evidence shows `Location: https://moneybird.com/login?url=...evil...`. The redirect destination is `moneybird.com` (same org), with the evil.example.com URL preserved as a *query parameter*, not as the redirect target. Identical pattern to neon.tech FP from Session 8.

### Kredivo Blog (RedStorm/HackerOne) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `https://blog.kredivo.com/` (WordPress blog — marketing/blog site, NOT the main Kredivo BNPL app)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP on blog.kredivo.com | **FP** | Marketing blog. Triagers auto-reject header findings on blogs. |
| `_hcc` cookie missing HttpOnly/Secure | **FP** | `_hcc` is a HubSpot CMS tracking/marketing cookie — same FP pattern as consent and analytics cookies. Not sensitive, not bounty-worthy. |
| Rate limiting on blog.kredivo.com/login | **FP** | WordPress blog login endpoint, not the Kredivo main product login. Triagers scope is `*.kredivo.com` apps with user data, not blog admin panels. Even if accepted, rate limiting on a blog login is informational at best. |
| wp-login.php exposed (HTTP 200) | **Informational** | Standard WordPress behavior — every WordPress site has `/wp-login.php` publicly accessible. Not a vulnerability unless credentials are unprotected (no MFA, no IP restriction). Not submittable as-is. |
| Missing X-Frame-Options, CORS, HSTS preload | **FP** | Standard noise on a marketing blog. All low/info severity. |

**Net result:** 0 Kredivo findings are bounty-submittable. The scan target (`blog.kredivo.com`) is a WordPress blog, outside the interesting attack surface. Future scans should target `app.kredivo.com` or `mysandbox.kredivo.com` with authentication (`api.kredivo.com` is out of scope per `scopes/kredivo.txt`).

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

**Bounty readiness: Still LOW.** Session 9 processed 2 untriaged scan sets + 3 auto-drafted reports:
- Kredivo blog: 14 raw findings → 0 submittable (wrong target, all marketing blog noise)
- Moneybird pending drafts: 3 drafts reviewed → 2 FP, 1 HOLD pending manual browser verification
- Open redirect batch: 8 findings → all same-org redirect FP (same as neon.tech pattern)
- Scanner bugs noted: postMessage detector confusing mouse event handlers with postMessage listeners

**One potential real finding pending verification:**
- Moneybird DOM XSS (`6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`) — needs manual browser test to confirm alert fires. If confirmed, this is a real medium/high submission to Moneybird HackerOne.

**Root cause unchanged:** Unauthenticated scan + hardened targets = passive findings only.

**Bright spot:** OpenProject CVE analysis (`OPENPROJECT-CVE-ANALYSIS.md`) documents 22 real CVEs
with exact endpoints and payloads. The path forward is a local Docker test → authenticated scan.

---

## Next Steps (Priority Order)

1. **Verify Moneybird DOM XSS manually** — Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in a browser. If alert fires, the `6d09cce8` draft is submittable (update evidence, add screenshot, remove misleading curl command, add browser-only note). Takes 5 minutes. Highest-ROI action this session.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Scan app.kredivo.com or mysandbox.kredivo.com** — The blog scan was wasted on wrong target. Re-run on in-scope authenticated app surface with `--auth-cookie`. (`api.kredivo.com` is out of scope per `scopes/kredivo.txt`.)
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

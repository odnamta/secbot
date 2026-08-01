# Bounty Pool Triage — Updated 2026-08-01 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 5 | moneybird.com | DOM XSS via URL Fragment (innerHTML sink) | High | **Playwright-confirmed** alert fired in Chromium. Draft updated: `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. **ACTION NEEDED:** Verify manually in browser by visiting `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` before submitting. |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | openproject | Session Fixation: _open_project_session not regenerated | Medium | Scan detected same session cookie pre/post login on `community.openproject.org/login?layout=1`. **CAVEAT:** Scanner had no credentials — POST without valid credentials = failed login = session regeneration not triggered. Need authenticated test to confirm. Community instance is fully patched — test against local Docker (see OPENPROJECT-CVE-ANALYSIS.md). |
| 6 | blog.kredivo.com | No rate limiting on WordPress admin login | Medium | Draft ready: `pending/2026-08-01-kredivo-rate-limit-wp-login.md`. blog.kredivo.com is in scope (RedStorm). Run the 50-request brute-force test to capture evidence before submitting. **Expectation:** Low-Medium bounty (~Rp 500,000 / ~$32). Worth trying. |

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

## Session 9 Analysis — March 22, 2026 Scans (Triaged 2026-08-01)

Two previously un-triaged scans processed: **Kredivo** (blog.kredivo.com) and **Cal.com v1** (cal.com marketing site, 2026-03-22).
Also resolved: **Moneybird DOM XSS** draft from scan-results (drafted by earlier session, TRIAGE never updated).

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Scope: blog.kredivo.com is explicitly in scope per `scopes/kredivo.txt`.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login + No Rate Limiting (`/wp-login.php`, HIGH/HIGH) | **DRAFT** | Legit Medium. No rate limiting confirmed (15 POST attempts, all HTTP 200, no lockout). blog.kredivo.com is a fintech company blog — WP admin compromise = malicious script injection on all blog pages. Draft: `pending/2026-08-01-kredivo-rate-limit-wp-login.md` |
| Missing CSP header on blog.kredivo.com | **FP** | Blog/marketing page. Triagers auto-reject header findings on marketing pages. Informational at best. |
| Cookie `_hcc` missing HttpOnly/Secure | **FP** | `_hcc` = HubSpot contact tracking cookie (third-party analytics). By design, intentionally JS-accessible. Classic FP pattern. |

### Cal.com v1 (HackerOne) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Scope note: cal.com (marketing site) is explicitly OUT OF SCOPE per `scopes/calcom.txt`.**  
Only `app.cal.com` and `*.companyhub.com` are in scope. All findings below are OOS — no bounty action taken.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation (CRITICAL/MEDIUM) | **FP + OOS** | Scanner flagged itself: "may be false positive due to WAF response misidentified as file content." No evidence captured. AWS WAF + Cloudflare in place. Even if real, cal.com is OOS. |
| XXE on /api/geolocation (CRITICAL/MEDIUM) | **FP + OOS** | Same endpoint as above. /api/geolocation is a geolocation lookup API — no XML input expected. Scanner fired XXE probes and likely got a WAF block that looked like an error. No evidence. OOS anyway. |
| Exposed Admin Routes (HIGH/LOW) | **Skipped** | Low confidence — skip by policy. |
| Token in URL (`/api/web_experiments/?token=`) (HIGH/MEDIUM) | **FP + OOS** | Token value appears empty (`token=`). Endpoint is A/B testing experiment loader — token is a public experiment ID, not an auth credential. Weak finding even if in scope. OOS. |
| Rate limiting on auth endpoint (MEDIUM/MEDIUM) | **FP + OOS** | GET page-load probe only. Same pattern as calcom-v2. OOS. |
| OAuth state not enforced (MEDIUM/LOW) | **Skipped** | Low confidence. OOS. |
| Missing SRI on external scripts (MEDIUM/HIGH) | **FP + OOS** | Marketing site CDN pattern. Not submittable standalone. OOS. |
| Auth cookie missing HttpOnly (LOW) | **Skipped** | Low severity — skip by policy. |

### Moneybird (HackerOne) — `scan-results/moneybird/secbot-2026-03-22T12-37-45-339Z.json`

Re-reviewed: Session 8 only triaged 2 of 5 interpreted findings. The DOM XSS and postMessage findings had drafts already created (pre-Session-8) but were never acknowledged in TRIAGE.

| Finding | Verdict | Reason |
|---------|---------|--------|
| DOM XSS via URL Fragment (HIGH/HIGH) | **DRAFT — TIER 1** | Playwright confirmed alert fired in Chromium. `dom-sink` detection = browser-side auto-verify. moneybird.com is in scope. Draft improved with proper HTML PoC and impact analysis. **Needs manual browser confirm by Dio before submit.** |
| postMessage handlers missing origin validation (MEDIUM/MEDIUM) | **FP** | www.moneybird.com has Intercom/HubSpot chat widgets — these register postMessage listeners without origin checks by design. Matches known FP pattern. Not submittable without evidence of actual state manipulation. |

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

**Bounty readiness: IMPROVING.** Two new draftable findings this session:
- **Moneybird DOM XSS** — High severity, Playwright-confirmed. First true injection vulnerability surfaced. Needs manual browser verification by Dio before submission.
- **Kredivo rate limiting** — Medium severity, credible finding on an explicitly in-scope asset. Low bounty value but submittable.

The pattern of header/cookie FPs continues, but we now have one genuine XSS candidate.

**Root cause unchanged:** Unauthenticated scan + hardened targets = passive findings only for most targets.

**Bright spot:** Moneybird DOM XSS is the first Playwright-confirmed injection finding. OpenProject CVE analysis (`OPENPROJECT-CVE-ANALYSIS.md`) documents 22 real CVEs
with exact endpoints and payloads. The path forward is a local Docker test → authenticated scan.

---

## Next Steps (Priority Order)

1. **Verify + Submit Moneybird DOM XSS** — Visit `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` in your browser. If alert fires, submit `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` to HackerOne. **This is the highest priority action.**
2. **Submit Kredivo rate limiting** — Run the 50-request loop in `pending/2026-08-01-kredivo-rate-limit-wp-login.md` to capture evidence, then submit to RedStorm. Low bounty but in-scope and legit.
3. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
4. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
5. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

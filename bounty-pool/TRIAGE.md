# Bounty Pool Triage — Updated 2026-09-05 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | moneybird.com | DOM XSS via URL Fragment on www.moneybird.com | High | Draft: `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. Detected via `dom-sink` static analysis (innerHTML sink reads `window.location.hash`). Scanner claims `#<img src=x onerror=alert("secbot-xss-37")>` fires. **NEEDS: Open URL in browser to confirm alert fires before submitting.** Marketing page, so impact is account-context-limited but still submittable to HackerOne if real. |
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

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP on www.moneybird.com | **FP** | Marketing homepage. Triagers auto-reject header findings on marketing pages. |
| Mixed Content: http://www.moneybird.com/artikelen/ (and 10+ others) | **Informational** | Same-domain http:// href links on HTTPS page. If Moneybird has HSTS (they do), browser auto-upgrades. No actual insecure request made. Weak finding, likely informational. |

---

## Session 9 Analysis — September 5, 2026 (Triaged 2026-09-05)

Three previously un-triaged scans reviewed: **moneybird** (pending drafts), **cal-com v1** (2026-03-22), **kredivo** (2026-03-22).
Session 8 missed moneybird DOM XSS and did not process cal-com v1 or kredivo scans at all.

### Moneybird — `bounty-pool/pending/moneybird/` (scan: 2026-03-22)

| Finding | Verdict | Reason |
|---------|---------|--------|
| DOM XSS via URL Fragment on www.moneybird.com | **TIER 2** | Scanner detected innerHTML sink reading `window.location.hash` — claims alert fired. Detection via static `dom-sink` analysis (not live browser execution). Cycle 18 patched a DOM XSS FP class; this finding post-dates that fix. Draft exists. **Action needed: Dio verify in browser** — open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` and confirm alert. If confirmed: submit to HackerOne Moneybird. |
| postMessage handlers missing origin validation | **FP** | 3 handlers on www.moneybird.com homepage. Pattern: chat/analytics widgets (Intercom, Drift, HotJar) register postMessage listeners without origin checks by design. No handler logic that processes sensitive actions confirmed. Archive. |
| Missing CSP on www.moneybird.com | **FP** | Marketing homepage. Already noted Session 8. Archive. |

### Cal.com v1 — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

Note: Session 8 only analyzed calcom-v2 (app.cal.com). This is the v1 scan of cal.com marketing/landing.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on `/api/geolocation` [critical/medium] | **FP** | curl `cal.com/api/../../../etc/passwd` — Cloudflare normalizes URL path before it reaches Next.js. No actual file content in evidence. Detection method `path-traversal-response` fires on response shape, not confirmed data exfil. |
| XXE on `/api/geolocation` [critical/medium] | **FP** | POST XML to a JSON geolocation endpoint. Next.js API route rejects non-JSON bodies. No entity expansion confirmed in evidence — scanner fired because server responded (didn't 500), not because XML was processed. |
| Exposed Admin Routes [high/low] | **FP** | Low confidence, `/admin` etc. on cal.com → redirects to login or 404. Next.js + NextAuth pattern, no sensitive access without credentials. |
| Sensitive Token in URL `/api/web_experiments/?token=` [high/medium] | **Informational** | A/B test experiment tokens, not auth tokens. These are non-sensitive split-test IDs. Token leaking to analytics Referer is standard A/B testing design. Not submittable. |
| Missing SRI / Auth Cookie HttpOnly | **FP** | Same findings as calcom-v2 Session 8 — already marked FP. |

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Target: `blog.kredivo.com` (WordPress blog, in scope per scopes/kredivo.txt).

| Finding | Verdict | Reason |
|---------|---------|--------|
| WordPress /wp-login.php accessible [high/high] | **Informational** | HTTP 200 confirmed at `blog.kredivo.com/wp-login.php`. Technically real (not a scanner FP). However: this is a marketing blog, not the financial app. Attacker gain = blog content defacement, not account/financial data access. RedStorm bounty programs typically pay $0–$32 for blog WordPress admin exposure; likely N/A. Hold unless Dio wants to submit as informational to show engagement. |
| Missing CSP on blog.kredivo.com [high/high] | **FP** | Marketing blog. Informational, auto-rejected. |
| `_hcc` cookie missing HttpOnly/Secure [medium/high] | **FP** | `_hcc` = HubSpot analytics cookie. Third-party cookie FP pattern. |

---

## Honest Assessment (Sep 2026, Session 9)

**Bounty readiness: Still LOW.** Session 9 caught 3 previously un-triaged scans:
- Moneybird DOM XSS is the only finding promoted to TIER 2 — **needs Dio browser verification**
- Cal.com v1 critical findings (traversal, XXE) are CDN-normalization FPs, not real
- Kredivo WordPress login is real but informational-grade (blog, not fintech app)
- Still 0 injection vulnerabilities confirmed by auto-verify across all scans
- Still 0 authenticated scans performed

**Root cause unchanged:** Unauthenticated scan + hardened targets + CDN-fronted apps = passive findings only.

**OpenProject CVE analysis** (`OPENPROJECT-CVE-ANALYSIS.md`) still documents 22 real CVEs with exact endpoints. The path forward is a local Docker test → authenticated scan.

---

## Next Steps (Priority Order)

1. **[IMMEDIATE] Dio: verify Moneybird DOM XSS in browser** — open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome. If alert fires, the draft at `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` is ready to submit to HackerOne Moneybird.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. Highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. Auth scan on console.neon.tech could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

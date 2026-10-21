# Bounty Pool Triage — Updated 2026-10-21 (Session 9)

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

## Honest Assessment (Oct 2026, Session 9)

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

---

## Session 9 Analysis — October 21, 2026 (Report Drafter Auto-Run)

No new scan results since March 2026. This session reviews the Kredivo scan (never triaged) and triages the three pending Moneybird report drafts.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Scanned `blog.kredivo.com` (in scope per `scopes/kredivo.txt`). Only 10 pages crawled (stealth profile).

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing security headers (7 findings) | **FP** | All detected on pages returning HTTP 403 (bot protection active). Header analysis on blocked pages is meaningless — the real app is behind the WAF. |
| `_hcc` cookie missing HttpOnly/Secure | **FP** | `_hcc` is a CDN anti-bot challenge cookie (base64-encoded session token from the CDN layer, not the app). Missing flags on CDN challenge tokens is expected and not exploitable. |
| WordPress login `/wp-login.php` exposed (200) | **Informational** | `blog.kredivo.com` is a WordPress blog. wp-login.php being accessible is expected WordPress behavior, not a vulnerability. |
| Rate limiting on `/wp-login.php` | **FP** | Scanner fires 15 GET requests at the login page. Rate limiting applies to POST credential submissions, not page-load GETs. Same GET-probe FP as all other rate-limit findings. |

**Verdict:** 0 submittable findings. Blog subdomain fully hardened at CDN level during scan window.

### Moneybird — Pending Report Draft Triage

Three report drafts in `bounty-pool/pending/moneybird/`. Status below.

#### `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`

**Status: HOLD — needs manual browser verification before submission**

Scanner detected a potential DOM XSS on `www.moneybird.com` (marketing homepage):
- Detection: Playwright `dom-sink` — payload `#<img src=x onerror=alert("secbot-xss-37")>` reached `innerHTML` sinks (detected twice)
- Raw confidence: **medium** (Playwright auto-verify not triggered/confirmed)
- Response status in evidence: `0` — suspicious; may indicate navigation abort or challenge page during crawl

**Issues with the current draft:**
1. Draft claims confidence "high" but raw finding is "medium" — overstated
2. Steps to Reproduce use `curl` which cannot execute JavaScript. Fragment-based DOM XSS is entirely client-side; curl cannot reproduce it. Triagers will immediately reject a report with a broken PoC.
3. No screenshot of `alert()` firing
4. Impact references session cookie theft — but `www.moneybird.com` (marketing) and `app.moneybird.com` (accounting) have separate cookie scopes; actual impact may be limited to marketing page context

**Required before submission:** Manually navigate to `https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>` in a real browser (not curl). If `alert()` fires, capture a screenshot, update PoC to browser-based steps, and correct the confidence to medium. Then eligible for HackerOne.

#### `8c0823c1-postmessage-handlers-missing-origin-validation.md`

**Status: FP — archive this draft**

The handler code snippet reveals this is a mouse/event normalization polyfill, not an application message protocol:
> `function(i){(i=i||window.event).pageX||i.pageY...`

This is characteristic of third-party widget JavaScript (chat/analytics). postMessage listeners on the marketing homepage without origin checks match the known FP pattern (Intercom, Drift, Zendesk). Not exploitable, not submittable.

#### `09dd5267-missing-content-security-policy-header.md`

**Status: FP — archive this draft**

Marketing homepage missing CSP. Already identified as FP in Session 8. Auto-rejected by HackerOne triagers. No action.

### Session 9 Summary

- **New findings triaged:** 14 (Kredivo) + 3 pending Moneybird drafts
- **True positives drafted:** 0
- **Drafts archived as FP:** 2 (Moneybird postMessage, Moneybird missing CSP)
- **Drafts held for verification:** 1 (Moneybird DOM XSS — needs browser PoC)
- **Bounty readiness:** unchanged (LOW)

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

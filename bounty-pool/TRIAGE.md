# Bounty Pool Triage — Updated 2026-07-29 (Session 9)

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

## Session 9 Analysis — Previously Unreviewed Scans (Triaged 2026-07-29)

Two scan result files present in `scan-results/` were not covered in Session 8:
`scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json` (cal.com marketing site)
`scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json` (blog.kredivo.com)

Also reviewed: three draft reports sitting in `bounty-pool/pending/moneybird/`.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Target:** `https://blog.kredivo.com/` — WordPress blog subdomain (NOT the financial app)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login Page `/wp-login.php` (HIGH, CVSS 8.1) | **FP** | Accessible wp-login.php is standard WordPress behavior, not a vulnerability. The scanner upgraded severity but triagers will immediately reject this. Blog subdomain is almost certainly out of scope for a financial app bounty program. |
| Missing CSP Header (HIGH, CVSS 7.0) | **FP** | Marketing/blog subdomain. Auto-rejected as informational by triagers. |
| Cookie `_hcc` missing HttpOnly/Secure (MEDIUM) | **FP** | `_hcc` = HubSpot Click Count cookie (marketing analytics tracker). Classic analytics cookie FP pattern. |
| Rate Limiting on `/login` GET (MEDIUM/high) | **FP** | GET page-load probe only, no POST credential test performed. Same FP pattern as all other rate-limit findings. |

**Session 9 outcome: 0 new reports drafted. All 4 findings are FPs.**
Note: Future Kredivo scans should target `kredivo.com` or `app.kredivo.com` (financial app), not the blog subdomain.

---

### Cal.com v1 Marketing Site — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Target:** `https://cal.com/` — Marketing homepage (NOT `app.cal.com`)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on `/api/geolocation`, `/api/auth/session`, sitemap URLs (CRITICAL/high) | **FP** | Test URLs are `https://cal.com/api/../../../etc/passwd`. Vercel/Next.js normalizes URL paths before routing — the server returns its 404/200 HTML shell, not `/etc/passwd`. Scanner detected "system file content" heuristically from the large HTML response. No actual file content visible in evidence. |
| Exposed Admin Panel `/admin`, `/administrator`, `/manage`, `/manager`, `/management` (CRITICAL/high) | **FP** | Cal.com uses Next.js dynamic routes (`[username]/`). Any slug including "admin" resolves to a user booking page (body ~367KB = full Next.js HTML shell). These are user booking pages for hypothetical users named "admin", not admin panels. |
| Sensitive Data in URL — PostHog token (HIGH/high) | **FP** | URLs like `/api/web_experiments/?token=…` are PostHog analytics feature flag API calls. The `token=` is a PostHog project API key, not a user auth token. Intentional PostHog SDK usage. |
| XXE Injection on `/api/geolocation` (HIGH/medium) | **FP** | `/api/geolocation` is a JSON endpoint. Scanner sent XML payload and detected HTML error page as "DTD processing." Evidence shows standard HTML `<!DOCTYPE html>` response, not XML parser output. The `classic-file-read` technique reported "DTD processing detected" from the HTML doctype declaration — not a real XXE. |
| Missing CSP (HIGH/medium) | **FP** | Marketing homepage. Auto-rejected as informational. |
| `__Secure-next-auth.callback-url` missing HttpOnly (MEDIUM/medium, ×5 pages) | **FP** | Already documented in Session 8 for app.cal.com: this cookie stores the post-login redirect URL, not an auth token. Not sensitive. |
| Missing SRI for PostHog/CloudFront scripts (MEDIUM/medium) | **FP** | Third-party CDN analytics scripts. SRI not applicable for auto-updating CDN resources. Known FP pattern. |
| Rate Limiting on `/api/auth/session` (MEDIUM/high) | **FP** | `/api/auth/session` is a session getter (GET, returns current session state). Not an authentication endpoint. Known FP pattern. |
| OAuth missing state on `/api/auth/session` (MEDIUM/medium) | **FP** | Wrong endpoint — `/api/auth/session` is NextAuth's session reader, not an OAuth authorization endpoint. Already documented in Session 8. |
| OAuth PKCE not enforced on `/api/auth/session` (LOW/medium) | **FP** | Same wrong endpoint. Same Session 8 note. |

**Session 9 outcome: 0 new reports drafted. All 15 raw findings (deduplicated to 10 categories) are FPs.**

---

### Moneybird Pending Report Review (bounty-pool/pending/moneybird/)

Three draft reports auto-generated by scanner, reviewing for submission readiness:

| Report | Verdict | Reason |
|--------|---------|--------|
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | **HOLD — Manual Verification Required** | DOM XSS via `window.location.hash → innerHTML` on `www.moneybird.com` homepage. IF real, this is submittable. However: (1) curl cannot reproduce (curl doesn't execute JS); (2) the marketing homepage is a low-severity target for an accounting SaaS; (3) scanner evidence doesn't show the actual innerHTML sink in source. Needs manual browser verification: open the URL in DevTools, check if `#<img src=x onerror=alert(1)>` actually fires. Do NOT submit without browser confirmation. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP** | Steps to reproduce say "observe whether handlers process the data" — incomplete, no confirmed impact. Marketing sites routinely include postMessage handlers from Intercom, Drift, or other chat widgets that intentionally accept messages from any origin. Without identifying the specific handler and proving exploitation, this is a non-finding. Known FP pattern from CLAUDE.md. |
| `09dd5267-missing-content-security-policy-header.md` | **FP** | Marketing homepage missing CSP. Auto-rejected as informational by bug bounty triagers. Noted in Session 8 already. |

**Session 9 outcome: 2 of 3 moneybird drafts marked FP, 1 flagged for manual browser verification.**

---

## Session 9 Summary (2026-07-29)

**Session result: 0 new bounty reports submitted, 0 new reports drafted.**

Pattern is unchanged: unauthenticated scans of hardened targets (or wrong subdomains) produce passive/header findings only. The two unreviewed scans (Kredivo blog, cal.com marketing) were both against low-value subdomains that yield only marketing-site FPs.

**One manual action needed:** Verify the moneybird DOM XSS finding in a real browser before discarding it.

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

1. **Verify moneybird DOM XSS manually** — Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in a browser with DevTools open. If the alert fires, the draft at `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` is ready to submit to HackerOne. If it doesn't, mark as FP in TRIAGE.md.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction). Draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md`.
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Fix kredivo scan target** — Change `hunt-registry.yaml` Kredivo entry to target `app.kredivo.com` or `kredivo.com` instead of `blog.kredivo.com`. Blog scans produce only marketing-site FPs.
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

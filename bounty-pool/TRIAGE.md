# Bounty Pool Triage — Updated 2026-08-15 (Session 9)

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

---

## Session 9 Analysis — August 15, 2026

Three untriaged March 22 scans processed + three pre-existing moneybird pending drafts assessed.

### Moneybird Pending Drafts (bounty-pool/pending/moneybird/)

Three auto-generated drafts from an earlier scan session, never formally assessed in prior TRIAGE.md sessions.

| Finding | File | Verdict | Reason |
|---------|------|---------|--------|
| Missing CSP on www.moneybird.com | `09dd5267-missing-content-security-policy-header.md` | **FP** | Already triaged in Session 8. Marketing homepage — auto-rejected by triagers. Duplicate assessment. |
| postMessage handlers missing origin validation | `8c0823c1-postmessage-handlers-missing-origin-validation.md` | **FP** | Medium confidence, no confirmed impact. Scanner detected 3 postMessage listeners but could not enumerate handler logic or demonstrate any exploitable behavior. `curl` cannot reproduce. Likely third-party widget (Intercom/Drift pattern). Cannot submit without confirmed impact. |
| DOM XSS via URL fragment | `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | **NEEDS HUMAN VERIFICATION** | Claim is specific (`#<img src=x onerror=alert("secbot-xss-37")>`) and confidence is "high", suggesting Playwright may have detected an alert dialog. However: (1) `curl` cannot reproduce — fragments are never sent to server; (2) target is `www.moneybird.com` marketing homepage, not `app.moneybird.com`; (3) marketing homepage has no user session cookies, limiting bounty impact. **Action needed:** Manually visit `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome DevTools to confirm or deny. If confirmed real, submit as Low/Info due to marketing-page context with no session exposure. |

### Kredivo blog.kredivo.com — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Note:** Scan target is `blog.kredivo.com` (WordPress blog subdomain), not the main Kredivo fintech app. 10 pages attempted; homepage and sitemaps returned HTTP 403 (WAF blocked), but two specific probes reached the application.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP headers | **FP** | All header findings are from HTTP 403 WAF error pages. These reflect the WAF/CDN's error page headers, not the application. Not actionable. |
| `_hcc` cookie missing HttpOnly + Secure | **FP** | `_hcc` is the WAF challenge token (HubSpot CDN challenge cookie) issued by the 403 response — not an application cookie. Not actionable for bounty. |
| WordPress login page at `/wp-login.php` accessible (HTTP 200) | **Informational** | Real finding: `blog.kredivo.com/wp-login.php` returns HTTP 200 with a full WordPress login form (title: "Log In ‹ Kredivo — WordPress"). The WAF blocked the homepage but left `/wp-login.php` exposed. This is a real WordPress instance. However: (1) this is the blog subdomain, not the fintech app; (2) WordPress admin login exposure is typically informational/low severity in bug bounty programs; (3) check if `blog.kredivo.com` is in scope for Kredivo's RedStorm program before submitting. |
| Missing rate limiting on `/login` (GET, 15 rapid requests → all 200) | **FP** | GET page-load probe only. Rate limit on POST credential submission was not tested. Standard FP pattern. |
| Exposed `/wp-login.php` interpreted finding (CVSS 8.1 assigned) | **Over-scored** | Scanner combined the WordPress login exposure + missing rate limit into a high-severity interpreted finding. The CVSS 8.1 is inflated for a blog subdomain. If in scope, this would be low/informational. |

**Verdict:** One real but low-value finding (WordPress login exposed on blog subdomain). Worth checking if `blog.kredivo.com` is in scope for RedStorm before deciding to submit as Low/Informational. No injection or access control vulnerabilities found.

### Cal.com Marketing Site — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Note:** This scan targets `cal.com` (Framer marketing homepage), 5 pages scanned. Contains both `rawFindings` (header/cookie/sensitive-url) and 8 `interpretedFindings` including critical-severity claims. Partially superseded by the calcom-v2 scan, but the interpreted findings were not assessed in Session 8.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP headers | **FP** | Framer marketing site. Auto-rejected by triagers. Same as Session 8 calcom-v2. |
| Cookie `__Secure-next-auth.callback-url` missing HttpOnly | **FP** | Stores post-login redirect URL, not auth token. Same as Session 8 calcom-v2. |
| **Directory Traversal on `/api/geolocation`** (CVSS 9.0, critical, confidence medium) | **FP** | Scanner itself notes: "this may be a false positive caused by the scanner misinterpreting a generic error or redirect response as file content." `/api/geolocation` is a location lookup endpoint — it does not accept file path parameters. Cal.com is MIT open source and among the most-tested Next.js apps by security researchers. No evidence of actual `/etc/passwd` content in response. |
| **XXE Injection on `/api/geolocation`** (CVSS 9.1, critical, confidence medium) | **FP** | Both critical findings target the same endpoint. Scanner warns "manual verification recommended given WAF/CDN layer." A geolocation API returning IP-to-location data has no reason to parse XML. `detectionMethod: entity-expansion` likely means scanner sent XML and got a non-JSON error response that it misinterpreted. |
| **Exposed admin routes** (`/admin`, `/administrator`, `/manage`, etc.) returning HTTP 200 | **FP** | Already assessed in Session 8 calcom-v2: standard Next.js app shell. `/administrator` returns 404 on the app instance. Marketing site Next.js routes rendering HTML ≠ unprotected admin. Confidence is LOW in the scanner output. |
| **Sensitive token in URL** (`/api/web_experiments/?token=`) | **FP** | `token=` value appears empty in evidence. This is the PostHog feature flags SDK endpoint — the "token" is a public-facing anonymous project key, standard for client-side feature flag SDKs. Not a user auth token. Cal.com is open source and their PostHog project key is visible in the public codebase. |
| Rate limiting on `/api/auth/session` (GET probe) | **FP** | GET requests to the NextAuth session getter endpoint. Same FP pattern as calcom-v2 Session 8 analysis — rate limiting applies to POST credential submissions, not session-read GETs. |
| OAuth state on `/api/auth/session` | **FP** | Scanner probing wrong endpoint. Same as Session 8 calcom-v2 — NextAuth's `/api/auth/session` is not an OAuth authorization endpoint. NextAuth handles state parameter internally. |
| Missing SRI (7 external scripts: PostHog, Twitter Ads, CloudFront) | **FP** | Analytics/ads scripts — frequently updated, SRI not practical. Same as Session 8 calcom-v2. |

**Verdict:** All 8 interpreted findings are FP after context-aware review. The two critical scanner claims (traversal + XXE on `/api/geolocation`) are scanner artifacts with medium confidence and self-acknowledged uncertainty. No actionable bounty findings.

### OpenProject community.openproject.org v1 — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

**Note:** Superseded by openproject-v2 (March 26) triaged in Session 8. This scan has more findings than previously documented — raw findings include SRI and rate-limit checks in addition to header findings, and there are 2 `interpretedFindings`.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing Permissions-Policy, COOP/COEP/CORP headers | **Informational** | Strong overall security posture (nonce-CSP, HSTS, X-Frame-Options). Permissions-Policy absence is informational. Not submittable. |
| **Missing SRI on `cdn.aws-de-community.openproject.com`** (8 external resources, medium severity, high confidence) | **FP for bounty** | The CDN is OpenProject's own (`aws-de-community.openproject.com`) — not a third-party CDN they don't control. Missing SRI on your own CDN is technically a supply-chain risk, but community.openproject.org is OpenProject's own community instance. Submitting a bug about their own infrastructure to YesWeHack would be out-of-scope for the product program. If it were a customer-hosted instance, it might be relevant. Not submittable. |
| **Missing rate limiting on `/login` and `/login?back_url=...`** (GET, 15 rapid requests → all 200, medium severity) | **FP** | GET page-load probe only. Rate limiting is not expected on page-load endpoints. Same FP pattern as calcom-v2 and openproject-v2 Session 8 analysis. |
| Rate limiting on `/api/v3/attachments/.../content` and `/api/v3/configuration` (GET, low severity) | **FP** | Public read-only API endpoints returning non-sensitive configuration data. No rate limiting expected on publicly documented REST API endpoints. |

**Verdict:** No actionable findings. OpenProject community instance has strong security posture (nonce-CSP, HSTS, X-Frame-Options). SRI on own CDN is not a bounty-worthy finding for the community instance. Rate limit findings are all GET-probe FPs.

---

## Session 9 Summary

**Findings triaged this session: 9 across 4 scan sets + 3 pending drafts**
**New reports drafted: 0**
**Bounty readiness: Still LOW**

Same root cause: no injection vulnerabilities found in any scan, all medium+ findings collapse to FPs on review. The moneybird DOM XSS is the only item worth a 5-minute manual browser check.

---

## Next Steps (Priority Order)

1. **Manually verify Moneybird DOM XSS** — Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in browser. If alert fires, submit as Low (marketing page context, no session). If not, close `6d09cce8` as FP.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

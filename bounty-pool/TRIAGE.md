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

**Note:** Scan target is `blog.kredivo.com` (blog/WordPress subdomain), not the Kredivo fintech app.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | **FP** | **All findings from HTTP 403 response** — scanner was blocked by WAF/CDN from the first request. All header findings reflect the WAF error page headers, not the application. Scanner could not access any app content. `_hcc` cookie in Set-Cookie confirms WAF challenge enforcement. No findings are from the actual application. |
| Missing COOP/COEP headers | **FP** | Same reason — 403 WAF block on all 10 scanned URLs. |

**Verdict:** Zero actionable findings. Kredivo blog actively blocks unauthenticated scanners. If Kredivo is a priority target, focus on the main app endpoints after solving WAF bypass or using auth.

### Cal.com Marketing Site — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

**Note:** Superseded by calcom-v2 (March 26) scan already fully triaged in Session 8. This is the `cal.com` Framer marketing site (not `app.cal.com`), 5 pages scanned.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing CSP on cal.com/ (Framer marketing site) | **FP** | Marketing landing page on Framer CDN. Triagers auto-reject header findings on marketing sites. Same pattern as Session 8. |
| Other header findings | **FP** | Marketing site, same pattern. No new findings beyond Session 8 calcom-v2 assessment. |

### OpenProject community.openproject.org v1 — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

**Note:** Superseded by openproject-v2 (March 26) already triaged in Session 8. This earlier scan has a single finding.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing Permissions-Policy header | **Informational** | Only finding in entire scan. community.openproject.org has a strong CSP (nonce-based), HSTS, X-Frame-Options: SAMEORIGIN, X-Content-Type-Options. Permissions-Policy absence is informational at best, auto-rejected. Not submittable. |

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

# Bounty Pool Triage — Updated 2026-10-10 (Session 9)

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

## Session 9 Analysis — October 10, 2026

No new scans since session 8. This session covers housekeeping: triaging 3 previously unreviewed v1 scan files and clearing 3 stale pending reports from `bounty-pool/pending/moneybird/`.

### Stale Pending Reports — Moneybird (archived)

Three auto-generated reports from cycle 18 (March 22, 2026) were sitting in `bounty-pool/pending/moneybird/`. All moved to `bounty-pool/archived/`:

| File | Finding | Decision | Reason |
|------|---------|----------|--------|
| `09dd5267-missing-content-security-policy-header.md` | Missing CSP on www.moneybird.com | **FP** | Marketing homepage. Session 8 already triaged as auto-rejected by triagers. |
| `6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | DOM XSS via URL fragment | **FP confirmed** | Cycle 18 commit explicitly documents: "verified as FP in browser — no alert fired, payload was URL-encoded." Scanner bug was fixed in same commit. |
| `8c0823c1-postmessage-handlers-missing-origin-validation.md` | postMessage missing origin validation | **FP** | Homepage-only. 3 handlers likely from analytics/chat widgets (Intercom/HubSpot pattern). By design per CLAUDE.md FP rules. No exploitable path without XSS. |

### Cal.com v1 (March 22, 2026) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

Previously unreviewed. Session 8 covered the v2 scan; these findings are from the earlier v1 run on the same target.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation (critical, medium) | **FP** | No evidence fields populated. Endpoint is a standard geolocation API (lat/lon → timezone), not a file path handler. AWS WAF + Cloudflare in place. Scanner artifact. |
| XXE Injection on /api/geolocation (critical, medium) | **FP** | Same endpoint. Geolocation API accepts JSON, not XML. entity-expansion detection hit on non-XML endpoint. Scanner artifact. |
| Sensitive Token in URL /api/web_experiments/?token= (high, medium) | **Informational** | Token is empty in evidence. `/api/web_experiments/` is Cal.com's A/B variant assignment endpoint — the token is a variant identifier, not an auth credential. Not exploitable. |
| Missing SRI on External Scripts (medium, high) | **FP** | Third-party analytics/widget scripts. SRI not applicable for CDN-hosted auto-updating scripts. Standard FP pattern. |
| Missing Rate Limiting on /api/auth/session + /api/geolocation (medium, medium) | **FP** | Scanner sent 15 rapid GET requests to the NextAuth session-getter (`/api/auth/session`) and the public geolocation API (`/api/geolocation`). Neither is a credential submission endpoint; no brute-force vector exists on either. Same conclusion as session 8 v2 analysis. |
| OAuth State on /api/auth/session (medium, low) | **FP** | Wrong endpoint — session getter, not OAuth authorization endpoint. Session 8 v2 analysis confirmed. |
| Admin-like routes without auth (high, low) | **FP** | Low confidence. No concrete access demonstrated. |
| Auth Cookie Missing HttpOnly (low, high) | **Informational** | `__Secure-next-auth.callback-url` — stores post-login redirect, not auth token. Session 8 v2 analysis confirmed. |

### Kredivo (March 22, 2026) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

Never triaged. All findings on `blog.kredivo.com` (in scope per scope file).

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login (/wp-login.php) (high, high) | **Informational** | WordPress admin login accessible by design on all WordPress installations. Without rate limit bypass proof or version-specific CVE, triagers auto-close as informational. Needs: WP version fingerprint + CVE check, or rate limit bypass demo. |
| Missing CSP on blog.kredivo.com (high, high) | **FP** | WordPress marketing blog. No XSS found to chain with. Header-only findings on blog subdomains are auto-rejected. |
| Cookie `_hcc` Missing HttpOnly/Secure (medium, high) | **Unclassified / Likely FP** | Purpose not confirmed from scan evidence. `_hcc` does not match any known HubSpot pattern (`hubspot*`, `__hs*`, `__hstc`, `__hssc`, `__hssrc`). May be a CDN/security cookie or WordPress plugin cookie. Set on the marketing blog, not the main app — no XSS to chain with. **Needs manual browser check** to identify the setter before closing. |

### OpenProject v1 (March 22, 2026) — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

Previously unreviewed. Session 8 covered the v2 scan.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing Rate Limiting on /login (medium, medium) | **FP** | Scanner sent 15 rapid requests (POST without credentials). Failed login without valid creds = no real brute-force test performed. Same GET/unauthenticated-probe FP as session 8 v2 analysis. |
| Missing Rate Limiting on /api/v3/attachments/120892/content (medium, medium) | **Informational** | Public attachment download endpoint on community.openproject.org. 15 rapid GET requests got no 429. Attachments are publicly readable by design; rate limiting on a public file download is not a security finding. Informational at most. |
| Missing SRI on External Scripts (medium, high) | **FP** | Third-party scripts (CDN-hosted). Standard FP. |

### Honest Assessment (Oct 2026, Session 9)

**Status unchanged from session 8: bounty readiness LOW.**

No new scans have run in 6+ months. The stale Moneybird pending reports have been cleared (3 archived). The **Indeed CSRF draft** (`pending/2026-03-14-indeed-csrf-cookie-SUBMISSION.md`) remains the one live Tier 1 item awaiting manual verification. Zero injection findings across all scans; all other active findings are passive header/cookie issues.

**The bottleneck is scan depth, not scan quality.** SecBot correctly identifies and rules out FPs. What it cannot do unauthenticated is reach the authenticated endpoints where real bugs live.

### Next Steps (unchanged from Session 8)

1. **Submit Indeed finding** — only credible pending submission. Needs Playwright browser reproduction.
2. **OpenProject Docker test** — highest ROI. Authenticated scan against unpatched local instance.
3. **Add neon.tech to hunt registry** — has active HackerOne program with real auth surface.
4. **Authenticate Twitch** — unlock Tier 2 cookie findings.
5. **Fix own app** — rate limiting + HSTS on finance.atmando.app.

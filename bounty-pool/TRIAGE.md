# Bounty Pool Triage — Updated 2026-09-23 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------| ------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | blog.kredivo.com | Unprotected WP login — no rate limiting, username enumeration | High | CVSS 7.5. Full curl reproduction. blog.kredivo.com explicitly in scope (RedStorm). Draft ready: `2026-09-23-kredivo-wordpress-brute-force.md`. **Verify /wp-login.php still accessible before submitting.** |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------| ------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | openproject | Session Fixation: _open_project_session not regenerated | Medium | Scan detected same session cookie pre/post login on `community.openproject.org/login?layout=1`. **CAVEAT:** Scanner had no credentials — POST without valid credentials = failed login = session regeneration not triggered. Need authenticated test to confirm. Community instance is fully patched — test against local Docker (see OPENPROJECT-CVE-ANALYSIS.md). |
| 5 | cal.com | Sensitive token exposed in URL (`/api/web_experiments/?token=`) | High | HOLD — token is likely an A/B experiment config token, not a user auth token. Needs verification: what does the `token=` value look like? Is it per-user or global? Does it appear in Referer headers sent to third-party analytics? Cal.com is HackerOne. Worth escalating to Dio to check manually. CVSS 7.0. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

---

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------| ------|
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

## Session 9 Analysis — March 2026 Scans (Triaged 2026-09-23)

Three previously untriaged v1 scans processed: **kredivo**, **cal.com** (marketing site), **openproject v1**.

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WP Login + no rate limiting on /wp-login.php | **DRAFT REPORT** | blog.kredivo.com in scope. High/High confidence. No rate limiting confirmed by curl (20 requests, zero 429). Username enumeration via distinct error messages. Full report: `2026-09-23-kredivo-wordpress-brute-force.md`. Needs live verification before submission. |
| Missing CSP Header on blog.kredivo.com | **FP** | Marketing/company blog homepage. Missing headers on landing/marketing pages auto-rejected as informational. |
| Cookie `_hcc` missing HttpOnly/Secure | **FP** | `_hcc` = HubSpot Marketing Cookie (analytics/tracking). Third-party analytics cookie — canonical FP pattern. |

### Cal.com marketing site (cal.com) — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

Note: Session 8 triaged `app.cal.com` (calcom-v2). This is the marketing homepage (cal.com). Different surface.

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation (CRITICAL/medium) | **FP** | Next.js normalizes `/../../../etc/passwd` paths to 404. No actual file read. Agent confirmed HTTP 404 on all 6 variants. |
| XXE Injection on /api/geolocation (CRITICAL/medium) | **FP** | Geolocation endpoint sits behind Cloudflare WAF. Scanner matched "error" pattern in a Cloudflare 403 challenge page, not actual XML parser error. |
| Sensitive token in URL `/api/web_experiments/?token=` (HIGH/medium) | **HOLD** | Token likely an A/B experiment config, not auth token. CVSS 7.0. Needs Dio to manually inspect: what does `token=` contain? Is it per-user? Does it leak via Referer to PostHog/Twitter Ads scripts on the page? Added to Tier 2. |
| Missing rate limiting on /api/auth/session (MEDIUM/medium) | **FP** | `/api/auth/session` is NextAuth's current-session getter (GET endpoint), not an auth submission endpoint. Same FP as calcom-v2 in Session 8. |
| Missing SRI on 7 external scripts (MEDIUM/high) | **FP** | PostHog, Twitter Ads, CloudFront analytics scripts on marketing site. SRI not applicable to frequently-updated CDN scripts. Same as calcom-v2 FP in Session 8. |
| Exposed admin routes (HIGH/low) | **FP** | `/admin` in Next.js on cal.com is a valid user booking slug (cal.com/admin). Not an actual admin panel. |
| OAuth state missing on /api/auth/session | **FP** | Wrong endpoint — session getter, not OAuth authorization endpoint. |

### OpenProject v1 (community.openproject.org) — `scan-results/openproject/secbot-2026-03-22T12-38-03-985Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing rate limiting on /login (MEDIUM/medium) | **FP** | GET page-load probe. Same FP as all other rate limit findings across every scan. |
| Missing SRI on external scripts (MEDIUM/high) | **FP** | Community forum. Third-party scripts without SRI. YesWeHack triagers would reject as informational. |

---

## Honest Assessment (Sep 2026, Session 9)

**Bounty readiness: LOW but improving.** 16 new findings analyzed, 1 draft report produced.

Key pattern continues: unauthenticated scans on hardened targets → passive findings + FPs.

**One genuine signal this session:**
- Kredivo WP login brute-force — a real, reproducible, in-scope finding. Bounty: ~Rp 1,500,000 (~$95).

**Pattern broken once:** cal.com token-in-URL is worth a manual look — could be a weak medium if the token is per-user.

---

## Next Steps (Priority Order)

1. **Verify and submit Kredivo WP login** — Check `curl -I https://blog.kredivo.com/wp-login.php` still returns 200. If yes, submit `2026-09-23-kredivo-wordpress-brute-force.md` to RedStorm. Expected: High bounty (~$95 USD). Fast to triage since it's fully reproducible with curl.
2. **Investigate cal.com token-in-URL** — Load cal.com in browser with DevTools network tab. Check what `token=` in `/api/web_experiments/` contains. If it's a user-specific value (not a global config key), escalate to HackerOne.
3. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
4. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
5. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
6. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

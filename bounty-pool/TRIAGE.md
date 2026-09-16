# Bounty Pool Triage — Updated 2026-09-16 (Session 9)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM-Based XSS via URL Fragment on homepage | Medium | Playwright confirmed payload `#<img src=x onerror=...>` reached two innerHTML sinks. CSP is report-only only, allows unsafe-inline. **CAVEAT:** On marketing homepage (www.moneybird.com), not the app — impact depends on cookie sharing. **Requires browser verification before submit.** Draft: `2026-09-16-moneybird-dom-xss.md` |

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

---

## Session 9 Analysis — March 2026 Scans Re-triaged (2026-09-16)

Session 8 missed several findings in `interpretedFindings` (used wrong JSON key during parse). Full re-triage of all 7 scan result files.

### Moneybird — `scan-results/moneybird/secbot-2026-03-22T12-37-45-339Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| DOM-Based XSS via URL Fragment | **DRAFT REPORT** | Playwright confirmed `#<img src=x onerror=alert("secbot-xss-37")>` reached two `innerHTML` sinks on `www.moneybird.com`. CSP is report-only (not enforced). Scope: `moneybird.com` covers `www.moneybird.com`. Impact caveat: marketing homepage, no auth context confirmed. Browser verification required to check cookie scope. → `2026-09-16-moneybird-dom-xss.md` |
| postMessage Handlers Missing Origin Check | **FP** | Handler snippet is a mouse event polyfill (`i.pageX || i.pageY || ...`), not a chat widget. Even if triggered via postMessage, it processes mouse coordinate data only — no sensitive action or data sink reachable. |
| Missing CSP (already triaged) | **FP** | Marketing homepage, same verdict as Session 8. |
| Mixed Content (already triaged) | **Informational** | Same verdict as Session 8. |

### Kredivo — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login Page (/wp-login.php) | **Informational** | `blog.kredivo.com` is a marketing blog, not the app. WordPress admin login being publicly accessible is standard WordPress behavior. Raw finding was `[info-disclosure][low][low]` before AI upgrade. RedStorm programs rarely reward this. Not worth submitting. |
| Missing Rate Limiting on /login | **FP** | Same GET-probe pattern as all other rate limit FPs. No POST credential test. |
| Cookie `_hcc` Missing HttpOnly/Secure | **FP** | `_hcc` = HubSpot click cookie (analytics). Third-party tracking cookie — not bounty-worthy. |
| Missing CSP | **Informational** | Blog subdomain, marketing content. |

### Cal.com v1 — `scan-results/cal-com/secbot-2026-03-22T11-36-33-679Z.json`

| Finding | Verdict | Reason |
|---------|---------|--------|
| Directory Traversal on /api/geolocation | **OUT OF SCOPE** | Per `scopes/calcom.txt`: `cal.com` (marketing) is explicitly OUT OF SCOPE. Only `app.cal.com` is in scope. All v1 findings invalid. |
| XXE on /api/geolocation | **OUT OF SCOPE** | Same — cal.com is excluded. |
| Sensitive Token in URL (/api/web_experiments/?token=) | **OUT OF SCOPE + FP** | Out of scope AND the token is a web experiments (feature flags) token, not an auth token. |
| Admin-like routes without auth | **OUT OF SCOPE** | Same. |

### Cal.com v2 — `scan-results/calcom-v2/secbot-2026-03-26T08-17-21-602Z.json`

All v2 findings on `app.cal.com` (in scope) re-triaged:

| Finding | Verdict | Reason |
|---------|---------|--------|
| XPath Injection × 3 (month, user, _rsc params) | **FP** | Cal.com uses Prisma ORM + PostgreSQL. No XPath processing anywhere. Boolean difference detection is a SQLi heuristic misfiring on response variance. `_rsc` is a Next.js RSC internal param, not user-facing. |
| XXE on /api/trpc/features/map | **FP** | tRPC endpoint, JSON-only. No XML parser in use. "parameter-entity" XXE technique on a JSON endpoint = guaranteed FP. |
| LDAP Injection on /auth/login?user=1 | **FP** | Cal.com authenticates via NextAuth (database strategy). No LDAP in the stack. |
| HTTP Method Override × 4 (on /api/trpc/me/myStats and /api/trpc/slots/getSchedule) | **FP** | These are unauthenticated read-only tRPC endpoints. Even if server processes the override header, sending DELETE to a stats/availability endpoint has no security impact. Scanner detected response difference (405 vs 200) as "accepted" — not actual method processing. |
| Web Cache Deception (already triaged) | **FP** | cf-cache-status: DYNAMIC, same verdict as Session 8. |

### Neon.tech, OpenProject (previously triaged in Session 8)

No change from Session 8 analysis. All findings confirmed FP.

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

1. **Verify + Submit Moneybird DOM XSS** — Open `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` in a browser. If alert fires, also check `document.cookie` to assess session data exposure. If real, submit `2026-09-16-moneybird-dom-xss.md`. Likely Medium severity (~$200-500 if accepted).
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

## Session 9 Honest Assessment (Sep 2026)

**Bounty readiness: LOW but improving.** Session 9 found a genuine missed finding:
- 1 DOM XSS on Moneybird marketing page (high/high Playwright confirmed) — needs browser verification
- Previous session missed it due to parsing the wrong JSON key (`findings` vs `interpretedFindings`)
- All other scans: consistent FP pattern (headers, cookies, injection FPs on non-vulnerable stacks)
- Still zero injection vulns found on authenticated endpoints

**Root cause unchanged:** Unauthenticated scanning on hardened targets = passive findings only.
Moneybird DOM XSS is the first potentially submittable finding since the Indeed CSRF cookie report.

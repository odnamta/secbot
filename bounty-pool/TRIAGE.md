# Bounty Pool Triage — Updated 2026-07-18 (Session 9)

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
| 5 | moneybird | DOM XSS via URL Fragment on www.moneybird.com | High | Playwright found XSS payload in two innerHTML sinks (dom-sink detection). Alert has NOT been confirmed to fire. Report draft: `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. **Action: Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome. If alert fires → submit. If not → archive.** |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented
- moneybird Missing CSP (`09dd5267`) — FP, marketing homepage, auto-rejected
- moneybird postMessage origin (`8c0823c1`) — FP, widget mouse-event handler code (not security-relevant)

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

## Session 9 Analysis — July 18, 2026

Two new targets processed: **Kredivo** (March 22, 2026 scan — first-time triage) and **Moneybird missed findings** (Session 8 incomplete triage of March 22 scan).

### Kredivo (RedStorm) — `scan-results/kredivo/secbot-2026-03-22T12-37-39-601Z.json`

**Scan target was `blog.kredivo.com` (marketing blog), NOT the main finance app. Main kredivo.com returned 403 — scanner was WAF-blocked.**

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login Page on blog.kredivo.com | **FP/Out-of-scope** | `blog.kredivo.com` is the marketing blog. Public `/wp-login.php` is standard WordPress — not an exploitable finding on a blog. Kredivo's finance app scope is likely `kredivo.com`/`pay.kredivo.com`, not the blog. |
| Missing CSP on blog.kredivo.com | **FP** | Marketing blog returning HTTP 403 (WAF blocked). Header findings on blocked/marketing pages = auto-rejected. |
| `_hcc` cookie missing HttpOnly/Secure | **FP** | `_hcc` = HubSpot tracking/analytics cookie. Third-party marketing cookie intentionally exposed to JavaScript for widget state management. Classic FP pattern. |
| Rate limiting on GET /login | **FP** | GET page-load probe only. Same false-positive as all prior rate-limit findings. |

**Overall:** 0 submittable findings. Scanner was blocked on the primary target. To properly scan Kredivo, need to identify in-scope subdomains (pay.kredivo.com, app.kredivo.com, api.kredivo.com) and retry with stealth profile.

### Moneybird (HackerOne) — Session 8 Missed Findings

Session 8 only reviewed CSP + Mixed Content from the March 22 scan. Three `interpretedFindings` were skipped:

| Finding | Verdict | Reason |
|---------|---------|--------|
| DOM XSS via URL Fragment on www.moneybird.com | **HOLD** | Playwright navigated to `https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>` and detected the payload in two separate innerHTML sinks. This is real browser-based evidence (not heuristic). Alert execution has NOT been confirmed. **Needs manual verification in browser before submitting.** Report draft in `bounty-pool/pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. |
| postMessage handlers without origin check | **FP** | Handler code snippet shows mouse event coordinate normalization (`pageX`/`clientY`), not message data processing. This is a marketing widget (likely scroll/animation handler) attached to multiple event types. Not a security-relevant postMessage vulnerability. Archived. |
| Open Redirect via url/redirect/next/returnTo/etc. params | **FP** | Same pattern as neon.tech Session 8. `Location` header redirects to `moneybird.com/login?param=https://evil.example.com` — redirect target is `moneybird.com` itself, NOT `evil.example.com`. Scanner detected the parameter being forwarded, not an actual open redirect. |

---

## Honest Assessment (Jul 2026, Session 9)

**Bounty readiness: LOW, but one unverified active finding.** Session 9 brings the first potential XSS finding (moneybird DOM XSS, Tier 2 #5), which is meaningfully different from prior passive-only sessions. Still no confirmed injection findings.

- Kredivo scan was blocked (WAF) — blog subdomain only, all findings FP
- Moneybird Session 8 triage was incomplete — 3 findings were missed; all but DOM XSS are FP
- DOM XSS (moneybird) has real Playwright evidence but needs browser confirmation of alert() execution
- No authenticated scanning performed on any target (unchanged)

**Root cause unchanged:** Unauthenticated scan + hardened targets = passive findings only. The DOM XSS is a potential break in this pattern but requires manual confirmation.

**Path forward:** OpenProject Docker test remains highest-ROI next step. The moneybird DOM XSS browser check is a 2-minute task that could yield a real submission.

---

## Next Steps (Priority Order)

1. **[2 min] Verify moneybird DOM XSS** — Open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome DevTools. If alert fires → complete the `6d09cce8` report with a screenshot and submit to HackerOne. If not → archive. No tools needed.
2. **Submit Indeed finding** — CSRF cookie inconsistency. Only if Dio confirms willingness (cookie is JS-set, needs Playwright reproduction).
3. **Authenticate Twitch** — Get Twitch account, run `secbot scan --auth-cookie` to unlock Tier 2 cookie findings.
4. **OpenProject Docker test** — Spin up `openproject/openproject:16.6.2` (pre-patch), create two user accounts, run `secbot scan --auth ... --idor-alt-auth ...`. This is the highest-ROI next step.
   - CVE-2026-27716 (`GET /api/v3/custom_fields/{id}/items`) — quick IDOR win
   - CVE-2026-23646 (`DELETE /my/sessions/{id}`) — session IDOR
   - CVE-2026-27731 (emoji reaction → internal comment leak) — reader-level IDOR
   - CVE-2026-24685 (git rev argument injection → file write) — Critical RCE if repo enabled
5. **Add neon.tech to hunt registry** — Neon has an active HackerOne program. App is PostgreSQL-as-a-service with real auth (console.neon.tech). Auth scan could find IDOR/BAC in API.
6. **Fix own app** — rate limiting + HSTS on finance.atmando.app (unchanged from March).

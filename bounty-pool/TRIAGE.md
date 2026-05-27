# Bounty Pool Triage — Updated 2026-05-27 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM XSS via URL Fragment (innerHTML sink) | High | **Best active finding.** Confirmed via dom-sink detection: `#<img src=x onerror=alert("secbot-xss-37")>` fires on homepage. Draft: `pending/moneybird/6d09cce8-dom-based-xss-via-url-fragment.md`. Needs Dio to verify manually in browser before submitting. |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | moneybird.com | postMessage handlers missing origin validation (3 listeners) | Medium | Draft: `pending/moneybird/8c0823c1-postmessage-handlers.md`. Medium confidence — scanner couldn't fully enumerate handler logic. Needs manual review of what handlers actually do with messages. |
| 5 | blog.kredivo.com | WordPress login accessible + no rate limiting | Medium | REAL FINDING. blog.kredivo.com is explicitly in Kredivo RedStorm scope. WP login returns 200 (9360 bytes), 15 rapid requests all succeed. Draft: `pending/2026-05-27-kredivo-wp-login-bruteforce.md`. Needs Dio to check if xmlrpc.php also accessible before submitting. |

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

## Session 8 Triage — 2026-05-27

**Scans processed:** 5 scan files (neon-v2, openproject-v2, kredivo, cal-com, moneybird — dates Mar 22-26)

### Findings Triaged This Session

| Target | Finding | Decision | Reason |
|--------|---------|----------|--------|
| neon.tech | SQLi in /unify?a=&n= (14 instances) | **ARCHIVE FP** | "SQL error: postgresql/tutorial" is a navigation link in Neon's site HTML (`<a href="/docs/postgresql-tutorial">`), not an actual DB error. Scanner matched site content literally. |
| neon.tech | Directory Traversal on /unify (6 instances) | **ARCHIVE FP** | Payload `..\..\..\..\etc\passwd` uses Windows-style backslashes on a Linux Node.js app. Path is in URL segment, not parameter. CDN normalizes before app sees it. |
| neon.tech | Server-Side Prototype Pollution | **ARCHIVE FP** | Response was HTTP 403 Cloudflare challenge page. "Canary reflected" = query params echoed in Cloudflare's own challenge page HTML. Not actual prototype pollution. |
| neon.tech | Open Redirect on /login (8 params) | **ARCHIVE FP** | Redirect goes `neon.tech/login` → `neon.com/login?param=evil.example.com`. Target is their own domain (neon.com), not evil.example.com. Single-hop redirect on same org. |
| neon.tech | Verbose Error "Database error details" on /undefined | **ARCHIVE FP** | Same root cause as SQLi FP — "postgresql/tutorial" text in the page HTML is a nav link. 404 page includes full navigation, including PostgreSQL Tutorial link. |
| neon.tech | Missing HSTS, CSP, cookies | **ARCHIVE** | Marketing/landing site passive findings. Not bounty-worthy. Note: neon.tech NOT in hunt-registry — was a one-off scan. |
| community.openproject.org | All findings (info/low: missing COOP, COEP, CORP, Permissions-Policy, CSP unsafe-inline) | **ARCHIVE** | Community instance with good security posture. All findings are info/low passive headers. OpenProject CVE testing requires a local Docker instance (see OPENPROJECT-CVE-ANALYSIS.md). |
| cal.com | Directory Traversal on /api endpoints (6 instances) | **ARCHIVE FP** | `../../../etc/passwd` in URL path — Cloudflare normalizes path traversal before it reaches the app. "System file content" detection = scanner FP pattern match. |
| cal.com | Exposed Admin Panels /admin, /administrator, /manage, /manager, /management | **ARCHIVE FP** | Cal.com is a Next.js SPA. Returns HTTP 200 with full React bundle (~367KB) for ALL unmatched routes. These are not admin panels — scanner confused 200 + large body for exposed admin. |
| cal.com | Rate Limiting missing on /api/auth/session | **ARCHIVE FP** | The `/api/auth/session` endpoint is a read-only GET that returns current session state (empty/null for anonymous users). Rate limiting a stateless session check is not a security requirement. |
| cal.com | Sensitive token in URL (token= params) | **ARCHIVE FP** | All `token=` parameters have empty values — these are PostHog feature flag API calls with blank token. No actual token exposed. |
| cal.com | OAuth state parameter missing on /api/auth/session | **ARCHIVE FP** | Scanner tested OAuth flow on a session status endpoint, not an OAuth endpoint. Wrong endpoint for this check. |
| cal.com | XXE on /api/geolocation | **ARCHIVE FP** | Geolocation API (IP → country lookup) does not parse XML input. XXE payload returning non-error response is a scanner FP. |
| cal.com | Missing CSP, cookie flags, SRI | **ARCHIVE** | Passive findings on hardened target. Not bounty-worthy standalone. |
| blog.kredivo.com | WP Login exposed + no rate limiting | **TIER 2 HOLD** | Real finding, in-scope target. Draft created. Needs manual verification of xmlrpc.php before submitting. |
| blog.kredivo.com | Cookie _hcc missing HttpOnly/Secure | **ARCHIVE FP** | `_hcc` is HubSpot Chat Cookie — third-party analytics/chat widget. Not bounty-worthy per standard FP rules. |
| blog.kredivo.com | Missing CSP header | **ARCHIVE** | Marketing blog, passive finding. Auto-rejected. |
| moneybird.com | Mixed Content (98 instances) | **ARCHIVE FP** | All instances are HTTP `<a href="http://www.moneybird.com/...">` links on moneybird.com's own domain. These are internal links (not resource loads) that would redirect to HTTPS. Browser mixed content blocking only applies to actual resource loads (scripts, images), not links. |
| moneybird.com | Open Redirect on /login (8 params) | **ARCHIVE FP** | `www.moneybird.com/login` → `moneybird.com/login?param=evil.example.com`. Redirects to their own apex domain, evil URL is only preserved in query string param, not used as redirect destination. |
| moneybird.com | SRI missing on GTM scripts | **ARCHIVE FP** | Missing SRI on `gtm.moneybird.com/gtag/js` — this is their own Google Tag Manager hosted on their own subdomain. SRI on first-party analytics is not required/expected. Auto-rejected by bounty programs. |
| moneybird.com | Race condition on /features/bookkeeping/ | **ARCHIVE FP** | 10 concurrent GET requests to a marketing page all returning 200 is not a race condition. Race conditions require state-changing endpoints where concurrent access creates a TOCTOU window. |
| moneybird.com | DOM XSS (already drafted) | **TIER 1 KEEP** | Already triaged in Session 7. Strongest finding. |
| moneybird.com | postMessage no origin validation (already drafted) | **TIER 2 KEEP** | Already triaged in Session 7. Needs manual validation. |
| moneybird.com | Missing CSP (already drafted) | **TIER 2 COMPANION** | Only submittable as amplification companion to the DOM XSS report. |

---

## Honest Assessment (2026-05-27)

**Bounty readiness: LOW-MEDIUM.** After 30+ targets scanned across 8 sessions:
- 1 strong active finding: Moneybird DOM XSS (needs manual browser verification)
- 1 medium finding: Kredivo WP login + no rate limiting (real, in scope)
- All other findings were passive or FPs

**Key FP patterns confirmed this session:**
- PostgreSQL company (Neon.tech) site content triggers SQLi pattern matching = major FP source
- Next.js SPA returning 200 for all paths = admin panel FP  
- Path traversal with backslashes on Linux = guaranteed FP
- Cloudflare 403 challenge page = reflected-canary FP for prototype pollution
- www.domain → domain redirect = open redirect FP
- HTTP internal links on HTTPS pages = mixed content FP
- Empty `token=` params = sensitive URL FP

**What needs to happen:**
1. Dio manually verifies Moneybird DOM XSS in browser → submit if confirmed
2. Dio checks blog.kredivo.com/xmlrpc.php accessibility → if accessible, strengthens Kredivo WP report
3. OpenProject CVEs require local Docker testing with authenticated accounts (see OPENPROJECT-CVE-ANALYSIS.md)
4. Fix own app issues: rate limiting + HSTS on finance.atmando.app

## Next Steps (Priority Order)

1. **Verify Moneybird XSS** — open browser, test `https://www.moneybird.com/#<img src=x onerror=alert(1)>` — if alert fires, submit immediately
2. **Check Kredivo xmlrpc.php** — `curl -sI https://blog.kredivo.com/xmlrpc.php` — if 200, add to report for higher impact
3. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
4. **OpenProject Docker** — set up local instance for CVE testing (see OPENPROJECT-CVE-ANALYSIS.md) to find real vulns rather than passive header findings
5. **Get Twitch credentials** — unlock T2 auth-cookie finding

---

## Previous Sessions

**Session 7 (Mar 15, 2026):** Indeed CSRF, Moneybird XSS + postMessage + CSP drafts. All T2 cookie findings remain on hold.

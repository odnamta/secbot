# Bounty Pool Triage — Updated Jun 10, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM-Based XSS via URL fragment on homepage | Medium | Playwright auto-verified (marker `secbot-xss-37`, 2 innerHTML sinks). www.moneybird.com is in scope. No CSP present (impact amplifier). **ACTION:** Draft ready at `pending/2026-06-10-moneybird-xss-homepage.md`. Manually confirm in browser before submitting — navigate to `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>` and verify alert fires. |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | moneybird.com | postMessage handlers missing origin validation (homepage) | Medium | HOLD — automated scan detected 3 handlers without origin checks. Handler logic unknown; likely marketing widgets (HubSpot, Intercom). **Do not submit without manual JS analysis** — open DevTools, run `window.addEventListener('message', e => console.log(e))`, trigger handlers, observe if they do anything security-relevant beyond widget communication. Raw draft: `pending/moneybird/8c0823c1-postmessage-handlers-missing-origin-validation.md` |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented
- moneybird.com missing CSP (standalone) — Informational alone; bundled as impact amplifier into the XSS submission (`pending/2026-06-10-moneybird-xss-homepage.md`). Raw draft: `pending/moneybird/09dd5267-missing-content-security-policy-header.md`
- cal.com directory traversal / admin panels / XXE / sensitive URLs — **OUT OF SCOPE**: scan targeted `cal.com` but the Cal.com HackerOne program explicitly excludes the marketing site; only `app.cal.com` is in scope. Reschedule scan against `app.cal.com`.
- kredivo blog findings (missing CSP, cookie flags, /wp-login.php, rate-limit on WP /login) — Expected WordPress blog behaviour on `blog.kredivo.com`; none bounty-worthy. Reschedule scan against `app.kredivo.com` (authenticated).

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

## Session 8 Assessment (Jun 10, 2026)

**Bounty readiness: IMPROVING.** 1 genuine active vulnerability drafted for submission.

**New this session:**
- Moneybird DOM XSS on homepage — first *active* (non-passive) finding across all target scans. Playwright auto-verified. Polished HackerOne draft ready.
- Triaged new scan results from 4 targets (moneybird, kredivo, cal.com, openproject)
- Identified scope error: cal.com scans targeted wrong domain (should be `app.cal.com`)
- Identified scan gap: all Kredivo + OpenProject findings were unauthenticated — zero findings on authenticated surfaces

**What changed vs Session 7:**
- Previously: 0 active vulns, all passive headers/cookies
- Now: 1 active DOM XSS (medium, HackerOne-submittable) ready to go
- Correct CVSS: 6.1 (original auto-generated file incorrectly stated 7.0)

## Honest Assessment (Jun 10)

**Root causes of low yield remain:**
1. Unauthenticated scans miss IDOR, BFLA, business logic — the majority of real bounties
2. Wrong target URLs scanned (cal.com vs app.cal.com)
3. No authenticated scan on app.kredivo.com (requires real fintech account)

## Next Steps (Priority Order)
1. **Submit Moneybird DOM XSS** — manually verify in browser first, then submit `pending/2026-06-10-moneybird-xss-homepage.md` to HackerOne
2. **Fix scan targets** — update hunt registry: cal.com → app.cal.com, blog.kredivo.com → app.kredivo.com
3. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app (still outstanding since Session 7)
4. **Get Kredivo + cal.com credentials** — authenticate before scanning to unlock IDOR/BFLA checks
5. **Manually verify postMessage** on moneybird.com — could be T1 if handlers are non-trivial
6. **Indeed submission** — Dio to confirm willingness (cookie is JS-set, reproduction tricky)

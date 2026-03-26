# Bounty Pool Triage — Updated Mar 15, 2026 (Session 7)

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

## Honest Assessment (Mar 15)

**Bounty readiness: LOW.** After 27+ targets scanned:
- 0 critical/high vulnerabilities found on external targets
- All findings are passive (headers, cookies) — no injection vulns
- Cookie findings require browser reproduction (not curl-verifiable)
- No authenticated scanning performed

**What actually worked:**
- Finding real issues on our OWN app (rate limiting, HSTS)
- 0% FP rate across all scans
- Correctly identifying and filtering non-exploitable findings

**Root cause unchanged:** Marketing sites + no auth + hardened targets = passive findings only.

## Next Steps (Priority Order)
1. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
2. **Get test credentials** — Twitch account for auth scan, unlock T2 findings
3. **Scan less-hardened targets** — community apps, smaller BBPs, OWASP Juice Shop
4. **Indeed submission** — only if Dio confirms willingness (cookie is JS-set, reproduction tricky)

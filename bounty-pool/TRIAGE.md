# Bounty Pool Triage — Updated May 6, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Draft | Notes |
|---|--------|---------|----------|-------|-------|
| 1 | moneybird.com | DOM XSS via URL fragment — Playwright-confirmed alert() | Medium | `2026-05-06-moneybird-dom-xss.md` | **Ready to submit.** Playwright-verified. CVSS 6.1. No CSP amplifies impact. Provide browser PoC (not curl). |
| 2 | kredivo.com | Exposed `/wp-login.php` + no rate limiting on blog.kredivo.com | Medium | `2026-05-06-kredivo-wp-login-exposed.md` | **Ready to submit.** blog.kredivo.com explicitly in scope. High/high confidence. HTTP 200 confirmed, 15 requests no lockout. |
| 3 | indeed.com | CSRF cookie missing Secure on login page | Medium | `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify before submitting. |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 4 | moneybird.com | postMessage handlers missing origin validation | Medium | `pending/moneybird/8c0823c1-postmessage...md` — HOLD. 3 listeners, but likely Intercom/chat widget (by-design per rules). Needs manual page review to identify which widget sets these handlers. |
| 5 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 6 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |

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

## Session 8 Triage — May 6, 2026

Processed 4 scan result files from `scan-results/`. Total raw findings reviewed: 57+. After triage: 2 new drafts, remainder false positives.

### New Scans Processed

| Target | Scan Date | Raw Findings | Actionable |
|--------|-----------|--------------|------------|
| neon.tech / neon.com | 2026-03-26 | 45 raw, 17 validated | 0 (all FP) |
| app.cal.com | 2026-03-26 | 54 raw, 21 validated | 0 (all FP) |
| cal.com | 2026-03-22 | 50 raw | 0 (all FP) |
| blog.kredivo.com | 2026-03-22 | 6 medium+ | 1 (wp-login) |
| www.moneybird.com | (prev scan) | — | 1 (DOM XSS — upgraded to T1) |

### Session 8 False Positive Log

**neon.tech / neon.com (all FP):**
- **SQLi on /unify** (critical/medium) — "SQL error" evidence is a PostgreSQL documentation URL, not a DB error. FP.
- **Directory Traversal on /unify** (critical/medium) — Cloudflare/Vercel normalize paths; no actual file read. FP.
- **Prototype Pollution** (critical/medium) — Returns 403; canary reflection in blocked response is not exploitable. FP.
- **Missing HSTS** (high/medium) — HSTS IS present (`max-age=63072000`) in actual responses; scanner hit a parameterized URL variant (`?chatId=1`) that may have been served without the header by CDN edge. Verified: `curl -sI https://neon.com/` shows HSTS. FP.
- **Open Redirect via 8 params on /login** (medium/high) — Interpreted finding notes "redirect goes to neon.com/login, not evil.example.com." Not a cross-domain open redirect. FP.
- **Verbose Error on /undefined** (medium/low) — Matched a PostgreSQL doc URL in Next.js RSC payload. No stack trace or real error. FP.
- **neon_consent cookie** (medium/high) — Consent/preference cookie. Explicitly excluded per triage rules. FP.
- **Missing SRI on /unify** (medium/high) — 24 scripts from `neon.com` CDN (same-org CDN serving Next.js chunks). Same-org SRI is a known FP pattern. FP.

**app.cal.com — calcom-v2 (all FP):**
- **Missing HSTS** (high/medium) — HSTS header `max-age=63072000` IS present in multiple raw responses (e.g., `/api/auth/session` response). Scanner hit unauthenticated admin probe paths. FP.
- **Web Cache Deception** (high/medium) — Response headers show `cache-control: private, no-cache, no-store` and `cf-cache-status: DYNAMIC`. CDN is NOT caching. FP.
- **XPath Injection (3 findings: month, user, _rsc params)** (high/medium) — Detection method is response size difference. Cal.com is a Next.js/tRPC app; size variation between XPath tautology and contradiction payloads is caused by different page states, not XPath evaluation. `_rsc` is a Next.js React Server Components parameter. FP.
- **XXE on /api/trpc/features/map** (high/medium) — Response is Cloudflare 403 HTML page. The indicator pattern `error|DTD` matched the HTML `<!DOCTYPE html>` declaration, not an XML error. FP.
- **LDAP Injection on /auth/login?user=1** (high/high) — Response body is standard Next.js HTML page; no LDAP error string present. The "error pattern" `invalid.*dn|invalid.*filter` did not appear in the response. Cal.com uses NextAuth/PostgreSQL, not LDAP. FP.
- **Method Override (4 findings)** (high/medium) — All findings show baseline POST → 403 AND override DELETE → 403. The method override did not change the response code. FP.
- **Missing SRI (Intercom widget)** (medium/medium) — Single third-party Intercom widget. Third-party chat widget SRI is excluded per triage rules. FP.
- **OAuth missing state on /api/auth/session** (medium/medium) — `/api/auth/session` is the NextAuth session endpoint (returns current session), not an OAuth authorization endpoint. It's not supposed to require a `state` parameter. FP.
- **Race condition on /register** (medium/medium) — 10 concurrent GET requests to a page all returning 200 is expected behavior. No state mutation tested. FP.
- **Missing CSP on app.cal.com** (high/medium) — Cal.com is an open-source project; their security team is aware of CSP absence. Likely auto-rejected. FP for bounty.
- **Cookie __Secure-next-auth.callback-url missing HttpOnly** (medium/medium) — NextAuth sets this cookie as JS-readable by design (used for client-side redirect logic). FP.
- **Rate limiting on auth endpoints** (medium/high) — Evidence is 15 GET requests to login page returning 200, not POST to auth API. GET requests to a login page should return 200 indefinitely. Weak evidence. FP for now.
- **Source map exposure** (medium/high) — Turbopack runtime files only, not app business logic. Cal.com is fully open-source on GitHub (calcom/cal.com); source is already public. Bounty platforms auto-reject source maps on open-source projects. FP for bounty.

**cal.com — v1 (all FP):**
- **Missing CSP** (high/medium) — Marketing site. Auto-rejected. FP.
- **Sensitive data in URL (4 findings)** (high/high) — URLs like `/api/web_experiments/?token=` with empty token values (PostHog/Posthog integration API calls). No actual token exposed. FP.
- **Cookie __Secure-next-auth.callback-url** (medium/medium) — Same as above. By design. FP.
- **Missing SRI** (medium/medium) — All third-party analytics/marketing scripts (PostHog, Twitter, Framer, dubcdn). Explicitly excluded per triage rules. FP.
- **Rate limit on /api/auth/session** — Session endpoint, not authentication. FP.
- **OAuth state on /api/auth/session** — Not an OAuth endpoint. FP.

**blog.kredivo.com:**
- **Exposed /wp-login.php** (high/high) — TRUE POSITIVE. Drafted → `2026-05-06-kredivo-wp-login-exposed.md`
- **Missing CSP** (high/medium) — Blog/WordPress site. Informational, auto-rejected for bounty. FP.
- **Missing X-Frame-Options** (medium/low) — Low confidence, WordPress blog. FP.
- **Cookie _hcc** (medium/medium) — `_hcc` is a HotJar tracking cookie. Third-party analytics cookie. Excluded per triage rules. FP.
- **Rate limit on /login** — Included in wp-login.php report as supporting evidence. Not standalone.

---

## Honest Assessment (May 6)

**Bounty readiness: IMPROVING.** 
- 2 T1 drafts ready: Moneybird DOM XSS + Kredivo WordPress login
- 1 T1 carry-over: Indeed CSRF cookie
- Scanner is generating many FPs on complex targets (Next.js SPAs, Cloudflare-protected sites) — boolean-based XPath, method override, race condition checks need tuning
- Active injection checks (SQLi, XPath, XXE, LDAP) are generating FPs on CDN-blocked responses — need to filter Cloudflare 403 HTML as "blocked, not vulnerable"

**Key patterns causing FPs this session:**
1. Boolean-based injection detection on SPAs — response size varies naturally in Next.js RSC pages
2. Cloudflare 403 HTML matched by XML/LDAP error patterns (DOCTYPE/HTML content)
3. HSTS detection on CDN edge URLs with query params that bypass header injection
4. Method override: both responses returning 403 does NOT mean override succeeded

## Next Steps (Priority Order)
1. **Submit Moneybird DOM XSS** — verify `document.domain` shows `www.moneybird.com` in browser first
2. **Submit Kredivo WordPress login** — confirm `/wp-login.php` still returns 200 before submitting
3. **Verify Indeed CSRF cookie** — run Playwright check on id.indeed.com to confirm cookie is still present
4. **Manually check Moneybird postMessage** — open DevTools on www.moneybird.com, look at which scripts register `message` event listeners
5. **Scanner improvement ticket** — filter Cloudflare 403 HTML pages before checking XML/LDAP error patterns

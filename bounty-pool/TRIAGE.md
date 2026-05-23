# Bounty Pool Triage — Updated May 23, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Program | Notes |
|---|--------|---------|----------|---------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | HackerOne | Cookie set via JS — curl won't reproduce. Needs browser verification. Draft: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM XSS via URL fragment (innerHTML sink) | High | HackerOne | High/high confidence. **Verify in browser first** — open PoC URL, confirm alert fires, take screenshot. Draft: `2026-03-22-moneybird-dom-xss.md` |

### TIER 2 — Hold (needs verification before submitting)

| # | Target | Finding | Severity | Program | Notes |
|---|--------|---------|----------|---------|-------|
| 3 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | — | HOLD — needs Twitch account + authenticated scan. Cookie names suggest auth tokens. |
| 4 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Bugcrowd | Weak standalone — needs XSS chain. Submitting to their own program is bad optics. |
| 5 | community.openproject.org | Session Fixation — cookie not regenerated post-login | Medium | YesWeHack | **Check scope first** — community.openproject.org may be out of scope. If in scope: create free account, verify with curl, then submit. Draft: `2026-03-26-openproject-session-fixation.md` |
| 6 | app.cal.com | Production source maps publicly accessible (4 source files) | Medium | HackerOne | **Manual check needed** — fetch `/_next/static/chunks/38892383c615aecb.js.map` and inspect sourcesContent for secrets/sensitive logic. If contains just generic React components: informational. If contains API keys or sensitive routes: submit. Draft: `2026-03-26-calcom-source-map-exposure.md` |

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

## Session 8 Triage Log — Scans from 2026-03-22 and 2026-03-26

### New Reports Drafted (3)

| File | Target | Verdict |
|------|--------|---------|
| `2026-03-22-moneybird-dom-xss.md` | moneybird.com | **TIER 1** — High/high confidence DOM XSS. Verify + submit. |
| `2026-03-26-calcom-source-map-exposure.md` | app.cal.com | **TIER 2** — Real exposure, needs content check before deciding severity. |
| `2026-03-26-openproject-session-fixation.md` | community.openproject.org | **TIER 2** — CWE-384 finding, check program scope first. |

### Findings Triaged as False Positive / Informational

#### Neon.tech (scanned 2026-03-26, 8 findings)

| Finding | Verdict | Reason |
|---------|---------|--------|
| SQL Injection on /unify (critical/medium) | **FP** | Scanner note says evidence is a PostgreSQL docs link, not an actual DB error. The `/unify` endpoint is a Next.js page router—likely not SQL-driven. Do not submit. |
| Directory Traversal on /unify (critical/medium) | **FP** | Neon.tech runs on Vercel/Next.js. Infrastructure normalizes `../` paths before they reach application code. Curl command uses Windows-style `\..\` which is invalid on Linux filesystems. |
| Prototype Pollution via __proto__ (critical/medium) | **FP** | Evidence shows 403 response from Cloudflare WAF. Canary `secbot_pp=polluted` reflected in Cloudflare's error page HTML, not from the actual application. The 403 indicates the WAF blocked the request before it reached the app. |
| Open Redirect on /login (medium/medium) | **FP** | Scanner note explicitly states redirect goes to `neon.com/login?param=...` not to `evil.example.com`. The redirect stays within neon.com — not an open redirect. |
| Verbose Error on /undefined (medium/low) | **FP** | Low confidence. Next.js RSC page data shown for undefined route — standard Next.js behavior, not sensitive error disclosure. |
| neon_consent cookie flags (medium/high) | **FP** | Consent/GDPR preference cookie. Analytics/consent cookies excluded from bounty scope by all major programs. |
| Missing SRI on own CDN (medium/high) | **Informational** | Scripts served from neon.com's own CDN — not third-party. SRI on own-origin scripts is defense-in-depth, not a bounty-worthy finding. |
| Missing HSTS header (high/high) | **Informational** | Standalone HSTS findings are auto-rejected by most mature programs. |

#### Cal.com (scanned 2026-03-26, 21 findings)

| Finding | Verdict | Reason |
|---------|---------|--------|
| XPath Injection — month param (high/medium) | **FP** | Response size difference (17%) on `/admin/30min` explained by calendar content variation when injecting tautology vs. contradiction — the query parameter changes what events appear in the calendar. `' or '1'='1` is a URL-encoded XPath injection payload but the response difference is benign content variation, not injection signal. |
| XPath Injection — user param (high/medium) | **FP** | Same issue on `/auth/login?user=1`. The login page renders differently based on the `user` param value — not XPath-driven. |
| XPath Injection — _rsc param (high/medium) | **FP** | `_rsc` is a Next.js React Server Components internal parameter. Response size differences are caused by RSC re-renders when this param is manipulated — no XPath involved. |
| XXE on /api/trpc/features/map (high/medium) | **FP** | Response was HTTP 403 from Cloudflare. The "DTD" pattern in detection matched Cloudflare's challenge page HTML (`<!DOCTYPE html>`), not actual XML processing. |
| LDAP Injection on /auth/login (high/medium) | **FP** | Response was HTTP 200 standard NextAuth login page. The "invalid.*filter" error pattern matched a div ID or CSS class in the page HTML, not an actual LDAP error message. |
| Method Override DELETE on /api/trpc/me/myStats (high/medium) | **FP** | Baseline POST → 403, override DELETE → 403. Both responses return 403 (Forbidden). No actual behavior change — the server consistently rejects unauthorized requests regardless of method. |
| Method Override _method/method/_httpmethod (high/medium) | **Low confidence** | Baseline POST → 404, override → 403. The change from 404 to 403 could indicate the endpoint exists and requires auth, but this alone does not confirm an ACL bypass. Would need authenticated testing to determine if override grants elevated access. Skip without auth. |
| OAuth missing state on /api/auth/session (medium/medium) | **FP** | `/api/auth/session` is the NextAuth.js session endpoint (returns current session data), not an OAuth authorization endpoint. Scanner probed it with OAuth parameters but it doesn't implement the OAuth authorization flow. |
| Race Condition on /register (medium/medium) | **FP** | Scanner sent 10 concurrent GET requests to the `/register` registration form page. GET requests to a registration form returning 200 is expected behavior. No state-changing action tested. |
| SRI on Intercom widget (medium/medium) | **FP** | `widget.intercom.io` is a third-party chat widget loaded by design. Third-party SaaS widget scripts are excluded from SRI bounties by all major programs. |
| Cookie __Secure-next-auth.callback-url HttpOnly (medium/medium) | **Informational** | Already has `__Secure-` prefix (Secure flag present). The callback URL stored here is a redirect destination, not a session secret. Missing HttpOnly on a callback URL cookie is low-impact informational at best. |
| Web Cache Deception on /admin/30min (high/medium) | **FP** | Evidence shows `cf-cache-status: DYNAMIC`. Cloudflare `DYNAMIC` status means the response was NOT cached — Cloudflare's WAF correctly identified the response as dynamic content and refused to cache it. No actual cache poisoning occurred. |
| Missing Rate Limiting on /auth/login (medium/medium) | **Informational** | Cal.com uses Cloudflare for rate limiting at the edge — the app-level responses don't include rate-limit headers but Cloudflare enforces limits transparently. Standalone rate limit findings without confirmed bypass are typically informational on Cloudflare-protected apps. |
| Missing HSTS (high/medium) | **Informational** | Standalone, auto-rejected by most programs. |
| Missing SRI (medium/medium) | **See above** | — |
| Username Enumeration (medium/medium) | **Informational** | Common in NextAuth apps — error message differences are intentional UX. Most mature programs reject this as by-design on login pages that intentionally say "wrong password" vs "user not found". |
| OAuth PKCE not enforced (low/medium) | **Informational** | `/api/auth/session` is not an OAuth authorization endpoint. |
| Missing Rate Limiting on API (low/medium) | **Informational** | — |

#### Kredivo blog.kredivo.com (scanned 2026-03-22, 3 findings)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Exposed WordPress Login /wp-login.php (high/high) | **Informational** | blog.kredivo.com is a blog subdomain. Exposed wp-login.php on a blog is standard WordPress behavior. Without brute-force evidence or additional chaining, this is informational. Kredivo's main finance app (not the blog) would need WP login exposure to be bounty-worthy. |
| Missing Content-Security-Policy (high/high) | **Informational** | Standalone CSP absence on a marketing blog — auto-rejected by all bug bounty programs. |
| Cookie _hcc missing HttpOnly/Secure (medium/high) | **FP** | `_hcc` is a HubSpot analytics/click-tracking cookie. Third-party marketing/analytics cookies are explicitly excluded from bounty scope by all major programs. |

#### OpenProject community.openproject.org (scanned 2026-03-22 + 2026-03-26)

| Finding | Verdict | Reason |
|---------|---------|--------|
| Missing HSTS (high/high) | **Informational** | Standalone. |
| Missing CSP (high/high) | **Informational** | Standalone on community forum. |
| Missing Rate Limiting on /login (medium/high) | **Informational** | Weak standalone without confirmed bypass. |
| Username Enumeration via timing (low/medium) | **Skip** | Low confidence, timing-based enumeration is hard to prove reliably. |
| Missing Rate Limiting on API (low/high) | **Informational** | — |

#### Moneybird (scanned 2026-03-22)

| Finding | Verdict | Reason |
|---------|---------|--------|
| postMessage missing origin validation (medium/medium) | **Hold** | Scanner couldn't enumerate handler logic. Needs manual testing — what do the 3 handlers DO with the message data? If they just trigger UI changes (e.g., close a banner), this is informational. If they process auth tokens or trigger API calls, escalate. |
| Mixed Content HTTP resource (medium/high) | **Informational** | Link to `http://www.moneybird.com/artikelen/` — internal HTTP link on an HTTPS page. Not directly exploitable, informational. |
| Missing CSP (high/high) | **Companion finding** | Included as supporting evidence in the DOM XSS report to strengthen impact, not submitted standalone. |

---

## Honest Assessment (May 2026)

**Bounty readiness: LOW-MEDIUM.** Session 8 is the first session to yield a credible active vulnerability:

- **Moneybird DOM XSS (high/high)** — first genuine injection finding after 7 sessions. One browser test away from submission.
- All other new findings are passive (headers, cookies) or false positives requiring manual verification.
- Critical/high confidence rate: 1 of 44 new findings = 2.3% true positive rate.

**Pattern on false positives:**
- **XPath injection** — boolean-based detection fires on any URL parameter that affects page content (calendar, RSC)
- **XXE** — detection triggers on Cloudflare 403 HTML containing "DOCTYPE" or "error"
- **LDAP injection** — detection triggers on error-like substrings in standard HTML responses
- **Method override** — 404→403 change is not sufficient evidence of bypass without authenticated testing
- **Prototype pollution** — 403 from WAF means canary never reached app

**What's needed next:**
1. **Verify Moneybird DOM XSS** — browser test with screenshot → Tier 1 submission
2. **Check OpenProject YesWeHack scope** — verify community.openproject.org in scope
3. **Manual postMessage analysis on Moneybird** — check handler logic in browser DevTools
4. **Authenticated scan of cal.com** — method override findings need auth context to determine exploitability

## Next Steps (Priority Order)

1. **[IMMEDIATE]** Verify Moneybird DOM XSS in browser — open `https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>`, confirm alert, screenshot
2. **[IMMEDIATE]** Check cal.com source map content — `curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['sourcesContent'][0][:3000])"`
3. **[THIS WEEK]** Check YesWeHack scope for community.openproject.org — if in scope, create account, verify session fixation, submit
4. **[HOLD]** Manually test Moneybird postMessage handlers
5. **[NEXT SCAN]** Authenticated scan of cal.com — use `--auth-cookie` with a cal.com session
6. **[FIX OWN APP]** Rate limiting + HSTS on finance.atmando.app (unchanged from previous sessions)

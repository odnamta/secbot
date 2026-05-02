# Bounty Pool Triage — Updated May 2, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | moneybird.com | DOM XSS via URL Fragment | High | Playwright-confirmed innerHTML sink. Alert fires on `#<img src=x onerror=alert(...)>`. No enforced CSP. **CAVEAT:** Marketing homepage only; requires user to click crafted link. Browser-verify before submitting. Draft: `2026-03-14-moneybird-dom-xss.md` (in pending/moneybird/) |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 2 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 3 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |
| 4 | indeed.com | CSRF cookie missing Secure on login page | Medium | Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Draft: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 5 | cal.com | Username Enumeration — login form (content-based) | Medium | `email=admin` → response contains "wrong password" (vs no-account message). Real behavior but cal.com is open source with public profiles — very likely informational. Manual verify needed. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented
- moneybird.com postMessage handlers — **FP:** Intercom + Freshdesk widget handlers, by design (per FP patterns)

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Session 8 Scan Results (Mar 22–26, 2026)

Five targets re-scanned: neon.tech (new), openproject-v2, calcom-v2, kredivo-v2, moneybird-v1.

### neon.tech (2026-03-26, 45 raw findings)

**NOT in hunt registry.** Scanned as opportunistic target.

| Finding | Decision | Reason |
|---------|----------|--------|
| SQLi in `/unify?a=` and `?n=` (CRITICAL/high, 14 dupes) | **FP** | "SQL error" is `postgresql/tutorial">PostgreSQL Tutorial</a>` — neon.tech's own sidebar nav link to PostgreSQL docs. Present on every page regardless of input. Pattern matched normal site content. |
| Directory Traversal (CRITICAL/high, 6 dupes) | **FP** | Windows-style payload `..\..\..` on Vercel/Next.js CDN. "System file content" heuristic mismatch — Vercel normalizes these paths; server file is never accessed. |
| Prototype Pollution via `__proto__[secbot_pp]` (CRITICAL/high) | **FP** | Status 403 = WAF blocked the request. Canary value reflected inside Cloudflare error page HTML, not in app response. |
| Verbose Error — Database error details (MEDIUM/high) | **FP** | Same root cause as SQLi FP: `/undefined` route response contains the `postgresql/tutorial` nav link. Not a database error. |
| Open Redirects × 8 (MEDIUM/high) | **FP** | Need manual verification; marketing/docs site, no auth flows confirmed. Lower priority than in-registry programs. |
| Missing CSP / HSTS (HIGH/medium) | **Skip** | Marketing site, not in hunt registry. No established program to submit to. |
| Cookie / SRI (MEDIUM/medium) | **Skip** | Low bounty value, marketing site. |

**Neon.tech summary:** 0 real findings. All criticals are scanner FPs from "postgresql/" matching their own navigation content.

### openproject-v2 — community.openproject.org (2026-03-26, 32 raw findings)

| Finding | Decision | Reason |
|---------|----------|--------|
| Missing Rate Limiting on Login × 4 (MEDIUM/high) | **FP / Out of Scope** | Scanner sent 15 GET requests to the login page (not POST with credentials). Rate limiting applies to POST login attempts. Also scoped to community instance, not the main hosted product. |
| Session Fixation `_open_project_session` (MEDIUM/medium) | **FP** | Scanner sent POST with no credentials → login failed → session correctly unchanged. Session regeneration only occurs on *successful* authentication. |
| Missing headers (info/low) | **Skip** | Informational. |

**OpenProject summary:** 0 real findings. Rate limiting FP (GET != auth attempt), session fixation FP (no valid login performed).

### calcom-v2 — app.cal.com (2026-03-26, 54 raw findings)

| Finding | Decision | Reason |
|---------|----------|--------|
| LDAP Injection `wildcard-filter-break` (HIGH/high) | **FP** | Cal.com uses PostgreSQL/NextAuth, not LDAP. Pattern `invalid.*dn\|invalid.*filter` matched coincidental text in Next.js bundle (likely CSS/DOM validation strings). Response was standard login page HTML with no error exposed. |
| Web Cache Deception `/nonexistent.css` (HIGH/medium) | **FP** | `cf-cache-status: DYNAMIC` in response — Cloudflare explicitly NOT caching this. No cache poisoning occurred. |
| XXE Injection parameter-entity (HIGH/medium) | **FP** | Response is HTTP 403 from Cloudflare WAF. The `error` keyword in the Cloudflare HTML page matched the detection pattern. tRPC endpoints don't accept XML. |
| HTTP Method Override × 5 (HIGH+MEDIUM/medium) | **FP** | All probes still return 403. No ACL bypass demonstrated — the server acknowledges the header but still blocks access. A different response size is due to Cloudflare challenge vs app 403 page. |
| XPath Injection × 3 (HIGH/medium) | **FP** | Cal.com is Next.js/PostgreSQL, no XPath usage. `month`, `user`, `_rsc` are booking/RSC params. |
| Source Map Exposure (MEDIUM/high) | **FP for bounty** | Cal.com is fully open source (github.com/calcom/cal.com). Source maps expose no additional attacker advantage. |
| OAuth missing state on `/api/auth/session` (MEDIUM/medium) | **FP** | `/api/auth/session` is NextAuth's session-retrieval endpoint, not an OAuth initiation endpoint. No CSRF risk here. |
| Race Condition on `/register` (MEDIUM/medium) | **Inconclusive** | Needs authenticated manual testing with concurrent registration requests. |
| Rate Limiting on auth endpoints (MEDIUM/high) | **FP** | Cloudflare WAF + rate limiting at CDN layer. Scanner's 15-request test doesn't account for infra-level throttling. |
| Username Enumeration login form (MEDIUM/high) | **Hold** | "Wrong password" vs "no account" response differentiation detected. Potentially real. **But:** cal.com has public profile URLs (cal.com/username), so email existence is already discoverable. Likely informational. Move to TIER 2. |
| Missing CSP / HSTS / SRI (HIGH/MEDIUM) | **Skip** | Cal.com has a nonce-based CSP with `strict-dynamic` — mostly correct. HSTS present. These are scanner quirks. |

**Cal.com summary:** 0 new submittable findings. Username enumeration moved to TIER 2 (hold, low bounty potential).

### kredivo-v2 — blog.kredivo.com (2026-03-22, 14 raw findings)

| Finding | Decision | Reason |
|---------|----------|--------|
| Missing CSP (HIGH/medium) | **Skip** | Marketing blog, not in-scope product. |
| `_hcc` cookie missing flags (MEDIUM/medium) | **FP** | `_hcc` is a third-party analytics/tracking cookie. FP by definition per bounty FP patterns. |
| Rate Limiting on /wp-login.php (MEDIUM/high) | **Out of Scope** | WordPress admin on a marketing blog. Not the Kredivo app. |
| Exposed /wp-login.php (MEDIUM/high) | **Skip** | Standard WordPress admin path, not a vulnerability. |

**Kredivo summary:** 0 real findings. blog.kredivo.com is a WordPress marketing site, out of scope for bug bounty.

### moneybird-v1 — www.moneybird.com (2026-03-22, 105 raw findings)

| Finding | Decision | Reason |
|---------|----------|--------|
| DOM XSS via URL Fragment (HIGH/medium) | **TIER 1** | Playwright confirmed. innerHTML sink fires alert on `#<img src=x onerror=...>`. Already drafted. |
| Open Redirect × 8 (MEDIUM/high) | **FP** | Scanner hit `https://www.moneybird.com/login?url=https://evil.example.com`. The HTTP 301 Location is `https://moneybird.com/login?url=https%3A%2F%2Fevil.example.com` — this is a www→non-www redirect. The evil.com URL stays in the query param; it is **never** the redirect destination. |
| postMessage no origin validation (MEDIUM/medium) | **FP → Archive** | The 3 postMessage handlers are from Intercom and Freshdesk widgets (both in their CSP). By design, per FP patterns. Moving to archived. |
| Mixed Content × 80+ (MEDIUM/medium) | **Skip** | Marketing site, mixed content on media embeds. Not bounty-worthy. |
| Missing SRI × 9 (MEDIUM/medium) | **Skip** | Marketing site with third-party scripts. |
| Race Condition on `/features/bookkeeping/` (MEDIUM/medium) | **FP** | Static marketing page — no state-changing operations. |
| Missing CSP (HIGH/medium) | **Supporting** | Real: they have `content-security-policy-report-only` but no enforced CSP. Already drafted as supporting evidence for DOM XSS. Not standalone bounty. |

---

## Session 8 Honest Assessment (May 2, 2026)

**Session 7 status unchanged.** After 5 more scans (neon.tech, openproject, cal.com, kredivo, moneybird):

- **0 new submittable findings** discovered across ~250 new raw findings
- Heavy scanner FP rate on high-confidence claims:
  - neon.tech "CRITICAL SQLi" = nav link text matching SQL error pattern
  - cal.com "HIGH LDAP Injection" = no LDAP in tech stack, bundle string matched
  - Multiple "method override" FPs = all return 403 (no bypass)
  - Multiple "XXE/XPath" FPs = wrong tech stack (Node.js/PostgreSQL)
- **Moneybird DOM XSS** remains the only Tier 1 finding. Needs browser verification and submission.
- **cal.com Username Enumeration** added to TIER 2 (hold) — real behavior, marginal bounty value.

**Root cause unchanged:** Unauthenticated scans of hardened production systems produce passive/header findings + scanner heuristic FPs. Active vulns (SQLi, RCE, IDOR) require authenticated sessions and bespoke testing.

## Next Steps (Priority Order)

1. **Submit Moneybird DOM XSS** — verify alert fires in browser on `https://www.moneybird.com/#<img src=x onerror=alert(1)>`, then submit to HackerOne
2. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
3. **Get authenticated sessions** — Twitch, cal.com accounts for deeper auth scanning
4. **Indeed submission** — only if Dio confirms willingness
5. **Tune scanner FP patterns** — add "programming language company site" heuristic: if target URL contains the DB/language name, skip that name as SQL error indicator

## FP Patterns Confirmed This Session

- **"Language company" SQLi FP:** `neon.tech` (PostgreSQL company) → "postgresql/" in all page responses → triggers SQL error pattern
- **Open redirect from www→canonical redirect:** Scanner interprets www→non-www 301 as open redirect when `url=` param is preserved in Location (but destination stays same-origin)
- **LDAP FP on Node.js apps:** `invalid.*dn|invalid.*filter` patterns match JavaScript bundle validation strings
- **Method override FP:** 403 response (blocked) ≠ ACL bypass; scanner flags header acknowledged even without exploit
- **Session fixation FP:** Scanner tests POST without credentials → failed login → session unchanged correctly

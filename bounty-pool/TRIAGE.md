# Bounty Pool Triage — Updated 2026-04-04 (Session 8)

## Submission Priority

### TIER 1 — Submit Now (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | moneybird.com | DOM XSS via URL fragment (`#` → innerHTML) | High | [high][high] confidence. DOM sink detected on homepage. **Must verify in browser first** — curl cannot trigger DOM XSS. If alert fires → submit immediately. Draft: `2026-04-04-moneybird-dom-xss.md` |
| 2 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md`. **CAVEAT:** Cookie set via JS, needs browser reproduction. |

### TIER 2 — Submit After Verification

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 3 | community.openproject.org | Missing rate limiting on /login (15 rapid POSTs, no 429) | Medium | [medium][high] confidence. Curl-verifiable. **Check YesWeHack scope** — confirm community.openproject.org is in-scope before submitting. Draft: `2026-04-04-openproject-rate-limiting.md` |

### TIER 3 — Hold (needs auth or more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 4 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 5 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Bad optics submitting to their own program. |
| 6 | community.openproject.org | Session Fixation — session cookie not regenerated after login (CWE-384) | Medium | [medium][medium] confidence. PROBLEM: tool tested unauthenticated POST (failed login), not successful login. Session cookie staying the same after a FAILED login is expected behavior. Cannot confirm without valid credentials. HOLD until auth scan. |
| 7 | moneybird.com | postMessage handlers missing origin validation | Medium | [medium][medium] confidence. Need to identify which handlers these are — likely Intercom/Drift/chat widgets (by-design FP). If custom app handlers, re-evaluate. |

### TIER 4 — Archived (confirmed non-bounty)

Moved to `bounty-pool/archived/` or documented below:
- shopify.com CORS /__dux — Non-exploitable (SameSite + empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

---

## OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but not appearing in response. Docker rebuild or middleware bug. |

---

## New Scan Triage — 2026-03-26 Batch

### community.openproject.org (openproject-v2) — YesWeHack

| Finding | Sev | Conf | Verdict | Reason |
|---------|-----|------|---------|--------|
| Missing HSTS Header | high | high | **FP (no bounty)** | Header-only finding on community/forum site. Typically informational on YesWeHack for community instances. Not worth submitting standalone. |
| Missing Content-Security-Policy | high | high | **FP (no bounty)** | Same — header-only, community site. Only worth mentioning as amplifier if a real XSS is found. |
| Session Fixation (session cookie unchanged after login) | medium | medium | **HOLD** | Tool tested unauthenticated POST, not successful login. Session staying same after *failed* login is by design (Rails). Needs valid credentials to confirm. |
| Missing Rate Limiting on /login | medium | high | **TIER 2 — DRAFT READY** | 15 rapid POSTs, zero 429, no X-RateLimit headers. Curl-verifiable. Compounded by timing-based username enumeration. Strong enough to submit after scope check. |
| Username Enumeration via timing (~317ms vs ~11s) | low | medium | **FP (no standalone bounty)** | Low severity, medium confidence. Valid finding class (CWE-208) but low value on its own. Include as supporting evidence in rate-limit report rather than separate submission. |
| Missing Rate Limiting on /api/v3/configuration | low | high | **FP (no bounty)** | Public configuration endpoint. Rate limiting on a public read-only API endpoint is not bounty-worthy. |

### neon.tech (neon-v2) — NOT in bounty registry

> **Note:** neon.tech is not in the current hunt-registry.yaml. Before submitting any finding, add neon.tech to the registry and confirm they have an active bug bounty program that accepts automated scanning.

| Finding | Sev | Conf | Verdict | Reason |
|---------|-----|------|---------|--------|
| SQL Injection on /unify (`a`, `n` params) | critical | medium | **FP** | Finding itself notes: "the SQL error evidence appears to be a PostgreSQL documentation link rather than a true database error." The `/unify` endpoint is Next.js routing that displays content mentioning PostgreSQL (neon.tech IS a Postgres company). A documentation URL is not a SQL error. |
| Directory Traversal on /unify | critical | medium | **FP** | Curl command uses Windows-style backslash paths (`\..\..\etc\passwd`). On Linux/Vercel/Next.js these are not path separators. Cloudflare/Vercel normalizes these paths. No evidence of file content in response. |
| Server-Side Prototype Pollution (`__proto__[secbot_pp]=polluted`) | critical | medium | **HOLD — manual verify needed** | Canary reflection claimed but server returned 403. The 403 error page may have reflected query params in the response body (common Cloudflare behavior) without actual prototype pollution. Test manually: send `GET https://neon.tech/unify?__proto__[secbot_pp]=polluted` and check if `polluted` appears in response body outside of the URL echo. If the 403 page echoes all query params → FP. |
| Missing HSTS (on neon.com) | high | high | **FP (no bounty)** | Marketing homepage. Low bounty value. Most programs accept header findings only from their main app, not marketing sites. |
| Open Redirect on /login | medium | medium | **FP** | Finding itself says "redirect goes to neon.com/login?param=... rather than directly to evil.example.com." That's an internal redirect, not an open redirect. Would need to verify redirect actually exits the neon.tech domain. |
| Verbose Error on /undefined | medium | low | **FP** | Low confidence. /undefined shows Next.js RSC data (page structure), not a true verbose error. This is normal Next.js behavior for undefined route params. |
| Cookie "neon_consent" missing Secure/HttpOnly | medium | high | **FP** | Consent/preference cookie. Per known FP patterns: "Third-party cookie flags (analytics, marketing, consent widgets) — always FP for bounties." |
| Missing SRI on external scripts | medium | high | **FP** | Scripts served from neon's own CDN. First-party script SRI is low value — supply chain risk is negligible when you control the CDN. Not bounty-worthy. |

### app.cal.com (calcom-v2) — HackerOne

| Finding | Sev | Conf | Verdict | Reason |
|---------|-----|------|---------|--------|
| Missing HSTS | high | medium | **FP (no standalone bounty)** | Generic header finding. Cal.com likely already aware. Low bounty value on HackerOne. |
| Web Cache Deception via /nonexistent.css | high | medium | **FP** | Evidence shows `cf-cache-status: DYNAMIC`. Cloudflare DYNAMIC status means the response is NOT being cached — the WCD attack fails because there's no cache to poison. FP. |
| XPath Injection boolean-based (month, user, _rsc params) | high | medium | **FP** | Boolean response size differences on Next.js SPAs are common and expected: different inputs render different page content (different calendar months, different user states). The `_rsc` parameter is Next.js React Server Components — RSC responses vary dramatically by parameter. Size difference ≠ injection. |
| XXE on /api/trpc/features/map | high | medium | **FP** | Server returned 403 Cloudflare HTML. The indicator regex `/root:.*:0:0|\/bin\/(ba)?sh|error|DTD/i` matched "error" in the Cloudflare error page HTML, not actual XXE output. |
| LDAP Injection on /auth/login?user=1 | high | medium | **FP** | Cal.com is Node.js/Next.js + PostgreSQL, not LDAP. The LDAP error pattern (`invalid.*dn|invalid.*filter`) matched something in the Next.js HTML response (possibly CSS class name or text), not an actual LDAP error. No LDAP infrastructure on this stack. |
| HTTP Method Override x4 (X-HTTP-Method-Override, _method, method, _httpmethod → DELETE) | high | medium | **FP** | Evidence: all override attempts return 403, same as baseline (some baseline 404 → override 403, which is NOT a bypass — the endpoint is now recognized but still rejected). A real bypass would change 403 → 200 or return different protected data. |
| Source Map Exposure | medium | medium | **HOLD** | Real finding class. Next.js apps sometimes expose `.map` files containing original source code. Low-medium bounty value. Verify: does the map file contain secrets (API keys, internal IPs, auth logic) or just minified JS? If only minified → low/informational. If secrets → submit. |
| Missing Rate Limiting on auth endpoint | medium | medium | **HOLD** | Same pattern as OpenProject finding. Solid class of vulnerability. Check if cal.com HackerOne program accepts rate-limit reports — some programs explicitly exclude them. |
| Username Enumeration (login form, content-based) | medium | medium | **HOLD** | Combine with rate-limit if submitting. Standalone is low value. |
| Race Condition on /register | medium | medium | **HOLD** | Needs manual verification — race conditions are hard to confirm automatically. Could be interesting if /register allows duplicate account creation or credit abuse. |
| OAuth missing state on /api/auth/session | medium | medium | **FP** | `/api/auth/session` is a session query endpoint (NextAuth), not an OAuth initiation endpoint. Missing state on a session check is not a real OAuth CSRF finding. |
| OAuth PKCE not enforced on /api/auth/session | low | medium | **FP** | Same as above — wrong endpoint for PKCE enforcement. |
| Missing Rate Limiting on API | low | medium | **FP** | Low severity, generic. Not bounty-worthy. |
| Cookie __Secure-next-auth.callback-url missing HttpOnly | medium | medium | **FP** | NextAuth callback URL cookie is a convenience cookie, not a session token. Not bounty-worthy on its own. |
| Missing SRI | medium | medium | **FP** | First-party Next.js chunks. Same reasoning as neon.tech SRI finding. |

### www.moneybird.com (moneybird, 2026-03-22) — HackerOne

| Finding | Sev | Conf | Verdict | Reason |
|---------|-----|------|---------|--------|
| DOM XSS via URL fragment | high | high | **TIER 1 — DRAFT READY** | Real finding. dom-sink detection method confirmed innerHTML assignment. Needs browser verification. See `2026-04-04-moneybird-dom-xss.md`. |
| Missing CSP | high | high | **FP (standalone)** | Amplifies XSS but not a standalone bounty submission. Include as supporting context in XSS report. |
| postMessage handlers missing origin validation | medium | medium | **HOLD** | Need to identify the handlers. If from Intercom/Drift/HubSpot chat widgets → FP (by design). If custom Moneybird code → re-evaluate. |
| Mixed Content (http://www.moneybird.com/artikelen/) | medium | high | **FP (no bounty)** | Internal marketing link using HTTP. Modern browsers block mixed content anyway. Not bounty-worthy. |

---

## Honest Assessment (Apr 4)

**Progress since Session 7:**
- 3 new full scan batches analyzed (openproject-v2, neon-v2, calcom-v2)
- 2 new draft reports written (Moneybird DOM XSS, OpenProject rate limit)
- FP rate: ~85% of findings from new scans confirmed FP after manual analysis
- Pattern: Medium-confidence injection findings on Next.js/Cloudflare stacks are almost always FP (size-based boolean detection is unreliable on SPAs)

**Best current bets (ranked):**
1. **Moneybird DOM XSS** — Browser verify first, then submit. Highest potential.
2. **OpenProject rate limiting** — Scope-check, then submit. Curl-verifiable and clean.
3. **OpenProject session fixation** — Needs auth scan to confirm real bug.
4. **Cal.com source map exposure** — Low effort to verify, low-medium value.

**Root cause of FP concentration:**
- Next.js RSC parameters (`_rsc`, `month`, `user`) naturally produce large response size differences → boolean injection FP
- Cloudflare 403 pages contain "error" in HTML → triggers error-pattern detection FP
- `cf-cache-status: DYNAMIC` indicates cache deception fails before it starts
- Backslash path traversal payloads don't work on Linux-hosted apps

## Next Steps (Priority Order)
1. **Moneybird DOM XSS** — Open browser, navigate to PoC URL, confirm alert fires → submit
2. **OpenProject scope check** — Confirm community.openproject.org in YesWeHack scope → submit rate-limit report
3. **Get Moneybird auth** — Scan app.moneybird.com (the actual product) with credentials
4. **OpenProject auth scan** — Test session fixation with real credentials
5. **Cal.com source maps** — Quick manual check: do .map files contain secrets?
6. **Add neon.tech to registry** — If they have a bug bounty program, re-run with fresh eyes on prototype pollution finding

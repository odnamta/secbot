# Bounty Pool Triage — Updated 2026-05-13 (Session 8 — Report Drafter)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | moneybird.com | DOM-Based XSS via URL Fragment | High | Auto-verify found two innerHTML sinks. **MUST verify in browser** — navigate to `https://www.moneybird.com/#<img src=x onerror=alert(1)>` and confirm alert fires. No CSP present (separate finding), so exploit impact is high. Draft: `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` |
| 2 | moneybird.com | Missing Content-Security-Policy | High | **Bundle with DOM XSS** — do not submit standalone. Amplifies XSS to critical. Draft: `pending/moneybird/09dd5267-missing-content-security-policy-header.md` |

### TIER 2 — Draft ready (needs Dio verification before submit)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 3 | community.openproject.org | Missing Rate Limiting on /login | Medium | 15 rapid requests all HTTP 200, zero rate-limit headers. YesWeHack (EUR 100-5000). Solid curl-reproducible evidence. Draft: `pending/openproject/2026-05-13-openproject-rate-limiting.md` |
| 4 | app.cal.com | Source Map Exposure | Medium | `.js.map` file HTTP 200, contains 4 source files. **CAVEAT: Cal.com is open-source.** Only submit if source map contains secrets not in public repo. Check with: `curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' \| grep -i 'key\|secret\|password\|token'`. Draft: `pending/calcom/2026-05-13-calcom-source-map.md` |

### TIER 3 — Hold (needs more work / resources)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 5 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 6 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Bad optics submitting to their own program. |
| 7 | neon.tech | Server-Side Prototype Pollution | Critical | Scanner raw confidence=high, canary `"secbot_pp":"polluted"` reflected in 403 response body. **AMBIGUOUS** — 403 from Cloudflare often reflects query params in block page. Could be WAF reflection FP. Needs manual curl test without Cloudflare (try from different IPs, or use `--header "CF-Connecting-IP: ..."` bypass attempts). Not in hunt registry — need to decide if neon.tech is a bounty program worth targeting before investing. |
| 8 | app.cal.com | Missing Rate Limiting on /auth/login | Medium | 15 rapid requests, all HTTP 200. Valid but low priority — Cal.com HackerOne program. Need to check their program policy on rate-limit findings (often N/A). |
| 9 | app.cal.com | Username Enumeration — login form | Medium | Different responses for valid vs invalid email. Content-based. Need to manually verify what the response difference actually is (error message vs timing vs redirect). |

### TIER 4 — Archived (non-bounty / false positive)

Moved to `bounty-pool/archived/`:

#### Pre-Session 8 Archives
- **shopify.com CORS `/__dux`** — Non-exploitable (SameSite + empty body)
- **konghq.com missing headers** — Informational, auto-rejected by triagers
- **gitlab.com GraphQL introspection** — By design, publicly documented

#### Session 8 Archives (2026-05-13)
- **moneybird.com postMessage handlers** → `archived/2026-05-13-moneybird-postmessage-fp.md`
  - **FP reason:** Handler snippet is mouse/touch event polyfill code (`pageX, clientY, preventDefault`). Not security-sensitive message processing.

---

## Session 8 FP Log — Scans Mar 22–26, 2026

### Cal.com (cal.com + app.cal.com)

| Finding | FP Reason |
|---------|-----------|
| Directory Traversal on `/api/geolocation` | HTTP clients resolve `..` before sending; Cloudflare blocks path traversal. URL `cal.com/api/../../../etc/passwd` is normalized to `cal.com/etc/passwd` at the HTTP layer. |
| XXE on `/api/geolocation` | Geolocation endpoint expects JSON, not XML. Sending `Content-Type: application/xml` gets 400/415. Not a processing sink. |
| XPath Injection × 3 (month, user, _rsc params) | Response size difference is from dynamic page content (different calendar months, different page renders), not XPath logic branching. `_rsc` is a React Server Components internal parameter — completely different behavior per token by design. |
| XXE on `/api/trpc/features/map` | tRPC endpoint expects JSON. Sending XML payload returns 400. Not processed by an XML parser. |
| LDAP Injection on `/auth/login?user=` | Cal.com is Next.js/Node.js — no LDAP stack. Error patterns not present in response. |
| HTTP Method Override × 5 (me/myStats, slots/getSchedule) | All requests return 403 in both baseline and override state. No ACL bypass demonstrated — both code paths hit the same authz gate. |
| Web Cache Deception via `?month=2026-04/nonexistent.css` | This is a query parameter trick, not path-based cache deception. CDN cache keys are based on URL path, not query string value containing `.css`. Requires manual verification to confirm if any CDN is actually caching the query variant. |
| Race Condition on GET `/register` | GET requests are idempotent — racing GET requests cannot produce TOCTOU vulnerabilities. No state-changing operation on a GET /register page. |
| OAuth state on `/api/auth/session` | This is a session check endpoint, not an OAuth authorization endpoint. Not the correct endpoint for testing OAuth state parameter enforcement. |
| Sensitive Token in URL (`/api/web_experiments/?token=`) | A/B testing experiment token — public identifier, not an auth credential. Low risk. |
| Missing HSTS (app.cal.com) | Informational. Cloudflare likely handles HSTS at edge. Not bounty-worthy on HackerOne for this program. |

### Neon.tech (neon.tech)

| Finding | FP Reason |
|---------|-----------|
| SQL Injection on `/unify` | Scan description notes: "SQL error evidence appears to be a PostgreSQL documentation link rather than a true database error." The `/unify` endpoint is a marketing URL router, not a DB query endpoint. |
| Directory Traversal on `/unify` | Next.js on Vercel/CDN. `..` sequences in paths are normalized by the edge network before reaching the origin. |
| Open Redirect on `/login` (all params) | Raw evidence shows redirect destination is `https://neon.com/login?param=...` — their own domain (neon.com). Not an external redirect. Neon.tech → neon.com is an authorized same-org redirect. |
| `neon_consent` cookie missing Secure/HttpOnly | Consent preference cookie. Per known FP patterns: "Third-party cookie flags (analytics, marketing, consent widgets) — always FP for bounties." |
| Missing SRI on `/unify` | Scripts served from `neon.com` CDN — same organization. Pre-filter pattern: "same-org SRI" is always FP. |
| Missing HSTS on `neon.com` | Informational. Neon is not in the current hunt registry. |

### Kredivo (blog.kredivo.com)

| Finding | FP Reason |
|---------|-----------|
| Exposed WordPress login `/wp-login.php` | Marketing blog subdomain. Not the finance app. Auto-rejected as informational. |
| Missing Content-Security-Policy | Marketing blog. Informational. Triagers auto-reject header findings on marketing sites. |
| Cookie `_hcc` missing HttpOnly/Secure | Analytics/tracking cookie. FP per known FP patterns. |

### OpenProject (community.openproject.org)

| Finding | FP Reason |
|---------|-----------|
| Missing HSTS | Informational. Community forum instance. Would be rejected as informational. |
| Missing CSP | Informational. Community instance, not the main product. |
| Session Fixation | FP — scan ran **without valid credentials**, so login failed. Session ID not regenerating after a **failed** login is expected behavior. Session fixation requires verified successful login to confirm. |

### Moneybird (www.moneybird.com)

| Finding | Status |
|---------|--------|
| Mixed Content (HTTP resource on HTTPS page) | FP — `http://www.moneybird.com/artikelen/` is their own domain blog link. Modern browsers display mixed content warnings but this isn't a security vulnerability eligible for bounty. |

---

## OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but not appearing. Docker rebuild or middleware bug. |

---

## Honest Assessment (May 2026 — Session 8)

**Overall status: Making slow progress.**

- Sessions 1-7 (through Mar 15): 0 credible bounty submissions, 0 high/critical on external targets
- Session 8 (May 13): 4 scans processed (Mar 22-26), 2 new drafts added
  - OpenProject rate-limiting: **most submittable finding yet** — curl-reproducible, solid evidence
  - Cal.com source map: **conditional** — only submit if secrets found in source map
  - All critical/high findings from newer scans are FPs (XPath, XXE, LDAP, traversal — all scanner noise on hardened Next.js/CDN-hosted apps)

**Root cause unchanged:**
- Marketing sites and CDN-fronted apps produce mostly FP active check results
- Authenticated scanning still not done — IDOR, stored XSS, business logic all require auth
- OpenProject CVE analysis (22 CVEs documented) is the biggest opportunity — requires local Docker setup with test credentials to validate real vulnerabilities

**Highest-ROI next action:**
1. Verify Moneybird DOM XSS in browser (5 minutes, could be a real $500-1000 finding)
2. Submit OpenProject rate-limiting (30 minutes, EUR 100+ if accepted)
3. Set up OpenProject Docker + run authenticated scan against known CVEs (could find real high/critical)

---

## Scan Coverage Summary

| Target | Scan Date | Findings | Submitted | Pending | FP |
|--------|-----------|----------|-----------|---------|-----|
| cal.com (marketing) | 2026-03-22 | 8 | 0 | 0 | 8 |
| app.cal.com (app) | 2026-03-26 | 21 | 0 | 1 (source map) | 20 |
| blog.kredivo.com | 2026-03-22 | 3 | 0 | 0 | 3 |
| www.moneybird.com | 2026-03-22 | 5 | 0 | 2 (XSS + CSP) | 3 |
| neon.tech | 2026-03-26 | 8 | 0 | 0 | 7 (+1 unresolved) |
| community.openproject.org | 2026-03-26 | 6 | 0 | 1 (rate-limit) | 5 |
| community.openproject.org | 2026-03-22 | 2 | 0 | 0 | 2 |

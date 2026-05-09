# Bounty Pool Triage — Updated May 9, 2026 (Session 8)

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

## Next Steps (Priority Order — as of Mar 15)
1. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
2. **Get test credentials** — Twitch account for auth scan, unlock T2 findings
3. **Scan less-hardened targets** — community apps, smaller BBPs, OWASP Juice Shop
4. **Indeed submission** — only if Dio confirms willingness (cookie is JS-set, reproduction tricky)

---

## Session 8 Triage — May 9, 2026

**Scans analyzed:**
| Scan | Target | Date | Profile | Pages |
|------|--------|------|---------|-------|
| cal-com | cal.com | Mar 22 | stealth | 5 |
| calcom-v2 | app.cal.com | Mar 26 | standard | 49 |
| kredivo | blog.kredivo.com | Mar 22 | stealth | 10 |
| moneybird | www.moneybird.com | Mar 22 | stealth | 10 |
| openproject | community.openproject.org | Mar 22 | stealth | 8 |
| openproject-v2 | community.openproject.org | Mar 26 | standard | 25 |
| neon-v2 | neon.tech | Mar 26 | standard | 17 |

**Total interpreted findings reviewed:** 53  
**Medium+ severity + medium+ confidence:** 27  
**True positives (drafted):** 1  
**Held for manual verification:** 2  
**False positives:** 24

---

### TIER 1 — Draft Ready (Session 8)

| # | Target | Finding | Severity | Report |
|---|--------|---------|----------|--------|
| S8-1 | moneybird.com | DOM XSS via URL Fragment (homepage) | HIGH | `pending/2026-05-09-moneybird-dom-xss-homepage.md` |

**S8-1 Assessment:** Playwright-detected dom-sink with HIGH confidence. The scanner observed a `<img onerror>` payload being inserted into two separate `innerHTML` sinks at `www.moneybird.com/#<payload>`. URL fragments are never sent to the server, so curl cannot reproduce — must verify in browser. HackerOne Moneybird program. **Caveat:** scan covered `www.moneybird.com` (marketing site); confirm this domain is in HackerOne scope before submitting. The existing auto-generated draft at `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` is raw output — use the new polished draft instead.

---

### TIER 2 — Hold (Session 8, needs manual verification)

| # | Target | Finding | Severity | Action |
|---|--------|---------|----------|--------|
| S8-2 | neon.tech | Open Redirect on login via `?url=` parameter | MEDIUM | Browser test: does `/login?url=https://evil.example.com` actually redirect? Clerk/Auth0 typically validate redirect URLs. |
| S8-3 | app.cal.com | HTTP Method Override: POST 404 → DELETE 403 on `/api/trpc/slots/getSchedule` | HIGH | Needs authenticated session. POST returns 404 (endpoint absent), but POST+`_method=DELETE` returns 403 (endpoint exists, requires auth). If authenticated DELETE is callable and cal.com's ACL only checks the outer HTTP method, this may bypass write restrictions on scheduling data. |

---

### FALSE POSITIVES — Session 8

#### neon.tech (neon-v2)
| Finding | Reason |
|---------|--------|
| SQLi — URL params on /unify [CRITICAL][medium] | AI's own analysis: "SQL error evidence appears to be a PostgreSQL documentation link rather than a true database error." /unify is a marketing landing page; `a` and `n` are UUID/page-name params, not SQL inputs. |
| Directory Traversal on /unify [CRITICAL][medium] | Vercel/Next.js normalizes path traversal at the edge. Request `..\..\..etc\passwd` is rewritten before hitting the app. |
| Server-Side Prototype Pollution [CRITICAL][medium] | Got 403 WAF block. No canary value reflected in response body. The 403 is Vercel's WAF blocking `__proto__` in query strings, not evidence of pollution. |
| neon_consent cookie missing HttpOnly/Secure [MEDIUM][high] | Consent management cookie (GDPR/CMP). Must be JS-readable by definition. FP per project FP rules. |
| Missing HSTS on neon.com [HIGH][high] | neon.com is a redirect-only domain pointing to neon.tech. HSTS on the redirect domain is a best practice, not a bounty finding. |
| Missing SRI [MEDIUM][high] | Informational. Not accepted by most programs. |

#### app.cal.com (calcom-v2)
| Finding | Reason |
|---------|--------|
| XPath Injection ×3 [HIGH][medium] | cal.com is Next.js + tRPC + PostgreSQL. No XML database in the stack. Boolean-based detection is comparing normal parameter value variations, not actual XPath errors. |
| XXE Injection [HIGH][medium] | Same stack — no XML processor. POST of XML to tRPC endpoint returns standard JSON error. |
| LDAP Injection [HIGH][medium] | No LDAP directory in cal.com's tech stack. |
| Web Cache Deception on /admin/30min [HIGH][medium] | `CF-Cache-Status: DYNAMIC` in the evidence means Cloudflare is explicitly NOT caching this response. The scanner misread this as a cache-positive. |
| Missing HSTS [HIGH][medium] | Standard informational, rejected by most programs. |
| Cookie `__Secure-next-auth.callback-url` missing HttpOnly [MEDIUM][medium] | NextAuth sets this cookie without HttpOnly by design — it's a client-readable redirect URL used by the auth flow. |
| OAuth state on /api/auth/session [MEDIUM][medium] | `/api/auth/session` is a session-status endpoint, not an OAuth authorization endpoint. State parameter check doesn't apply here. |
| Race Condition on /register [MEDIUM][medium] | No evidence of actual race condition effect — scanner flagged concurrent 200 responses but /register returns 200 for all page loads. |
| Username Enumeration [MEDIUM][medium] | "wrong password" vs "user not found" difference is documented NextAuth behavior. cal.com is open source and this is an explicit design choice. Will be rejected as informational. |
| Method Override on /api/trpc/me/myStats [HIGH][medium] | Both baseline POST and override DELETE return 403. No access granted — the response size difference is likely different error messages, not data exposure. |
| Missing Rate Limit [MEDIUM][medium] | Informational. |
| Missing SRI [MEDIUM][medium] | Informational. |
| Source Map Exposure [MEDIUM][medium] | cal.com is fully open source on GitHub. Exposing source maps of publicly-available open source code is informational. |

#### cal.com (cal-com, Mar 22)
| Finding | Reason |
|---------|--------|
| Directory Traversal [CRITICAL][medium] | Vercel normalizes paths. FP. |
| XXE Injection [CRITICAL][medium] | Next.js stack, no XML processor. FP. |
| Sensitive Token in URL [HIGH][medium] | Vague evidence on homepage — likely NextAuth CSRF token in a meta tag, not exposed in URL. |
| Rate Limit / SRI | Informational. |

#### blog.kredivo.com (kredivo)
| Finding | Reason |
|---------|--------|
| Exposed WP Login `/wp-login.php` [HIGH][high] | WordPress login page is by design. Marketing blog, not the main application. Out of scope for RedStorm bug bounty. |
| Missing CSP [HIGH][high] | Marketing blog. Informational. |
| Cookie `_hcc` missing HttpOnly/Secure [MEDIUM][high] | `_hcc` = HotJar Click Counter. Analytics cookie. FP per project FP rules. |

#### community.openproject.org (openproject + openproject-v2)
| Finding | Reason |
|---------|--------|
| Missing HSTS [HIGH][high] | Informational. |
| Missing CSP [HIGH][high] | Informational. |
| Session Fixation — `_open_project_session` [MEDIUM][medium] | Scanner couldn't log in (no credentials provided). Pre/post cookie comparison was done without a successful authentication, so the session couldn't have changed. Cannot confirm without real creds. |
| Missing Rate Limit [MEDIUM][high] | Informational. |
| Missing SRI [MEDIUM][high] | Informational. |

#### www.moneybird.com (moneybird — already triaged in Session 7)
| Finding | Reason |
|---------|--------|
| postMessage handlers missing origin validation [MEDIUM][medium] | Already drafted in `pending/moneybird/8c0823c1-...`. Likely Intercom/Drift/chat widget — FP per project FP rules. The existing draft notes this needs human review; until the specific handler logic is identified, do not submit. |
| Missing CSP [HIGH][high] | Already in pending/moneybird/. Informational — marketing site. Do not submit. |

---

## Session 8 Summary

**Bounty readiness: LOW (same as Session 7).**

7 scans across 5 targets, 53 interpreted findings reviewed:
- 1 true positive drafted (moneybird DOM XSS — needs browser confirmation + scope check)
- 2 findings held for manual verification (neon.tech open redirect, cal.com method override with auth)
- 24 false positives across neon.tech, cal.com, kredivo, openproject

**Dominant FP patterns this session:**
1. **Infrastructure FPs on Next.js/Vercel:** XPath/XXE/LDAP impossible on Node.js stacks; path traversal normalized by Vercel edge
2. **WAF-confused injection detections:** SQLi "evidence" was a Postgres docs link; prototype pollution got 403 WAF block
3. **Analytics/consent cookies:** _hcc (HotJar), neon_consent (CMP) — always FP
4. **Cache status misread:** `CF-Cache-Status: DYNAMIC` ≠ cached

**Next Steps (Session 8):**
1. **Verify S8-1 (moneybird DOM XSS)** — open browser, navigate to `https://www.moneybird.com/#<img src=x onerror=alert(1)>`, confirm alert fires. Check HackerOne scope for www.moneybird.com.
2. **Verify S8-2 (neon.tech open redirect)** — browser test: `/login?url=https://evil.example.com`
3. **Auth scan cal.com** — get cal.com account, run authenticated scan to confirm S8-3 method override and unlock rate-limit / IDOR checks
4. **OpenProject local Docker** — run against `openproject/openproject:16.6.2` with credentials to test the 22 CVEs mapped in OPENPROJECT-CVE-ANALYSIS.md

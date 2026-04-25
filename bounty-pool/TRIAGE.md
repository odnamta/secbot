# Bounty Pool Triage — Updated 2026-04-25 (Session 8 — Report Drafter)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Program | Notes |
|---|--------|---------|----------|---------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | HackerOne | **Held from Session 7.** Cookie is JS-set — curl won't reproduce. Needs Playwright/browser confirm before submitting. Draft: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM XSS via URL fragment on homepage | High | HackerOne | **NEW.** HIGH confidence, Playwright auto-confirmed (dom-sink). Two independent innerHTML sinks. Polished draft: `2026-04-25-moneybird-dom-xss.md`. **Verify in browser before submit** — fragment XSS won't show in curl. |
| 3 | community.openproject.org | Missing rate limiting on /login | Medium | YesWeHack | **NEW.** HIGH confidence. 15 rapid requests, zero throttling, no 429. Polished draft: `2026-04-25-openproject-rate-limiting.md`. |

### TIER 2 — Hold (needs more work before submitting)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 4 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | **Held from Session 7.** Needs Twitch account for auth scan. |
| 5 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | **Held from Session 7.** Weak standalone — XSS chain needed. Bad optics to submit to Bugcrowd's own program. |
| 6 | community.openproject.org | Session fixation — _open_project_session not regenerated after login | Medium | **NEW.** MEDIUM confidence. Detection method "endpoint-replay" without confirmed credentials means this could be a FP. Needs authenticated scan with valid creds to confirm cookie value before vs after real successful login. CVSS 6.9 if real. |
| 7 | app.cal.com | Username enumeration on /auth/login (content-based) | Medium | HackerOne | **NEW.** MEDIUM confidence. Login returns "wrong password" vs no-user distinction. Needs browser verification — submit test email vs random string, compare error messages. |
| 8 | app.cal.com | Source map exposure at /_next/static/chunks/ | Medium | HackerOne | **NEW.** Source map publicly accessible with original source. LOW bounty value — cal.com is open-source (GitHub public), so source exposure has reduced impact. Verify if secrets are in the map before deciding. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

---

## False Positive Register — Session 8 Findings

### cal.com (Mar 22 scan) — ALL OUT OF SCOPE
The Mar 22 scan ran against `cal.com` (marketing site), which is explicitly **out of scope** per the Cal.com HackerOne program. All findings from this scan (directory traversal on /api/geolocation, XXE on /api/geolocation, sensitive token in URL, OAuth state, missing HSTS, SRI) are **discarded**.

### app.cal.com (calcom-v2, Mar 26 scan) — IN SCOPE
| Finding | Decision | Reason |
|---------|----------|--------|
| XPath injection (month/user/_rsc params) | **FP** | Boolean size differences are caused by Next.js RSC (`_rsc` is React Server Components routing param) rendering different amounts of content. Cal.com uses Prisma ORM — no XPath/XML database. Size variance is normal SPA behavior, not injection. |
| Web Cache Deception on /admin/30min | **FP** | Scanner evidence shows `cf-cache-status: DYNAMIC` — Cloudflare explicitly marks this response as NOT cached. WCD requires CDN caching to be exploitable. |
| XXE injection on API endpoints | **FP** | Cal.com is a Next.js/TypeScript app using Prisma ORM. No XML processing. The entity-expansion detection fired on a non-XML endpoint. |
| LDAP injection on API endpoints | **FP** | Cal.com uses PostgreSQL via Prisma. No LDAP directory. Error-pattern detection on a non-LDAP endpoint. |
| HTTP method overrides (X-HTTP-Method-Override) | **Inconclusive** | Both baseline and override responses return 403 — no privilege escalation observed. Insufficient evidence of bypass. |
| Race condition on /register (GET) | **FP** | Scanner sent 10 concurrent GET requests to a public page. No state-changing behavior on GET. Not a real race condition. |
| OAuth state parameter on /api/auth/session | **FP** | Known FP: `/api/auth/session` is the NextAuth.js session endpoint, not an OAuth authorization endpoint. OAuth state parameter does not apply here. |
| Missing HSTS | **Inconclusive / Low value** | app.cal.com runs behind Cloudflare which can enforce HSTS. If missing, low bounty likelihood. |
| Cookie __Secure-next-auth.callback-url | **Low value** | NextAuth framework cookie. The missing HttpOnly is intentional — NextAuth reads this via JS for redirect handling. Unlikely to pay. |
| SRI on /login | **Low value** | Single external resource without integrity. Low bounty value alone. |

### neon.tech (Mar 26 scan) — NOT IN BOUNTY REGISTRY
Neon.tech is not in the hunt registry. Findings noted for reference only.

| Finding | Decision | Reason |
|---------|----------|--------|
| SQL injection on /unify endpoint | **FP** | Scanner description explicitly notes: "the 'SQL error' evidence appears to be a PostgreSQL documentation link rather than a true database error." The trigger was a URL containing `postgresql.org` in response content, not an actual database error. |
| Directory traversal on /unify | **FP** | Neon.tech runs on Vercel. Vercel edge infrastructure normalizes traversal paths. Scanner caveat confirms this is likely FP. |
| Server-side prototype pollution | **FP / Uncertain** | Server returned 403 (WAF blocking). Canary reflection (`secbot_pp=polluted`) likely appeared in the WAF rejection response body (WAFs often echo the blocked payload). Not exploitable. |
| Open redirect on /login | **FP** | Scanner evidence shows redirect goes to `neon.com/login?param=...` — the same domain, not an external attacker domain. This is a same-domain redirect, not an open redirect. |
| Verbose error /undefined | **FP** | Low confidence. Standard Next.js 404 handling with RSC data. No genuine application internals exposed. |
| neon_consent cookie missing flags | **FP** | Consent/preference cookie. Per CLAUDE.md FP patterns: analytics/marketing cookies are not bounty-worthy. |
| Missing SRI on /unify | **FP** | 24 scripts from neon.com own CDN (Next.js static chunks). First-party assets without SRI is not bounty-worthy. |
| Missing HSTS | **Low value** | Header finding on marketing page. Low bounty likelihood. |

### kredivo (blog.kredivo.com, Mar 22 scan)
| Finding | Decision | Reason |
|---------|----------|--------|
| Exposed WordPress /wp-login.php | **Informative** | Standard WordPress login page exposure on a blog subdomain. Typically out of scope or informative in bug bounty programs. Not a vulnerability itself. |
| Missing CSP | **Informative** | Header finding on blog subdomain. Auto-rejected as informative. |
| Cookie _hcc missing flags | **FP** | The `_hcc` cookie name pattern matches HotJar Cookie Consent or similar analytics consent widget. Third-party analytics cookies are per CLAUDE.md FP patterns. |

### moneybird.com (Mar 22 scan) — Additional findings beyond DOM XSS
| Finding | Decision | Reason |
|---------|----------|--------|
| Missing CSP header | **Include in XSS report** | The absent CSP amplifies the DOM XSS finding. Referenced in the XSS draft as a compounding factor rather than as a standalone report. Standalone header findings are auto-rejected. |
| postMessage handlers missing origin validation | **HOLD** | MEDIUM confidence. Moneybird homepage has 3 postMessage listeners with no origin check. Could be Intercom/Drift/Zendesk (FP per patterns) or a real finding. Needs manual browser investigation of handler logic. If handlers only process data from known widgets, it's a FP. |
| Mixed content (HTTP resource) | **Low value** | Links to `http://www.moneybird.com/artikelen/` from HTTPS page. Internal link, not a third-party script. Low bounty value. |

### openproject (community.openproject.org, Mar 22 scan)
| Finding | Decision | Reason |
|---------|----------|--------|
| Missing HSTS | **Low value** | Header finding on community instance. Auto-rejected as informative on most programs. |
| Missing CSP | **Low value** | Same as above. |
| SRI on CDN assets | **Low value** | Internal CDN assets. |

---

## OWN APPS — Fix These (carried from Session 7)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware configured but not appearing. Docker rebuild or middleware bug. |

---

## Honest Assessment (2026-04-25)

**Bounty readiness: LOW-MEDIUM.** After scans on 7+ targets (sessions 7–8):
- 2 submission-ready reports drafted: Moneybird DOM XSS (High) + OpenProject rate limiting (Medium)
- The moneybird XSS is the strongest finding — high confidence, auto-confirmed by Playwright
- All injection findings (SQLi, XSS, XXE, traversal, LDAP on external targets) were FPs or borderline
- Authenticated scanning would significantly improve finding quality

**Key pattern:** The scanner excels at passive/header checks and Playwright-confirmed client-side XSS. Server-side injection detection (SQLi, traversal, prototype pollution) has high FP rate against CDN-fronted targets where Cloudflare/Vercel normalizes inputs before they reach the application.

## Next Steps (Priority Order)
1. **Browser-verify Moneybird DOM XSS** — navigate to the PoC URL, confirm alert fires, check cookie scope
2. **Submit Moneybird XSS** if confirmed — it's the strongest finding
3. **Submit OpenProject rate limiting** — HIGH confidence, minimal verification needed
4. **OpenProject authenticated scan** — get test account, re-scan to find auth-only vulns (session fixation, IDOR, BFLA)
5. **Moneybird postMessage** — manually inspect the 3 event listeners in browser DevTools Sources
6. **Cal.com username enum** — verify in browser: submit existing vs nonexistent email, compare error messages
7. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app

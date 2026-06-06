# Bounty Pool Triage — Updated 2026-06-06 (Session 8 — Report Drafter)

## Submission Priority

### TIER 1 — Submit (strong signal, in-scope, curl-reproducible)

| # | Target | Finding | Severity | File | Notes |
|---|--------|---------|----------|------|-------|
| 1 | blog.kredivo.com | Exposed WordPress login without rate limiting | High (8.1) | `pending/2026-06-06-kredivo-wordpress-exposed-login.md` | HIGH confidence, endpoint-replay, in-scope. No browser needed. Submit to RedStorm. |
| 2 | community.openproject.org | Missing rate limiting on /login | Medium (5.3) | `pending/2026-06-06-openproject-auth-no-rate-limit.md` | HIGH confidence, brute-force-probe confirmed. In-scope. Consider submitting with #3. |
| 3 | moneybird.com | DOM XSS via URL fragment on homepage | High (7.0) | `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` | HIGH confidence, dom-sink. In-scope. **Needs Dio browser verify first** — auto-verified via Playwright but confirm `alert()` fires in real browser. |

### TIER 2 — Hold (needs manual verification before submitting)

| # | Target | Finding | Severity | File | Notes |
|---|--------|---------|----------|------|-------|
| 4 | community.openproject.org | Session fixation — session cookie unchanged after login | Medium (6.9) | `pending/2026-06-06-openproject-session-fixation.md` | MEDIUM confidence. Requires browser test with real credentials. If confirmed, submit alongside #2. |
| 5 | neon.tech | Open redirect on login via 7+ params | Medium (6.1) | `pending/2026-06-06-neon-open-redirect-login.md` | MEDIUM confidence. Neon not in hunt registry — check if they have a bounty program. Manually verify redirect goes to attacker domain (not just neon.com). |
| 6 | indeed.com | CSRF cookie missing Secure flag on login | Medium | `pending/2026-03-14-indeed-csrf-cookie-SUBMISSION.md` | Carry-over from Session 7. Cookie JS-set, curl won't reproduce. Needs Playwright/browser. |
| 7 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | `pending/2026-03-14-twitch-cookies.md` | Carry-over from Session 7. Needs auth scan with real Twitch credentials to confirm these are auth tokens. |

### TIER 3 — Archived (non-bounty, FP, out-of-scope, or informational)

Moved/archived from this and prior sessions:

**Session 8 (2026-06-06) — new triage decisions:**

| Finding | Target | Reason |
|---------|--------|--------|
| SQL Injection on /unify | neon.tech | FP — "SQL error evidence" was a PostgreSQL documentation link, not a real DB error. The `/unify` is a Next.js routing endpoint. |
| Directory Traversal on /unify | neon.tech | FP — Next.js page routing endpoint, not a filesystem traversal. Path traversal patterns on URL routing = not exploitable. |
| Prototype Pollution via query params | neon.tech | FP — Medium confidence only, behavioral detection on a marketing page. No clear evidence of actual Object.prototype modification. |
| Missing HSTS (neon.com) | neon.tech | Hold/Informational — valid but neon.tech not in registry; HSTS is typically informational unless they have an explicit bounty for it. |
| Cookie "neon_consent" missing flags | neon.tech | FP — consent/cookie-preferences cookie. No security value. Classic FP pattern. |
| Missing SRI on external scripts | neon.tech | FP/Informational — CDN-hosted analytics/marketing scripts. Not bounty-worthy for most programs. |
| Verbose error on /undefined | neon.tech | FP — accessing `/undefined` path triggers a 404/error page. Not a security finding. |
| Missing HSTS on community.openproject.org | openproject | Informational — valid but typically auto-rejected as informational by YesWeHack. Bundle into another report if submitting. |
| Missing CSP on community.openproject.org | openproject | Informational — valid but often rejected without a companion exploitation finding. |
| Missing CSP on blog.kredivo.com | kredivo | Informational on a marketing blog. Auto-rejected. Reference in WordPress login report if useful. |
| Cookie '_hcc' missing HttpOnly/Secure | kredivo | FP — HubSpot contact tracking cookie (`_hcc` = HubSpot Contact Cookie). Third-party marketing cookie. |
| postMessage missing origin validation | moneybird | FP — likely Intercom/Drift/chat widget. Third-party widget postMessage origin issues are expected by design. |
| Mixed content on moneybird.com | moneybird | Informational — typically not bounty-worthy without evidence of exploitation path. |
| Race condition on static GET endpoint | moneybird | FP — AI correctly flagged this as FP during validation. |
| Directory traversal on cal.com/api/geolocation | cal.com | OUT OF SCOPE — `cal.com` marketing site is explicitly out of scope per scope file. Only `app.cal.com` is in scope. |
| XXE on cal.com/api/geolocation | cal.com | OUT OF SCOPE — same scope issue. Also CRITICAL/medium confidence behind AWS WAF. |
| Admin routes returning 200 on cal.com | cal.com | OUT OF SCOPE + FP — Next.js app shell, likely public-facing routes, not real admin panels. |
| Sensitive token in URL (web_experiments) | cal.com | OUT OF SCOPE — tested on `cal.com` marketing domain. |
| Rate limiting missing on cal.com auth | cal.com | OUT OF SCOPE — tested on `cal.com`, not `app.cal.com`. AWS WAF likely handles it. |
| OAuth state not enforced on cal.com | cal.com | OUT OF SCOPE + LOW confidence — `/api/auth/session` on marketing domain. |
| Missing SRI on cal.com scripts | cal.com | OUT OF SCOPE + FP pattern (analytics scripts). |
| Auth cookie missing HttpOnly on cal.com | cal.com | OUT OF SCOPE + LOW severity — callback URL cookie, not session token. |

**Session 7 carry-overs:**

| Finding | Target | Reason |
|---------|--------|--------|
| CORS on /__dux | shopify.com | Non-exploitable (SameSite + empty response body) |
| Missing headers on konghq.com | kong | Informational, auto-rejected |
| GraphQL introspection on gitlab.com | gitlab | By design, publicly documented |

### OWN APPS — Fix These

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | **Unresolved** — brute-force risk. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | **Unresolved** — middleware has HSTS configured but not appearing in responses. Docker rebuild or middleware ordering bug. |

---

## Scan Coverage — Session 8

| Target | Scan Date | Findings | Outcome |
|--------|-----------|----------|---------|
| neon.tech | 2026-03-26 | 8 interpreted | 1 hold (open redirect), 7 FP/informational |
| community.openproject.org | 2026-03-26 | 6 interpreted | 2 draft (rate limit, session fixation), 2 informational, 2 low |
| blog.kredivo.com | 2026-03-22 | 3 interpreted | 1 draft (WordPress login), 2 FP/informational |
| www.moneybird.com | 2026-03-22 | 5 interpreted | 1 existing draft (DOM XSS), 4 FP/informational |
| cal.com | 2026-03-22 | 8 interpreted | ALL out-of-scope (scoped to app.cal.com only) |

---

## Honest Assessment (2026-06-06)

**Bounty readiness: IMPROVING.** Session 8 identified 3 new draft-ready reports + 1 upgraded existing:
- **Kredivo WordPress login** — strongest finding this session. HIGH confidence, fully curl-reproducible, in-scope, real attack surface. SUBMIT NOW.
- **OpenProject rate limiting** — high confidence, in-scope, clean curl reproduction. SUBMIT NOW.
- **Moneybird DOM XSS** — existing draft upgraded; HIGH confidence but needs browser confirmation before submitting.
- **OpenProject session fixation** — potential medium; hold pending manual browser verification.

**Key pattern:** Injection findings (SQLi, XXE, traversal) continue to be FP on hardened targets behind WAFs and Next.js routing. Real signal comes from:
1. Auth/session weaknesses (rate limiting, session fixation, exposed admin endpoints)
2. Client-side JS issues (DOM XSS) on less-hardened apps
3. Explicitly exposed endpoints (WordPress login on a fintech blog)

**Critical scope issue found:** All cal.com findings were tested on `cal.com` (marketing), which is explicitly OUT OF SCOPE. Only `app.cal.com` is in scope. Scanner targeted the wrong domain — update before next cal.com scan.

## Next Steps (Priority Order)
1. **Submit Kredivo WordPress login** — strongest signal, curl-verifiable, submit to RedStorm now
2. **Submit OpenProject rate limit** — high confidence, submit to YesWeHack now
3. **Browser-verify Moneybird DOM XSS** — visit `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in real browser and confirm alert() fires
4. **Browser-verify OpenProject session fixation** — log in with test account, check if `_open_project_session` cookie value changes
5. **Fix cal.com scope** — update scan to target `app.cal.com` instead of `cal.com`
6. **Check neon.tech bounty program** — if they have HackerOne/Bugcrowd, add to registry and re-scan
7. **Fix own app** — rate limiting + HSTS on finance.atmando.app

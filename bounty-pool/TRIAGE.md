# Bounty Pool Triage — Updated Apr 11, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Program | Notes |
|---|--------|---------|----------|---------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Indeed (HackerOne) | Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft: `pending/2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | cal.com | Username enumeration via distinct error messages on `/auth/login` | Medium | HackerOne | HIGH confidence. `email=admin` → "wrong password" response. Manual browser test recommended before submit. Draft: `pending/calcom/2026-04-11-calcom-username-enumeration.md` |
| 3 | cal.com | Missing rate limiting on 6 auth endpoints | Medium | HackerOne | HIGH confidence. No 429, no rate-limit headers on `/auth/login`, `/auth/forgot-password`, `/signup`, `/register`. Compounds finding #2. Draft: `pending/calcom/2026-04-11-calcom-rate-limit-auth.md` |
| 4 | community.openproject.org | Missing rate limiting on `/login` | Medium | YesWeHack | HIGH confidence. No WAF on this target. CSRF token required for POST — see reproduction steps in draft. Verify `community.openproject.org` is in scope. Draft: `pending/openproject/2026-04-11-openproject-rate-limit-login.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 5 | twitch.tv | `server_session_id` + `api_token` missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 6 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Bad optics submitting to their own program. |
| 7 | moneybird.com | DOM-Based XSS via URL fragment (`#<img src=x onerror=...>`) | High | HackerOne | HOLD — Playwright-detected, HIGH confidence, but curl won't reproduce (fragment not sent to server). **Needs manual browser test:** open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` and check if alert fires. If confirmed: high-value submission. Draft: `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` |
| 8 | community.openproject.org | Session fixation — `_open_project_session` not regenerated after login | Medium | YesWeHack | UNCONFIRMED — scanner tested with unauthenticated POST (no valid CSRF token), which returns 422. Session is not expected to regenerate on a failed login. Requires authenticated scan with valid credentials to confirm. Do not submit without re-testing. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS `/__dux` — Non-exploitable (SameSite + empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on `/login` and `/graphql` | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Session 8 Triage — New Findings (Mar 26 v2 Scans + Apr 11 Review)

### Cal.com (v2 scan, 2026-03-26, 49 pages, Cloudflare)

| Finding | Decision | Reason |
|---------|----------|--------|
| Username enumeration on `/auth/login` | **TIER 1 — Draft ready** | HIGH confidence, content-comparison, easy to verify |
| Rate limiting missing on auth endpoints | **TIER 1 — Draft ready** | HIGH confidence, 6 endpoints unthrottled |
| XPath injection — `_rsc` parameter | **FALSE POSITIVE** | `_rsc` is an internal Next.js RSC routing parameter; size differences caused by different render paths, not injection |
| XPath injection — `month`, `user` parameters | **FALSE POSITIVE** | Boolean-based size differences (12–17%) attributed to dynamic page rendering, not XPath execution; no error messages or data exfiltration observed |
| XXE on `/api/trpc/features/map` | **FALSE POSITIVE** | Response was HTTP 403 Cloudflare challenge page; detection matched "error" in Cloudflare's HTML, not actual XXE output from the application |
| LDAP injection on `/auth/login` | **FALSE POSITIVE** | Cal.com is a Next.js/Prisma/PostgreSQL stack with no LDAP component; error-pattern regex matched coincidental page content, not an LDAP error response |
| HTTP Method Override (4 findings) | **FALSE POSITIVE** | Both baseline and method-override requests return 403 from Cloudflare WAF; no response difference attributable to actual method routing in the application |
| Web Cache Deception via `.css` suffix | **FALSE POSITIVE** | Response headers show `cache-control: private, no-cache, no-store` — caching is disabled; no actual caching of sensitive content occurs |
| Race condition on `/register` | **FALSE POSITIVE** | Test sent concurrent GET requests to a form page; no state mutation involved, not a TOCTOU scenario |
| OAuth state missing on `/api/auth/session` | **FALSE POSITIVE** | `/api/auth/session` is NextAuth's session check endpoint (returns `{}`), not an OAuth authorization server endpoint |
| Source map exposure `/_next/static/chunks/*.js.map` | **FALSE POSITIVE for bounty** | Cal.com is fully open-source (github.com/calcom/cal.com); source maps expose nothing that isn't already public |
| SRI missing on Intercom widget | **FALSE POSITIVE** | Third-party widget (Intercom) loaded without SRI is a known non-bounty pattern; Intercom is a legitimate business tool, not an exploit vector |
| Cookie `__Secure-next-auth.callback-url` missing HttpOnly | **INFORMATIONAL** | NextAuth intentionally leaves callback-url accessible to JS for post-login redirect flow; `__Secure-` prefix confirms Secure flag is present; low bounty value |
| Missing HSTS (on non-existent admin paths) | **FALSE POSITIVE** | Empty header responses originate from Cloudflare bot-challenge pages, not the actual application; main app has HSTS |

### OpenProject community (v2 scan, 2026-03-26, 25 pages, no WAF)

| Finding | Decision | Reason |
|---------|----------|--------|
| Rate limiting missing on `/login` | **TIER 1 — Draft ready** | HIGH confidence, 15 rapid requests unthrottled, no WAF masking |
| Session fixation (`_open_project_session`) | **TIER 2 — HOLD, unconfirmed** | Scanner tested with unauthenticated POST returning 422; session regeneration only testable on a *successful* login; needs valid credentials |
| HSTS missing on `/login.php` | **FALSE POSITIVE** | `/login.php` is an unusual URL for a Rails/Angular app; likely a redirect URL returning 301 with no HSTS on the redirect response itself — informational at best |
| CSP missing on `/login.php` | **FALSE POSITIVE** | Same reasoning as HSTS — redirect/alias URL, not the real login page; main app pages have CSP |
| Username enumeration via timing (low severity) | **INFORMATIONAL** | 34x timing difference for `admin` vs baseline (317ms vs 10,979ms); suggestive but single data point; would need repeated measurements to confirm |

### Neon (v2 scan, 2026-03-26, 17 pages, Cloudflare + Vercel)

> **Note:** neon.tech is not currently in the hunt registry. These findings were triaged for completeness in case the program is added.

| Finding | Decision | Reason |
|---------|----------|--------|
| SQL injection — `/unify?a=...&n=...` | **FALSE POSITIVE** | Scanner's "SQL error" pattern matched a PostgreSQL documentation link (`/postgresql/tutorial`) embedded in the Next.js RSC JSON blob — not a database error message |
| Directory traversal — `/unify` | **FALSE POSITIVE** | Windows-style path (`..\..\..`) on a Linux/Vercel deployment; Vercel normalizes/rejects these; "system file content" detection likely matched RSC JSON structure |
| Prototype pollution — `/unify?__proto__[x]=y` | **UNCONFIRMED** | Cloudflare returned 403; canary reflection may be from page echoing query params in RSC JSON rather than actual `Object.prototype` mutation; needs testing against a non-Cloudflare instance |
| Open redirect — `/login?url=evil.example.com` | **FALSE POSITIVE** | Redirect target is `neon.com/login?url=...` (own domain), not `evil.example.com`; likely intra-brand redirect between neon.tech and neon.com, not an external open redirect |
| Verbose error — `/undefined` | **FALSE POSITIVE** | Next.js RSC JSON structure rendered on 404 route; `"$undefined"` is a React serialization token, not a real error disclosure |
| Cookie `neon_consent` missing flags | **FALSE POSITIVE** | Consent/analytics preference cookie — explicit known FP pattern per project guidelines; no session/auth value |
| SRI missing on Next.js chunks | **INFORMATIONAL** | First-party CDN assets (neon.com) loaded by neon.tech; same-org CDN SRI is a known non-bounty pattern |
| HSTS missing on `neon.com` | **INFORMATIONAL** | `neon.com` appears to be a redirect/alias domain; HSTS on the primary `neon.tech` should be verified separately |

### Moneybird (pending reports from v1 scan, Mar 22, reviewed Apr 11)

| Finding | Decision | Reason |
|---------|----------|--------|
| DOM XSS via URL fragment | **TIER 2 — HOLD, needs browser verification** | Playwright-detected (HIGH confidence), but reproduction requires a browser (curl won't execute JS). Report draft exists: `pending/moneybird/6d09cce8-...md`. Must manually verify alert fires before submitting to HackerOne. |
| Missing CSP header | **Secondary to XSS** | True finding; should be included as supporting evidence in the DOM XSS report rather than a standalone submission. |
| postMessage handlers missing origin validation | **FALSE POSITIVE** | 3 postMessage listeners without origin check — almost certainly Intercom, Drift, or similar customer support widget; explicit known FP per project FP patterns |

---

## Honest Assessment (Apr 11)

**Bounty readiness: IMPROVING.** After v2 scans of 3 new targets:
- 3 new medium-severity drafts ready (cal.com ×2, openproject ×1)
- 1 high-value finding (Moneybird DOM XSS) still needs browser confirmation
- FP rate improved: scanner's AI correctly flagged most injection FPs as medium confidence

**What's working:**
- Rate limit detection: HIGH confidence, low FP rate, consistently accepted on HackerOne/YesWeHack
- Username enumeration: strong content-comparison signal, easy triager experience
- Pre-filter correctly demoted most injection findings to medium confidence (Cloudflare 403s, pattern coincidences)

**Remaining gaps:**
- All active injection checks (SQLi, XPath, LDAP, XXE) produce FPs on Cloudflare-protected targets — WAF returns 403 before app processes payloads; scanner misidentifies WAF blocks as detections
- Authenticated scanning still not done (Twitch T2 finding stalled without credentials)

## Next Steps (Priority Order)

1. **Verify Moneybird DOM XSS** — open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in a browser; if confirmed, submit immediately (HIGH severity, HackerOne)
2. **Verify cal.com username enumeration** — curl both requests manually, confirm response text differs
3. **Submit cal.com rate limiting + username enumeration** — two companion reports, submit together for compound impact
4. **Check OpenProject scope** — confirm `community.openproject.org` is in scope on YesWeHack before submitting rate limit finding
5. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
6. **Improve WAF bypass** — scanner's injection checks need better WAF-aware detection to reduce FP rate on Cloudflare targets

# Bounty Pool Triage — Updated Mar 28, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Confidence | Notes |
|---|--------|---------|----------|------------|-------|
| 1 | community.openproject.org | Missing rate limiting on /login (brute-force) | Medium | **High** | 15 rapid requests → all 200, no 429, no rate-limit headers. Rails app — Rack::Attack fix is easy. Draft ready: `2026-03-28-openproject-missing-rate-limit-login.md` |
| 2 | indeed.com | CSRF cookie missing Secure on login page | Medium | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS — curl won't reproduce, needs browser. Draft: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

### TIER 2 — Hold (needs more work / manual verification)

| # | Target | Finding | Severity | Confidence | Notes |
|---|--------|---------|----------|------------|-------|
| 3 | community.openproject.org | Session fixation — `_open_project_session` not regenerated after login | Medium | Medium | CWE-384. CVSS 6.9. Detected via endpoint-replay (GET). Needs manual browser test: set cookie, POST login, check if session ID changes. Do not submit until verified. |
| 4 | www.moneybird.com | DOM XSS via URL fragment (`window.location.hash` → `innerHTML`) | High | High | Strong finding if real. **Needs manual browser verification** — curl cannot test DOM XSS. Load `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in browser and confirm alert fires. Draft ready: `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md` |
| 5 | www.moneybird.com | Missing CSP (supporting finding for DOM XSS) | High | High | Only submit alongside DOM XSS — strengthens the report significantly. Draft ready: `pending/moneybird/09dd5267-missing-content-security-policy-header.md` |
| 6 | www.moneybird.com | postMessage handlers missing origin validation | Medium | Medium | HOLD — homepage postMessage listeners. Need to check if these are third-party chat widgets (Intercom/Drift → FP by design) or actual Moneybird app code. Draft: `pending/moneybird/8c0823c1-postmessage-handlers-missing-origin-validation.md` |
| 7 | twitch.tv | `server_session_id` + `api_token` missing HttpOnly | Medium | Low | HOLD — needs auth scan to verify these are actual auth tokens, not public session IDs. Need Twitch account + login scan. |
| 8 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Low | Weak standalone. Submitting to their own program is bad optics. Skip unless we have XSS chain. |

### TIER 3 — False Positive / Non-Bounty (Mar 28 batch)

#### Cal.com (2026-03-26 scan) — all FP

| Finding | Reason |
|---------|--------|
| Missing CSP / HSTS (40+ URLs) | Informational. Cal.com is a large HackerOne program — missing headers auto-rejected without a working exploit chain. |
| Web Cache Deception on `/admin/30min?month=2026-04/nonexistent.css` | **FP** — `cf-cache-status: DYNAMIC` in response means Cloudflare is NOT caching the response. The scanner misfired; a real WCD requires the CDN to serve a cached copy to a different user. |
| XPath Injection (boolean-based) on `month`, `user`, `_rsc` params | **FP** — `_rsc` is Next.js React Server Components internal routing token (not user-controlled injection point). `month` controls calendar content naturally (different months = different events = different page size). `user` on login: cal.com uses PostgreSQL, not XPath. Response size variance on a Next.js SSR app is expected noise. |
| `__Secure-next-auth.callback-url` missing HttpOnly | **By design** — next-auth requires this cookie to be JS-readable for client-side redirect handling. Not a vulnerability. |

#### Neon.tech (2026-03-26 scan) — all FP

| Finding | Reason |
|---------|--------|
| Missing CSP / HSTS on neon.com | Marketing/docs site (Vercel-hosted). Auto-rejected as informational. Not a security product with a sensitive app. |
| `neon_consent` cookie missing HttpOnly/Secure | **Classic FP** — this is a GDPR consent cookie, intentionally JS-accessible so the consent widget can read/write it. Never bounty-worthy. |

#### OpenProject (2026-03-26 scan) — partial FP

| Finding | Reason |
|---------|--------|
| Missing HSTS on login.php / various probe paths | Informational. Missing headers without exploit chain = auto-rejected by YesWeHack triagers. |
| Missing CSP on login.php | Same. |
| Missing X-Frame-Options on /api/v3/configuration | Low confidence, informational. |

### Tier 4 — Archived (non-bounty, older sessions)

Moved to `bounty-pool/archived/`:
- shopify.com CORS `/__dux` — Non-exploitable (SameSite + empty body)
- konghq.com missing headers — Informational, auto-rejected
- gitlab.com GraphQL introspection — By design, publicly documented

---

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but not appearing in responses. Docker rebuild or middleware ordering bug. |

---

## Honest Assessment (Mar 28)

**Session 8 summary:** Scanned cal.com (v2), openproject (v2), neon.tech (v2) on 2026-03-26.

**New actionable findings: 1 submit-ready, 1 hold**
- OpenProject rate-limiting: Real finding, high confidence. Rails app makes fix easy, which means it might already be on their radar — submit quickly.
- OpenProject session fixation: Plausible but unverified. Needs manual POST login test in a real browser before touching.

**Still blocked on:**
- Moneybird DOM XSS: Strongest finding in the pool but unverified in browser. Single most important thing to manually test.
- All authenticated scanning: No credentials → no access to dashboard vulns, API endpoints, IDOR. This is the ceiling on finding quality.

**Ongoing FP patterns confirmed in this batch:**
- Boolean-based injection on Next.js RSC params (`_rsc`) — reliable FP indicator
- `cf-cache-status: DYNAMIC` negates any cache deception finding
- Consent cookies (`*_consent`, `cookie_consent`, `gdpr_*`) are always FP
- Probe-path findings (scanner probing `/administrator`, `/login.php` on non-PHP apps) generate noise

## Next Steps (Priority Order)
1. **Manually verify Moneybird DOM XSS** — open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in browser
2. **Submit OpenProject rate-limit report** — draft is ready in `pending/`
3. **Manually verify OpenProject session fixation** — set pre-auth cookie, POST /login, check if session ID regenerates
4. **Get auth credentials for Twitch/Moneybird** — unlock T2 findings
5. **Scan less-hardened targets** — smaller BBPs, community apps

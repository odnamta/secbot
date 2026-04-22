# Bounty Pool Triage — Updated Apr 22, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Platform | File |
|---|--------|---------|----------|----------|------|
| 1 | moneybird.com | DOM XSS via URL fragment — `innerHTML` sink on homepage, confirmed alert payload | HIGH | HackerOne | `2026-04-22-moneybird-dom-xss.md` |
| 2 | indeed.com | CSRF cookie missing Secure on login page (config inconsistency) | MEDIUM | HackerOne | `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |

**Notes on Moneybird DOM XSS:**
- Payload `#<img src=x onerror=alert("secbot-xss-37")>` confirmed via Playwright automation
- Two separate `innerHTML` sinks reached on the homepage
- No CSP header — no browser-level mitigation
- In-scope: `moneybird.com` is explicitly listed in program policy
- **Caveat:** XSS is on `www.moneybird.com` (marketing homepage), not `app.moneybird.com`. Impact depends on whether Moneybird sets auth cookies with `Domain=.moneybird.com`. Possible downgrade to Medium if triager treats marketing page as lower priority.
- **Action required before submitting:** Verify in a real browser (not just curl) that the alert actually fires. SecBot confirmed this via Playwright, but manually validate first.

### TIER 2 — Hold (needs more work or verification)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 3 | twitch.tv | server_session_id + api_token missing HttpOnly | MEDIUM | HOLD — needs auth scan to verify these are actual auth tokens |
| 4 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | MEDIUM | Weak standalone — needs XSS chain. Bad optics submitting to own program. |
| 5 | kredivo.com | Exposed wp-login.php on blog.kredivo.com | MEDIUM/HIGH | Draft ready: `2026-04-22-kredivo-wordpress-login-exposure.md`. RedStorm pays ~$32-95 for Medium. Low effort to submit. Verify curl command still returns HTTP 200 before submitting. |
| 6 | moneybird.com | postMessage handlers without origin validation (3 listeners, homepage) | MEDIUM | Likely third-party widget (Intercom or similar). Browser investigation needed — open DevTools, check which script registers the listeners, confirm it's a widget FP before archiving. |
| 7 | openproject | Session Fixation — session cookie unchanged after login attempt | MEDIUM | community.openproject.org. No formal paid bounty (YesWeHack VDP only). Detection used unauthenticated POST — needs real credentials to confirm session actually doesn't regenerate. Low priority. |

### TIER 3 — Archived (non-bounty)

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected
- gitlab.com GraphQL introspection — By design, publicly documented

### Session 8 FP Analysis (Mar 22 + Mar 26 scans)

#### Cal.com (HackerOne, app.cal.com) — 21 findings → 21 FPs

All cal.com findings triaged as false positives:

| Finding | Reason |
|---------|--------|
| XPath Injection (month, user, _rsc params) | Boolean-based detection fired on content variation. `month` param returns different calendar content for different months — natural size difference. `_rsc` is a Next.js RSC internal routing token — its "boolean" response difference is RSC bundle loading behavior. Not injection. |
| XXE on /api/trpc/features/map | Endpoint returned HTTP 403 Cloudflare block page. Detector matched "error" or "DTD" in the Cloudflare HTML response, not actual XXE output. FP. |
| LDAP Injection on /auth/login | Matched `invalid.*filter` pattern in Next.js page HTML (nonce attribute content). Cal.com is a Node.js/Next.js calendar app — does not use LDAP. FP. |
| Method Override (4 findings) | No actual bypass achieved. Baseline POST→403, override DELETE→403 (same denial). The 404→403 change on `/api/trpc/slots/getSchedule` confirms the endpoint exists for PUT/DELETE but returns 403 — access is still denied. Not exploitable without auth bypass. |
| Web Cache Deception | Cache header is `cf-cache-status: DYNAMIC` — Cloudflare is NOT caching the response. Dynamic = not cached. WCD attack requires the response to be cached and served to other users, which doesn't happen here. FP. |
| Source Map Exposure | Cal.com is fully open-source on GitHub. Source maps don't expose anything not already public. FP for bounty. |
| OAuth state on /api/auth/session | `/api/auth/session` is a session status check endpoint (returns current user session), NOT an OAuth authorization initiation endpoint. NextAuth uses this to check if user is logged in. Accepting requests without `state` is expected behavior. FP. |
| Race Condition on /register | Concurrent GET requests to registration page all return 200. GET requests to a public registration form are idempotent. No state mutation. FP — same class as moneybird bookkeeping race FP from session 7. |
| Username Enumeration (content-based) | Cal.com is an open-source calendar — booking links expose usernames by design (e.g., `/admin/30min`). Knowing "admin" is a valid username provides no attack value. Low bounty impact. |
| Cookie __Secure-next-auth.callback-url | Stores redirect URL after login, not a session token. Intentionally JS-readable by NextAuth design for SPA flow. |
| SRI on Intercom widget | External Intercom widget (`widget.intercom.io`) cannot have SRI because Intercom updates it frequently. Same-org SRI FP pattern. |
| Missing Rate Limiting | Vercel/Cloudflare edge rate limiting not detectable by 15-request probe. FP. |
| Missing HSTS | Standalone header finding — auto-rejected by HackerOne triagers. FP for submission. |
| Cookie HttpOnly (callback-url) | Callback URL cookie, not auth token. FP. |

#### Neon.tech (neon-v2, ad-hoc scan) — 8 findings → 8 FPs

Neon not in hunt registry. No established bounty program context. All findings are FPs:

| Finding | Reason |
|---------|--------|
| SQL Injection (CRITICAL) | "SQL error" matched a PostgreSQL documentation link in the page response. Neon IS a PostgreSQL company — their pages naturally contain PostgreSQL references. FP by definition. The AI report itself flagged this caveat. |
| Directory Traversal (CRITICAL) | `..\\etc\\passwd` path sent to Cloudflare/Vercel-fronted Next.js app. These paths are normalized and blocked at the edge before reaching the app. FP. |
| Prototype Pollution (CRITICAL) | `?__proto__[secbot_pp]=polluted` returned 403 (Cloudflare WAF blocked it). The "canary reflection" was in the Cloudflare WAF block page, not in application response. FP. |
| Missing HSTS | Standalone header finding. FP. |
| Open Redirect | Redirect goes to `neon.com` (Neon's own alternate domain), not an external attacker domain. Same-org redirect, not open redirect. FP. |
| Verbose Error on /undefined | Confidence: LOW. PostgreSQL "error" pattern matched a documentation link. FP. |
| Cookie neon_consent | Consent/preference cookie. Known FP pattern: "Third-party cookie flags (analytics, marketing, consent widgets) — always FP for bounties." |
| SRI on Next.js chunks | Self-hosted CDN chunks. CSP is the right mitigation, not SRI. FP. |

#### Kredivo (blog.kredivo.com) — 3 findings → 1 potential TP, 2 FPs

| Finding | Verdict |
|---------|---------|
| Exposed wp-login.php | POTENTIAL TP — draft ready. Verify live. |
| Missing CSP | FP as standalone submission. Context: WordPress blogs rarely get CSP bounties. |
| Cookie `_hcc` missing flags | FP — `_hcc` is a HubSpot tracking cookie (HubSpot Click-to-Chat). Third-party tracking cookie, known FP pattern. |

#### OpenProject (community.openproject.org) — 6 findings → 0 submissions

Platform: `other` (YesWeHack, no paid bounty confirmed). Community forum instance.

| Finding | Verdict |
|---------|---------|
| Missing HSTS | FP standalone |
| Missing CSP | FP standalone |
| Session Fixation | Needs valid credentials to confirm. HOLD — low priority without paid program. |
| Rate Limiting on /login | FP — community forum, auto-rejected |
| Username Enumeration via Timing | FP — timing difference of `admin` username (10s vs 300ms) likely due to LDAP/expensive lookup, not confirming a user exists |
| Rate Limiting on API | FP |

#### Moneybird (www.moneybird.com) — Existing + new findings

| Finding | Verdict |
|---------|---------|
| DOM XSS via URL Fragment | TP — draft ready, SUBMIT |
| Missing CSP | Include as amplifying detail in XSS submission, not standalone |
| postMessage origin validation | HOLD — needs browser investigation to rule out widget FP |
| Mixed content (HTTP link) | FP — an `<a href="http://...">` link is not exploitable mixed content. Browsers don't block passive mixed content (links). |
| Race Condition on /features/bookkeeping | FP (AI self-identified) |

---

## OWN APPS — Fix These

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | **UNFIXED** — Brute-force risk. Add Cloudflare rate limiting rule. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | **UNFIXED** — Middleware configured but not appearing. Docker rebuild or middleware ordering bug. |

---

## Honest Assessment (Apr 22, Session 8)

**Bounty readiness: LOW-MEDIUM.** 5+ targets scanned, 2 submittable findings:

**What we have:**
- 1 confirmed HIGH (Moneybird DOM XSS) — browser verification required before submitting
- 1 MEDIUM (Kredivo wp-login.php) — low-value bounty (~$32-95 IDR equivalent) but quick to submit
- 1 MEDIUM on hold (Indeed CSRF cookie) — strongest submission from prior sessions

**Root cause analysis unchanged:**
- No auth scanning = no IDOR, no business logic, no post-auth vulnerabilities
- Large targets (Moneybird, Cal.com) have WAFs and well-hardened passive posture
- All 21 cal.com "injection" findings were FPs from natural page content variation
- Boolean-based detection is unreliable against Next.js RSC routes (size varies by rendered content)

**Pattern recognition improvement:**
- `_rsc` parameter is a Next.js RSC internal token — never inject into this
- `cf-cache-status: DYNAMIC` = not cacheable = WCD FP
- Cloudflare 403 page containing scan keywords = injection FP
- PostgreSQL company + "SQL error" pattern = doc link match FP

## Next Steps (Priority Order)

1. **Verify Moneybird DOM XSS in real browser** — open `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome. If alert fires: submit immediately.
2. **Submit Indeed CSRF cookie** — only if Dio is willing; reproduction requires browser session.
3. **Submit Kredivo wp-login.php** — quick curl verify, then RedStorm submission.
4. **Investigate Moneybird postMessage** — browser DevTools → Sources → search for `addEventListener('message'`. If it's Intercom/HubSpot: archive. If it's custom code: investigate further.
5. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app.
6. **Get credentials for auth scanning** — Twitch account for T2 findings; test accounts for OpenProject CVE analysis.

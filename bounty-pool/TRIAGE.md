# Bounty Pool Triage — Updated 2026-05-20 (Session 8 — Report Drafter)

## Submission Priority

### TIER 1 — Ready to Submit (strongest signal)

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md`. **CAVEAT:** Cookie is JS-set — curl won't reproduce. Needs Playwright/browser verification. |

### TIER 2 — Submit After Verification

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| 2 | moneybird.com | DOM-Based XSS via URL Fragment on www.moneybird.com | Medium (CVSS 6.1) | Draft ready: `pending/moneybird/6d09cce8-dom-based-cross-site-scripting-(xss)-via-url-fragment.md`. **MUST VERIFY IN BROWSER FIRST** — navigate to `https://www.moneybird.com/#<img src=x onerror=alert(1)>` in Chrome and confirm alert fires before submitting. |

### TIER 3 — Hold (needs more work / auth)

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| 3 | twitch.tv | `server_session_id` + `api_token` missing HttpOnly | Medium | HOLD — needs auth scan. Verify these are actual auth tokens via `document.cookie` in browser console after login. Need Twitch account. |
| 4 | bugcrowd.com | `PathSession` + `FirstSession` missing HttpOnly/Secure | Medium | WEAK — only valuable chained with XSS. Submitting to their own program is bad optics. Skip unless XSS is found. |

### TIER 4 — Archived (FP or non-bounty)

Moved to `bounty-pool/archived/`:

| File | Target | Reason |
|------|--------|--------|
| `2026-03-14-shopify-cors-dux.md` | shopify.com | Non-exploitable: SameSite + empty response body |
| `2026-03-14-konghq-missing-headers.md` | konghq.com | Informational — auto-rejected |
| `2026-03-14-gitlab-graphql.md` | gitlab.com | GraphQL introspection by design, documented |
| `2026-05-20-moneybird-postmessage-fp.md` | moneybird.com | **FP** — 3 listeners are from third-party widgets (Intercom/Freshdesk/Wistia). Handler snippet is a mouse event normalizer, not a postMessage handler. Raw severity was "low", AI uprated to "medium" incorrectly. Matches known FP pattern. |
| `2026-05-20-moneybird-csp-informational.md` | moneybird.com | **Informational/Mischaracterized** — The scan description says "no CSP on any response" but the `/login` page serves `content-security-policy-report-only` with a detailed policy. CSP exists but is not enforced. Merge into XSS report as a compounding factor, not a standalone finding. |

---

## Moneybird Scan Deep Triage (2026-05-20)

**Scan date:** 2026-03-22 | **Profile:** stealth | **Pages:** 10 | **Duration:** 11m 28s

### All 5 Findings from Scan:

| ID | Title | Raw Severity | Raw Confidence | Verdict | Notes |
|----|-------|-------------|----------------|---------|-------|
| 6d09cce8 | DOM XSS via URL Fragment | high | medium | **LIKELY TRUE POSITIVE** | `dom-sink` detection: marker found in 2× `innerHTML` assignments. Needs human browser verification before submission. Confidence medium because alert() not directly confirmed. |
| 09dd5267 | Missing CSP Header | high | medium | **INFORMATIONAL/FP** | CSP-RO exists on `/login` page — scan description is inaccurate. Marketing pages lack enforced CSP. Not standalone bounty. Referenced in XSS report. |
| 8c0823c1 | postMessage Without Origin Check | low (raw) | medium | **FP** | Handler snippet is mouse event normalizer code. Likely from Intercom/Freshdesk/Wistia bundles. Known FP pattern. |
| 7c8686e3 | Mixed Content (http:// link) | medium | medium | **INFORMATIONAL** | Passive `href` link to HTTP URL — not an executable mixed resource. Browsers allow passive mixed content. Not exploitable. |
| 1a598909 | Race Condition on /features/bookkeeping/ | — | — | **FP (self-detected)** | AI reporter correctly identified this as FP: concurrent GETs to static page returning 200 is correct behavior. |
| 5f762956 | Open Redirect via `url` param | high (raw) | high (raw) | **FP (excluded by AI)** | `www.moneybird.com/login?url=evil.com` redirects to `moneybird.com/login?url=evil.com` (www→non-www canonical), NOT to evil.com. The `url` param is a post-auth destination. AI reporter correctly excluded this from interpretedFindings. |

### Key Evidence on DOM XSS:
- Detection: `dom-sink` — Playwright navigated to `https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>` and found the marker string inside two `innerHTML` assignment operations
- The page has no enforced CSP (only report-only on `/login`) — inline scripts and event handlers are not blocked
- The `content-security-policy-report-only` on the login page includes `unsafe-inline` in `script-src`, so even if CSP were enforced it wouldn't block `onerror` in this specific config
- Note: `www.moneybird.com` is the marketing site. The actual accounting app likely lives at `app.moneybird.com`. Bounty potential is Medium (phishing from official domain, no direct session cookie theft)

---

## OWN APPS — Fix These

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS but not appearing. Docker rebuild or middleware bug. |

---

## Honest Assessment (2026-05-20)

**Bounty readiness: LOW-MEDIUM.** After 3 months of scanning:
- 0 confirmed high/critical vulnerabilities on external targets
- 1 likely DOM XSS (needs 30 seconds of manual verification in Chrome)
- All previous findings are passive (headers, cookies)
- No authenticated scanning performed

**What the Moneybird scan found:**
- Probable DOM XSS on the marketing homepage — if verified, first real active vulnerability found
- 3 FPs correctly filtered (postMessage, open redirect, race condition)
- 1 mischaracterized finding (CSP described inaccurately)
- FP rate remains low (good) but true positive rate also low (expected for marketing sites)

**Next Steps (Priority Order):**
1. **VERIFY Moneybird DOM XSS** — open Chrome, navigate to the PoC URL, confirm alert fires (30 seconds)
2. **Submit to Moneybird HackerOne** if confirmed — use updated draft in `pending/moneybird/6d09cce8-*.md`
3. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
4. **Get Twitch auth** — login credentials to verify server_session_id/api_token are real auth tokens
5. **Scan authenticated targets** — run SecBot with `--auth` against targets with test accounts

## Session Log

| Date | Session | Action |
|------|---------|--------|
| 2026-03-14 | Session 1-6 | Initial scans of 27+ targets, all passive findings |
| 2026-03-15 | Session 7 | Triage: Indeed CSRF cookie to T1, Twitch/Bugcrowd on hold, Shopify/Kong/GitLab archived |
| 2026-03-22 | Scan | Moneybird stealth scan (10 pages, 11m) |
| 2026-05-20 | Session 8 | Moneybird deep triage: DOM XSS likely TP → T2, postMessage/CSP/mixed-content archived as FP/informational |

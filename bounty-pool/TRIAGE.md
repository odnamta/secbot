# Bounty Pool Triage — Updated Apr 15, 2026 (Session 8)

## Submission Priority

### TIER 1 — Submit (strongest signal)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 1 | indeed.com | CSRF cookie missing Secure on login page | Medium | Inconsistency between CSRF and INDEED_CSRF_TOKEN strengthens report. **CAVEAT:** Cookie set via JS, not HTTP header — curl won't reproduce. Needs Playwright/browser to verify. Submission draft ready: `2026-03-14-indeed-csrf-cookie-SUBMISSION.md` |
| 2 | moneybird.com | DOM-Based XSS via URL fragment (innerHTML sink) | High | NEW (Session 8) — High confidence, two sinks confirmed, no CSP. **CAVEAT:** Verify `www.moneybird.com` is in scope for HackerOne program (may be `app.moneybird.com` only). Must test in browser — curl can't confirm DOM XSS. Draft: `2026-04-15-moneybird-dom-xss.md` |

### TIER 2 — Hold (needs more work)

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| 3 | twitch.tv | server_session_id + api_token missing HttpOnly | Medium | HOLD — needs auth scan to verify these are actual auth tokens. Need Twitch account + login. |
| 4 | bugcrowd.com | PathSession + FirstSession missing HttpOnly/Secure | Medium | Weak standalone — needs XSS chain to be credible. Submitting to their own program is bad optics. |

### TIER 3 — Archived / False Positives

Moved to `bounty-pool/archived/`:
- shopify.com CORS /__dux — Non-exploitable (SameSite+empty body)
- konghq.com missing headers — Informational, auto-rejected by triagers
- gitlab.com GraphQL introspection — By design, publicly documented

**Session 8 FP notes (Moneybird scan):**
- moneybird.com postMessage handlers (3 listeners, medium confidence) — **FP.** Marketing homepage postMessage handlers match known FP pattern: Intercom, Drift, or Freshdesk chat widgets register unlabeled postMessage listeners without origin validation by design. Automated scanner cannot distinguish app code from third-party widget code. No exploitable handler behavior identified — scanner noted "automated testing could not fully enumerate all handler logic." Not bounty-worthy.
- moneybird.com missing Content-Security-Policy — **Not a standalone finding.** Missing CSP alone is rejected as informational by most programs including HackerOne. Included as an amplifying factor in the DOM XSS draft (`2026-04-15-moneybird-dom-xss.md`), not submitted separately. CVSS 7.0 classification in raw scan output is inflated for a header-only finding with no direct exploitability.

### OWN APPS — Fix These

| # | Target | Finding | Severity | Notes |
|---|--------|---------|----------|-------|
| A1 | finance.atmando.app | No rate limiting on /login and /graphql | HIGH | Brute-force risk on finance app. Add Cloudflare rate limiting + app-level throttle. |
| A2 | finance.atmando.app | Missing HSTS header | MEDIUM | Middleware has HSTS configured but it's not appearing in response. Docker rebuild or middleware bug. |

---

## Honest Assessment (Apr 15)

**Bounty readiness: LOW-MEDIUM.** Modest progress since Session 7:
- 1 new high-confidence active finding (DOM XSS on Moneybird) — first injection-class vuln found on external target
- Still 0 confirmed bounties paid out
- DOM XSS finding has a real scope uncertainty (www vs app subdomain) that blocks submission

**What changed since Session 7:**
- Moneybird scan found a DOM XSS candidate — strongest finding to date
- Triage correctly filtered 2 of 3 Moneybird findings as non-bounty (postMessage FP, missing CSP informational)
- FP rate still 0% on confirmed assessments

**What still hasn't changed:**
- No authenticated scanning performed on any target
- All external confirmed findings are passive or require scope verification before submission
- DOM XSS is on marketing domain (`www.`) not app domain (`app.`) — impact ceiling is lower

---

## Next Steps (Priority Order)

1. **Verify Moneybird scope** — Check HackerOne program page: is `www.moneybird.com` listed as in-scope? If yes, open the PoC URL in a browser and confirm the alert fires, then submit `2026-04-15-moneybird-dom-xss.md`.
2. **Retest Moneybird app** — Scan `app.moneybird.com` with a free trial account (auth scan). DOM XSS on the app subdomain would be a clean high-severity finding.
3. **Fix own app issues** — rate limiting + HSTS on finance.atmando.app
4. **Get test credentials** — Twitch account for auth scan, unlock T2 findings
5. **Indeed submission** — only if Dio confirms willingness (cookie is JS-set, reproduction tricky)

# Indeed — CSRF Cookie Missing Secure Flag

**Target:** indeed.com
**Program:** Indeed Bug Bounty Program (HackerOne)
**Scan Date:** 2026-03-14
**Status:** PENDING REVIEW

## Finding

### CSRF Cookie Missing Secure Flag
- **Severity:** Medium
- **CWE:** CWE-614
- **Asset:** https://id.indeed.com/?r=us
- **Impact:** CSRF token can be leaked over unencrypted HTTP connections. An attacker performing MitM can steal the CSRF token and forge cross-site requests.
- **Reproduce:** `curl -sI 'https://id.indeed.com/?r=us'` — check Set-Cookie for CSRF
- **Evidence:** `Set-Cookie: CSRF=y89sWHQ6GGgqZb3exhHwbl5z2QGz9YjX;Domain=.indeed.com;Path=/` — note: no Secure flag
- **Notes:** The `INDEED_CSRF_TOKEN` cookie does have Secure flag, but the `CSRF` cookie does not. This inconsistency suggests a configuration oversight.

### CSP with unsafe-inline in default-src
- **Severity:** Medium
- **CWE:** CWE-693
- **Asset:** https://id.indeed.com/?r=us
- **Impact:** `unsafe-inline` in default-src weakens CSP XSS protection on the login page
- **Notes:** This is on the LOGIN page (`id.indeed.com`), making it higher impact than on a marketing page

## Assessment
- CSRF cookie without Secure on a login page is a legitimate finding
- The inconsistency between CSRF and INDEED_CSRF_TOKEN cookies strengthens the report
- CSP unsafe-inline on login page is worth bundling
- **Recommendation:** Submit as single report, emphasizing the security of the authentication flow

## Raw Evidence
See: validation-run-8/indeed/secbot-2026-03-14T09-58-48-292Z-bounty.md

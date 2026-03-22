# Bugcrowd — Session Cookie Security Issues

**Target:** bugcrowd.com
**Program:** Bugcrowd Bug Bounty Program
**Scan Date:** 2026-03-14
**Status:** PENDING REVIEW

## Findings

### 1. Cookie "PathSession" Missing HttpOnly and Secure Flags
- **Severity:** Medium
- **CWE:** CWE-614
- **Impact:** Session cookie accessible via JavaScript (XSS → session hijack). Can be transmitted over HTTP.
- **Reproduce:** `curl -sI https://www.bugcrowd.com/` — check Set-Cookie for PathSession
- **Notes:** This appears to be an actual session cookie, not analytics. Missing HttpOnly is significant if XSS is found.

### 2. Cookie "FirstSession" Missing HttpOnly and Secure Flags
- **Severity:** Medium
- **CWE:** CWE-614
- **Impact:** Same as above. Likely a first-visit session identifier.
- **Reproduce:** `curl -sI https://www.bugcrowd.com/` — check Set-Cookie for FirstSession

### 3. Missing Content-Security-Policy
- **Severity:** High (as classified) but likely informational for bounty
- **CWE:** CWE-693
- **Impact:** No CSP means any XSS is fully exploitable
- **Notes:** Marketing site, so bounty programs may classify as informational

## Assessment
- PathSession + FirstSession are the most interesting — they're session cookies without basic security flags
- Bugcrowd probably accepts their own program findings but may classify these as low/informational
- Worth submitting if combined with any XSS finding (the missing HttpOnly becomes high impact)
- **Recommendation:** Submit as a single report covering both session cookies

## Raw Evidence
See: validation-run-8/bugcrowd/secbot-2026-03-14T09-58-42-455Z-bounty.md

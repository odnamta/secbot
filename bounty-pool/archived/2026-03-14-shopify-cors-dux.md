# Shopify — CORS on /__dux Endpoint

**Target:** shopify.com
**Program:** Shopify Bug Bounty (HackerOne)
**Scan Date:** 2026-03-14
**Status:** NOT BOUNTY-WORTHY — SameSite mitigates

## Finding

### CORS Reflects Origin with Credentials on /__dux
- **Severity:** Medium (downgraded from Critical)
- **CWE:** CWE-942
- **Asset:** https://www.shopify.com/__dux
- **Evidence:** POST with evil Origin → reflected + `Access-Control-Allow-Credentials: true`

### Why NOT Bounty-Worthy

1. **SameSite=Lax on all cookies** — All `_shopify_*` cookies use `SameSite=Lax`. Browsers won't attach cookies on cross-origin fetch/XHR POST requests, making the CORS misconfiguration non-exploitable.

2. **Empty response body** — POST to `/__dux` returns `200` with `content-length: 0`. Even if cookies were sent, there's no data to steal.

3. **GET returns 405** — Only POST is accepted, and it returns nothing useful.

### Verification

```bash
# POST with evil origin — CORS headers reflected but response is empty
curl -s -i -X POST \
  -H "Origin: https://evil.example.com" \
  -H "Content-Type: application/json" \
  -d '{"test":"data"}' \
  "https://www.shopify.com/__dux"

# All cookies have SameSite=Lax:
# set-cookie: _shopify_essential_=...; Domain=.shopify.com; Path=/; Secure; SameSite=Lax
# set-cookie: _shopify_y=...; Domain=.shopify.com; Path=/; Secure; SameSite=Lax
# set-cookie: _shopify_s=...; Domain=.shopify.com; Path=/; Secure; SameSite=Lax
```

### Verdict: SKIP — no real impact due to SameSite defense-in-depth + empty response

## Other Shopify Findings (all informational)
- Missing CSP on /id (Indonesia locale page) — not bounty-worthy
- mto_pvs cookie missing HttpOnly/Secure — Marketo tracking cookie, not session
- SRI on cdn.shopify.com — same-org CDN, not third-party

## Raw Evidence
See: validation-run-6/shopify/secbot-2026-03-14T02-28-12-356Z-bounty.md

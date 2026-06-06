# Open Redirect on Login Endpoint via Multiple Parameters

**Target:** https://neon.tech  
**Platform:** Unknown (not in hunt registry — check HackerOne/Bugcrowd first)  
**Program:** Neon  
**Severity:** Medium | **CVSS:** 6.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`  
**CWE:** CWE-601 (URL Redirection to Untrusted Site)  
**OWASP:** A01:2021 – Broken Access Control  
**Confidence:** Medium | **Detection:** location-header  
**Scan date:** 2026-03-26

> **⚠️ Verifier note (Dio):** Neon.tech is NOT currently in the hunt registry. Before submitting: (1) verify they have a public bounty program, (2) manually test the redirect — the scanner noted the redirect may go to `neon.com/login?param=...` rather than directly to the attacker domain. Only submit if you observe a redirect to the supplied `evil.example.com` URL or can chain it to a full phishing redirect.

---

## Summary

The `/login` endpoint on `neon.tech` accepts redirect destination via at least 7 different query parameters (`url`, `redirect`, `next`, `return`, `returnTo`, `redirect_uri`, `goto`, `dest`) and reflects them in the `Location` response header without validating that the destination is within the `neon.tech` domain. This allows an attacker to craft a phishing URL that appears legitimate (starts with `https://neon.tech/`) but redirects users to an attacker-controlled domain after login.

The `redirect_uri` parameter is particularly dangerous if used in an OAuth context — it could redirect OAuth authorization codes to attacker infrastructure.

---

## Steps to Reproduce

```bash
# 1. Test basic open redirect via 'next' parameter
curl -sI 'https://neon.tech/login?next=https://evil.example.com' | grep -i location
# Expected if vulnerable: Location: https://evil.example.com
# Redirect to neon.com/login still warrants investigation

# 2. Test 'url' parameter
curl -sI 'https://neon.tech/login?url=https://attacker.com' | grep -i location

# 3. Test redirect_uri (highest severity — OAuth implication)
curl -sI 'https://neon.tech/login?redirect_uri=https://attacker.com/callback' | grep -i location

# 4. Test with URL encoding bypass
curl -sI 'https://neon.tech/login?next=https%3A%2F%2Fattacker.com' | grep -i location

# 5. Test double encoding
curl -sI 'https://neon.tech/login?next=https%253A%252F%252Fattacker.com' | grep -i location
```

**Manual verification (browser):**  
Navigate to `https://neon.tech/login?next=https://evil.example.com`. After login (or immediately if the endpoint redirects pre-auth), observe if the browser lands on `evil.example.com`.

---

## Impact

1. **Phishing:** An attacker sends `https://neon.tech/login?next=https://attacker-phishing-page.com` — the URL passes email spam filters and human inspection (legitimate Neon domain). After login, the user is silently redirected to a credential-harvesting page.

2. **OAuth code theft (if `redirect_uri` is unvalidated):** If neon.tech uses OAuth and `redirect_uri` is passed through to an external authorization server without validation, an attacker can redirect OAuth authorization codes to their own server, enabling account takeover.

3. **Session token leakage:** If the redirect carries session information in the URL (e.g., `?token=`), those tokens leak to the attacker's server via Referer or direct parameter.

---

## Evidence

Scanner detected `Location` header reflection for the following parameter names across multiple test requests:
- `url`, `redirect`, `next`, `return`, `returnTo`, `redirect_uri`, `goto`, `dest`

Affected URLs tested:
- `https://neon.tech/login?url=https://evil.example.com`
- `https://neon.tech/login?redirect=https://evil.example.com`
- `https://neon.tech/login?next=https://evil.example.com`
- (and 5 additional parameter variants)

```bash
curl -L -i 'https://neon.tech/login?url=https%3A%2F%2Fevil.example.com'
```

---

## Suggested Fix

```typescript
// middleware.ts or login handler — validate redirect against allowlist
function getSafeRedirectUrl(redirectParam: string | undefined): string {
  const DEFAULT = '/dashboard';
  if (!redirectParam) return DEFAULT;

  try {
    // Reject any absolute URL not on our domain
    if (redirectParam.startsWith('//') || redirectParam.includes('://')) {
      const url = new URL(redirectParam);
      const allowed = ['neon.tech', 'neon.com', 'console.neon.tech'];
      if (!allowed.includes(url.hostname)) return DEFAULT;
    }
    // Accept relative paths
    if (redirectParam.startsWith('/') && !redirectParam.startsWith('//')) {
      return redirectParam;
    }
  } catch { /* malformed URL */ }

  return DEFAULT;
}
```

---

## Notes for Verifier (Dio)

- **Action required before submission:** Check if neon.tech has a HackerOne/Bugcrowd program
- **Manual test required:** Confirm redirect actually goes to the supplied URL, not just `neon.com`
- If `redirect_uri` is the confirmed vulnerable param (OAuth context), escalate to HIGH severity
- If redirect stays within `*.neon.com` family, this is likely not exploitable — mark FP

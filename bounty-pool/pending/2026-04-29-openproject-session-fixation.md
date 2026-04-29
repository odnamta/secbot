# Session Fixation — Session Cookie Not Regenerated After Login

**Severity:** Medium | **CVSS:** 6.9 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
**Platform:** YesWeHack | **Program:** OpenProject
**Confidence:** Medium | **CWE:** CWE-384 (Session Fixation)
**OWASP:** A07:2021 - Identification and Authentication Failures
**Scan Date:** 2026-03-26

## Title

Session Fixation: `_open_project_session` Cookie Not Regenerated After Authentication on community.openproject.org

## Summary

The `_open_project_session` cookie retains the same value before and after login on `community.openproject.org`. An attacker who can pre-set a known session ID in a victim's browser can hijack the authenticated session once the victim logs in — without needing to steal any credentials.

## Steps to Reproduce

**1. Capture a pre-authentication session ID:**
```bash
# Step 1: Get the login page to receive a pre-auth session cookie
curl -c /tmp/cookies.txt -sI 'https://community.openproject.org/login' \
  | grep -i set-cookie
# Note the _open_project_session value
```

**2. Submit the login form while carrying the pre-existing session cookie:**
```bash
# Step 2: Get CSRF token first
CSRF_TOKEN=$(curl -c /tmp/cookies.txt -b /tmp/cookies.txt -s \
  'https://community.openproject.org/login' \
  | grep -oP 'name="authenticity_token" value="\K[^"]+' | head -1)

# Step 3: Log in carrying the pre-auth session ID
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST 'https://community.openproject.org/login?layout=1' \
  -D - \
  -d "username=<YOUR_USERNAME>&password=<YOUR_PASSWORD>&authenticity_token=${CSRF_TOKEN}" \
  | grep -i 'set-cookie'
```

**3. Compare the `_open_project_session` value before (Step 1) and after (Step 3):**
- If the value is **unchanged**, session fixation is confirmed
- A correctly implemented system would issue a new session ID with each authentication

**4. Validate the pre-login session ID is accepted post-login:**
```bash
# Use the original (pre-login) session value to access an authenticated endpoint
curl -b '_open_project_session=<PRE_LOGIN_VALUE>' \
  'https://community.openproject.org/users' -I
# If HTTP 200 is returned (instead of redirect to login), session fixation is exploitable
```

## Attack Scenario

1. Attacker pre-sets a known session ID in the victim's browser via any means:
   - Subdomain XSS (setting a cookie for `.openproject.org`)
   - Network-level attack (SSL-strip + cookie injection on HTTP)
   - Shared device/browser session
2. Victim navigates to community.openproject.org and logs in
3. Attacker immediately uses the pre-known session ID to access the victim's authenticated session
4. Attacker gains full access to the victim's OpenProject community account

## Impact

- Complete session hijacking without credential theft
- Access to private messages, project discussions, and any privileged actions the victim can perform
- For admin/moderator accounts: ability to moderate, delete, or alter community content

## Suggested Fix

In Rails, call `reset_session` (or use Devise's `sign_in` which handles this automatically) immediately before establishing the authenticated session:

```ruby
# SessionsController
def create
  user = User.find_by(login: params[:username])
  if user&.authenticate(params[:password])
    reset_session  # ← Issue new session ID before setting auth state
    session[:user_id] = user.id
    redirect_to root_path
  else
    render :new
  end
end
```

## Notes for Triager

This finding was detected via automated session ID comparison (endpoint-replay method). Manual confirmation by comparing the `_open_project_session` cookie value before and after a real login is recommended before assigning bounty. The CVSS assumes network-level preconditions to plant the session — adjust if your threat model differs.

## References

- CWE-384: Session Fixation — https://cwe.mitre.org/data/definitions/384.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Rails `reset_session`: https://api.rubyonrails.org/classes/ActionController/Metal.html#method-i-reset_session

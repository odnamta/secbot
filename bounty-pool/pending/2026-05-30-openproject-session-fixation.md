# Session Fixation — Session Cookie Not Regenerated After Login (CWE-384)

**Severity:** Medium | **CVSS:** 6.9 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
**Platform:** YesWeHack | **Program:** OpenProject
**Confidence:** Medium | **CWE:** CWE-384 (Session Fixation)
**OWASP:** A07:2021 - Identification and Authentication Failures

> ⚠️ **Verification Required Before Submitting:** The automated scan detected that `_open_project_session` retains the same value before and after login. Manual browser verification is needed to confirm the cookie value is genuinely unchanged (not just that the response doesn't re-send the Set-Cookie header). Open browser DevTools, record pre-login cookie value, authenticate, and confirm post-login cookie value is identical.

## Summary

The session cookie `_open_project_session` is not regenerated upon successful authentication at `https://community.openproject.org`. If an attacker can set a victim's session cookie to a known value before login (via XSS, network interception, or a shared device), they can hijack the session immediately after the victim authenticates — without needing to know the victim's password.

## Steps to Reproduce

**1. Capture the pre-login session cookie:**
```bash
curl -c /tmp/cookies.txt -s -o /dev/null \
  'https://community.openproject.org/login?layout=1'
grep '_open_project_session' /tmp/cookies.txt
# Record the session value: PRE_LOGIN_SESSION=<value_A>
```

**2. Authenticate with valid credentials:**
```bash
curl -b /tmp/cookies.txt -c /tmp/cookies_post.txt \
  -X POST \
  -d 'utf8=%E2%9C%93&authenticity_token=TOKEN&username=USER&password=PASS&login=Login' \
  -L -i \
  'https://community.openproject.org/login?layout=1'
```

**3. Compare session cookie values:**
```bash
grep '_open_project_session' /tmp/cookies_post.txt
# Confirm the value matches <value_A> (unchanged from pre-login)
```

**Expected behavior:** A new session ID is issued on login.
**Observed behavior:** The same `_open_project_session` value is valid before and after authentication.

**4. Demonstrate exploitability (manual verification):**
1. Open two browser windows (Window A = victim, Window B = attacker)
2. In Window B: visit `https://community.openproject.org/` and note session cookie value
3. In Window A: inject Window B's session cookie (via DevTools → Application → Cookies), then log in normally
4. Confirm Window B is now authenticated as the victim without knowing their credentials

## Impact

An attacker who can pre-plant a known session ID can:
1. **Account takeover:** After the victim logs in, the attacker's known session is now authenticated — full access to the victim's OpenProject account, projects, and data.
2. **Privilege escalation:** If the victim is an administrator or project manager, the attacker gains admin-level access.
3. **Persistence:** The attacker can remain authenticated even after the victim logs out, depending on session invalidation logic.

**Pre-conditions for exploitation:**
- Attacker must be able to set the victim's session cookie — possible via subdomain XSS, a shared/public device, or network-level interception (especially relevant without HSTS).
- The missing HSTS finding on the same host amplifies the risk (HTTP downgrade → cookie interception).

## Root Cause

Rails applications must call `reset_session` (or equivalent) immediately upon successful authentication to invalidate the pre-auth session and issue a new one. If Devise or a custom session controller assigns `session[:user_id]` without first calling `reset_session`, the session ID is reused.

## Suggested Fix

```ruby
# Rails SessionsController
def create
  user = User.find_by(login: params[:username])
  if user&.authenticate(params[:password])
    reset_session  # MUST be called BEFORE writing to session
    session[:user_id] = user.id
    redirect_to root_path
  else
    render :new
  end
end

# If using Devise:
# Devise handles this via sign_in() — ensure you're not bypassing
# it with manual session[:user_id] assignment elsewhere.
```

## References

- CWE-384: Session Fixation — https://cwe.mitre.org/data/definitions/384.html
- OWASP Session Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Rails Security Guide — https://guides.rubyonrails.org/security.html#session-fixation

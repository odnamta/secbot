# YesWeHack Submission Draft — OpenProject

**Program:** OpenProject (YesWeHack)
**Asset:** community.openproject.org
**Weakness:** CWE-384: Session Fixation
**OWASP:** A07:2021 — Identification and Authentication Failures
**Severity:** Medium
**CVSS 3.1:** 6.3 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`

---

## Title

Session Fixation — `_open_project_session` Cookie Not Regenerated After Login

## Summary

The `_open_project_session` cookie on `community.openproject.org` retains its pre-authentication value after a successful login. This is a textbook session fixation vulnerability (CWE-384): an attacker who can plant a known session ID in the victim's browser can wait for the victim to authenticate and then use the pre-known session ID to access the victim's authenticated session.

## Steps to Reproduce

### Manual verification

1. Visit `https://community.openproject.org/login` and capture the initial session cookie:

```bash
curl -c /tmp/session_before.txt -sI 'https://community.openproject.org/login?layout=1' \
  | grep -i set-cookie
```

Note the value of `_open_project_session`.

2. Submit the login form with valid credentials:

```bash
# Extract the CSRF token first
CSRF_TOKEN=$(curl -s 'https://community.openproject.org/login?layout=1' \
  | grep -oP 'authenticity_token[^>]+value="\K[^"]+')

curl -c /tmp/session_after.txt -b /tmp/session_before.txt \
  -X POST 'https://community.openproject.org/login?layout=1' \
  -d "authenticity_token=${CSRF_TOKEN}&username=YOUR_USER&password=YOUR_PASS" \
  -sI | grep -i set-cookie
```

3. Compare the `_open_project_session` value in `/tmp/session_before.txt` and the post-login `Set-Cookie` header.

**Expected (secure):** A new session ID is issued on login — the pre-login session ID is invalidated.

**Actual (vulnerable):** The same session ID persists across the authentication boundary.

### Exploitation scenario (no valid credentials needed by attacker)

1. Attacker visits `https://community.openproject.org/login` — receives session cookie `SESSION_A`.
2. Attacker tricks victim (via XSS, network injection on HTTP page, or shared device) into accepting `SESSION_A` as their own session cookie.
3. Victim logs in normally with their credentials.
4. Since the session ID was not regenerated, `SESSION_A` is now an authenticated session.
5. Attacker uses `SESSION_A` to access the victim's account.

**Note:** The planted session must reach the victim's browser before they log in. This requires one of: XSS on the domain, network-level attack on an HTTP page that sets the cookie, or a shared/public device.

## Impact

If an attacker can plant the session ID (via any means), they gain full authenticated access to the victim's account after the victim logs in — without needing to know the victim's credentials. On a community/project management platform this means:
- Read all projects, work packages, and confidential discussions the victim has access to
- Perform actions as the victim (create/modify/delete work packages, send messages)
- Escalate to admin privileges if victim is an admin

## Suggested Fix

Call `reset_session` (in Rails) immediately after successful authentication:

```ruby
# In SessionsController or equivalent, after authentication succeeds:
def create
  user = authenticate(params[:username], params[:password])
  if user
    reset_session           # ← Invalidates old session ID, issues new one
    session[:user_id] = user.id
    redirect_to root_path
  else
    flash[:error] = 'Invalid credentials'
    render :new
  end
end
```

This is a one-line fix. Rails' `reset_session` preserves flash messages while issuing a new session ID, so there are no functional side effects.

## Scanner Evidence

- Endpoint tested: `https://community.openproject.org/login?layout=1`
- Detection method: `endpoint-replay` — session cookie value captured before and after login submission
- Cookie observed: `_open_project_session` (identical pre/post authentication)
- Scanner timestamp: 2026-03-26

---

> **Drafting note for Dio:** This needs manual verification with a real OpenProject community account before submitting. The scanner detected the cookie not changing on the POST request, but:
> 1. Create a free account at community.openproject.org
> 2. Use curl or browser DevTools to capture session cookie before and after login
> 3. Confirm the session value is unchanged
>
> **IMPORTANT — check scope first:** Verify that `community.openproject.org` is in scope for YesWeHack's OpenProject program. Some programs only cover their paid SaaS (`openproject.com`), not their community forum. If community.openproject.org is out of scope, skip this submission.
>
> If in scope and confirmed: this is a clean, reproducible, high-signal finding. Session fixation on a login endpoint with clear PoC steps is a strong Medium submission.

*Discovered by SecBot automated scanner on 2026-03-26.*

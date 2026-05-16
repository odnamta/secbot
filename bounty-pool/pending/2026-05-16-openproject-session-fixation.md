# Session Fixation — Session Cookie Not Regenerated After Login

**Program:** OpenProject (YesWeHack)
**Target:** `community.openproject.org`
**Severity:** Medium
**CVSS 3.1:** 6.9 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**CWE:** CWE-384 (Session Fixation)
**OWASP:** A07:2021 — Identification and Authentication Failures
**Scan date:** 2026-03-26 (v2 scan)
**Status:** ⚠️ NEEDS MANUAL VERIFICATION — requires authenticated test to confirm (scanner tested with a POST to login, but did not actually authenticate). Do not submit without browser verification.

---

## Summary

The OpenProject session cookie (`_open_project_session`) is not regenerated upon successful authentication. An attacker who can plant a known session ID in a victim's browser can wait for the victim to log in, then use that pre-known session ID to access the now-authenticated session. This is a classic session fixation attack (CWE-384).

---

## Vulnerability Details

**Affected cookie:** `_open_project_session`
**Affected endpoint:** `POST https://community.openproject.org/login?layout=1`

The scanner observed that the `_open_project_session` cookie value was identical in the pre-login request and the post-login response — indicating the server does not issue a new session ID upon authentication.

In a properly secured application, the session ID must be invalidated and replaced with a new one the moment a user successfully authenticates (`reset_session` in Rails).

---

## Steps to Reproduce

> ⚠️ Requires actual credentials for community.openproject.org. Create a free account to test.

**Browser-based verification (preferred):**

1. Open DevTools → Application → Cookies → `community.openproject.org`
2. Navigate to `https://community.openproject.org/login`
3. Record the current value of `_open_project_session`
4. Log in with valid credentials
5. After successful login, check the value of `_open_project_session` again
6. **If the value is unchanged → session fixation is confirmed**

**Attack simulation (requires two browser profiles):**

```bash
# Step 1: Get a pre-auth session cookie
curl -c /tmp/attacker_session.txt -b /tmp/attacker_session.txt \
  -s -o /dev/null \
  'https://community.openproject.org/login'

# Step 2: Extract the session cookie value
grep '_open_project_session' /tmp/attacker_session.txt

# Step 3: In a real attack, the attacker would plant this cookie in the victim's
# browser (via XSS, MITM, or shared device), then the victim logs in.
# If the session ID doesn't change after login, the attacker's known session
# becomes the authenticated session.

# Step 4: After victim logs in, use the planted session:
curl -b '_open_project_session=<VALUE_FROM_STEP_2>' \
  'https://community.openproject.org/my/account'
# If this returns the victim's account page → session fixation confirmed
```

---

## Impact

An attacker who can set a cookie in the victim's browser (e.g., via:
- A subdomain XSS vulnerability
- Network-level interception (MITM on HTTP, before HTTPS redirect)
- Physical access to a shared device or kiosk

...can pre-plant a known session ID. After the victim authenticates, the attacker uses that same session ID to access the account — gaining full access to projects, work packages, confidential discussions, and all data visible to the victim.

This is particularly severe in enterprise/project management contexts where work package data may be commercially sensitive.

---

## Suggested Fix

In the Rails `SessionsController`, call `reset_session` immediately upon successful authentication:

```ruby
def create
  user = User.find_by(login: params[:username])
  if user&.authenticate(params[:password])
    reset_session  # ← THIS LINE invalidates the old session, issues a new ID
    session[:user_id] = user.id
    redirect_to root_path
  else
    flash[:error] = 'Invalid username or password.'
    render :new
  end
end
```

If using Devise, ensure you are not bypassing `sign_in` with manual session assignment — Devise's `sign_in` handles session regeneration automatically.

---

## References

- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [OWASP: Testing for Session Fixation](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation)
- [Rails Security Guide: Session Fixation](https://guides.rubyonrails.org/security.html#session-fixation-countermeasures)

---

## Submission Notes

- **DO NOT SUBMIT without manual verification.** The scanner's detection was via `endpoint-replay` which does not guarantee actual authentication occurred. A failed login POST would also retain the same session cookie.
- Verification checklist before submitting:
  - [ ] Created a test account on community.openproject.org
  - [ ] Confirmed `_open_project_session` value matches before/after successful login
  - [ ] Confirmed the old session ID is still valid post-login (not just unregenerated but also still accepted)
- If verified, this is a clean medium finding — report separately from the rate limit report, or combine into a session security report.

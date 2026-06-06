# Session Fixation — Session Cookie Not Regenerated After Login

**Target:** https://community.openproject.org  
**Platform:** YesWeHack  
**Program:** OpenProject  
**Severity:** Medium | **CVSS:** 6.9 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`  
**CWE:** CWE-384 (Session Fixation)  
**OWASP:** A07:2021 – Identification and Authentication Failures  
**Confidence:** Medium | **Detection:** endpoint-replay  
**Scan date:** 2026-03-26

> **⚠️ Verifier note (Dio):** This requires manual browser verification before submission. The scanner observed `_open_project_session` cookie unchanged across login — confirm this in a browser (DevTools → Application → Cookies) by logging in and comparing pre/post values. If the cookie value changes after login, this is a FP. Only submit if confirmed.

---

## Summary

The `_open_project_session` cookie on `community.openproject.org` retains the same value before and after a successful login. A Rails application should call `reset_session` on authentication to invalidate the pre-login session ID and issue a new one. If this is not happening, an attacker who can plant a known session ID in a victim's browser (e.g., via a subdomain, network-level interception, or a shared device) can wait for the victim to authenticate and then use the pre-planted session ID to access the victim's authenticated session.

---

## Steps to Reproduce

**Automated detection evidence:**
```bash
# 1. Get a session cookie (pre-login)
PRE_SESSION=$(curl -sc /tmp/cookies.txt -o /dev/null \
  'https://community.openproject.org/login' && \
  grep '_open_project_session' /tmp/cookies.txt | awk '{print $7}')

echo "Pre-login session: $PRE_SESSION"

# 2. Submit login (replace with valid test credentials)
curl -sb /tmp/cookies.txt -sc /tmp/cookies_post.txt \
  -X POST 'https://community.openproject.org/login' \
  -d 'username=YOUR_TEST_USER&password=YOUR_TEST_PASS' \
  -H 'Content-Type: application/x-www-form-urlencoded'

POST_SESSION=$(grep '_open_project_session' /tmp/cookies_post.txt | awk '{print $7}')
echo "Post-login session: $POST_SESSION"

# 3. Compare — if equal, session fixation is confirmed
[ "$PRE_SESSION" = "$POST_SESSION" ] && echo "CONFIRMED: Session ID unchanged after login" \
  || echo "FP: Session ID changed after login"
```

**Manual browser verification (preferred):**
1. Open DevTools → Application → Cookies → `community.openproject.org`
2. Note the value of `_open_project_session` before logging in
3. Log in with valid credentials
4. Check the `_open_project_session` value immediately after login
5. **Vulnerable:** value is unchanged. **Safe:** value is different.

---

## Impact

If confirmed, session fixation enables the following attack:

1. Attacker visits the login page, obtains a valid (unauthenticated) session ID
2. Attacker plants this session ID in the victim's browser (via subdomain cookie injection, network-level injection on shared/public Wi-Fi, or a shared device)
3. Victim logs in — the existing session ID becomes authenticated
4. Attacker uses the pre-planted session ID to access the victim's authenticated session — full account takeover

For a community platform like community.openproject.org, an attacker could impersonate project contributors, access private projects, or post malicious content as a trusted community member.

---

## Expected Behavior

After successful login, the server should issue a new session ID. In Rails:

```ruby
# app/controllers/sessions_controller.rb (or Devise equivalent)
def create
  user = User.find_by(login: params[:username])
  if user&.authenticate(params[:password])
    reset_session           # ← This line invalidates old session, issues new ID
    session[:user_id] = user.id
    redirect_to root_path
  else
    render :new
  end
end
```

If OpenProject uses Devise, ensure `sign_in` is not bypassed with manual `session[]` assignment (Devise handles session regeneration internally via `sign_in`).

---

## Notes for Verifier (Dio)

- **Must manually verify** before submitting — medium confidence, requires browser test with real credentials
- If confirmed, this pairs well with the rate limiting finding (same target, same submission window)
- OpenProject community has user accounts — accounts can be private projects, patches, security-related content
- CWE-384 is well-recognized and has good precedent in bug bounty programs
- OpenProject bounty estimate: MEDIUM → EUR 200–500

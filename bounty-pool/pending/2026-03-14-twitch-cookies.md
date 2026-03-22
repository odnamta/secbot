# Twitch.tv — Bounty Assessment

**Scan Date:** 2026-03-14
**Target:** https://www.twitch.tv/
**Pages:** 5
**Duration:** 48m 36s

## Findings Summary

| # | Severity | Title | Bounty Potential |
|---|----------|-------|-----------------|
| 1 | HIGH | Missing CSP | LOW — most programs don't accept missing CSP alone |
| 2-3 | MEDIUM | `twitch.lohp.countryCode` HttpOnly/Secure | NONE — locale preference cookie |
| 4 | MEDIUM | `unique_id` missing HttpOnly | NONE — tracking cookie |
| 5 | MEDIUM | `server_session_id` missing HttpOnly | INVESTIGATE — session ID accessible via JS |
| 6 | MEDIUM | `experiment_overrides` missing HttpOnly | NONE — A/B testing cookie |
| 7 | MEDIUM | `api_token` missing HttpOnly | INVESTIGATE — may contain auth token |

## Analysis

### Worth Investigating
1. **`server_session_id` without HttpOnly** — Set as `server_session_id=068094f6b2bb4862ab734d7267f1e90b; domain=.twitch.tv; path=/; secure; samesite=none`. If this is actually used for session management, exposing it to JavaScript is a real security issue that amplifies any XSS.

2. **`api_token` without HttpOnly** — Cookie name suggests API authentication. If XSS can steal this value, an attacker could use it to call Twitch API as the victim.

### Not Worth Submitting
- Missing CSP alone on twitch.tv — Twitch has a mature security team, this is likely a conscious decision
- `twitch.lohp.countryCode` — "lohp" = Logged Out Home Page, just country detection for locale
- `unique_id` — Client-side tracking identifier, intentionally JS-readable
- `experiment_overrides` — A/B testing configuration, no security impact

### Next Steps
- Test with authenticated session to see if `api_token` contains actual bearer token
- Check if `server_session_id` changes behavior when modified/stolen
- Verify via `document.cookie` in console: are these values actually sensitive?

### Verdict: HOLD — needs authenticated scan

# JavaScript Source Map Publicly Accessible — Exposes Original Application Source

**Date:** 2026-05-13
**Severity:** Medium | **CVSS:** 6.9 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**Platform:** HackerOne | **Program:** Cal.com
**CWE:** CWE-540 — Inclusion of Sensitive Information in Source Code
**OWASP:** A05:2021 — Security Misconfiguration
**Scan date:** 2026-03-26 | **Confidence:** Medium

---

## Summary

A JavaScript source map file is publicly accessible on `app.cal.com`, exposing original TypeScript/JavaScript source code for 4 application files via the `sourcesContent` field. This allows any attacker to reconstruct application internals, review business logic, search for hardcoded secrets, and identify exploitable code paths — bypassing minification/obfuscation.

---

## Steps to Reproduce

1. Fetch the exposed source map directly:

```bash
curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('Files exposed:', len(d.get('sources', [])))
for s in d.get('sources', []):
    print(' -', s)
content = d.get('sourcesContent', [])
print('sourcesContent entries:', len(content))
print('Total source bytes:', sum(len(c or '') for c in content))
"
```

2. Extract and read the original source files:

```bash
curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | python3 -c "
import json, sys
d = json.load(sys.stdin)
sources = d.get('sources', [])
contents = d.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        print(f'=== {src} ({len(content)} bytes) ===')
        print(content[:2000])
        print()
"
```

3. Confirm the response is HTTP 200 and contains `sourcesContent` with non-empty values:

```bash
curl -sI 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | head -5
# Expected: HTTP/2 200
```

---

## Evidence

SecBot probed `/_next/static/` for accessible `.js.map` files. The scanner detected:

- **URL:** `https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map`
- **Status:** HTTP 200
- **Contents:** Source map with `sourcesContent` array containing **4 original source files**
- **Detection method:** `source-map-probe`

---

## Impact

An attacker with access to the source map can:

1. **Read business logic** — understand exactly how booking restrictions, payment flows, and access controls are implemented
2. **Find hardcoded secrets** — API keys, internal endpoint paths, and configuration values that developers left in source comments or variables
3. **Identify injection points** — locate unsanitized inputs, SQL queries, and other vulnerability patterns that are invisible in minified output
4. **Accelerate exploit development** — what might take days of reverse engineering is reduced to minutes of source reading

---

## Suggested Fix

Remove source maps from production builds. In `next.config.js`:

```js
// next.config.js
const nextConfig = {
  productionBrowserSourceMaps: false,  // default — ensure this is not set to true
};
```

Alternatively, serve source maps only to authenticated internal users (e.g., behind a Cloudflare Access policy on `/_next/static/*.map`).

---

## Verification Notes (for Dio — important caveats)

**Priority: LOW — verify before submitting**

Cal.com is **open source** (https://github.com/calcom/cal.com). Their general application code is already public. This finding is only bounty-worthy if the source map contains:

1. **Hardcoded secrets** (API keys, DB connection strings, internal service URLs)
2. **Proprietary/cloud-only business logic** not in the public repo (enterprise billing, Stripe keys, internal admin tooling)
3. **Comments revealing security-sensitive implementation details** not in the public codebase

**How to assess:** Run step 2 above and grep the output:
```bash
curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | \
  python3 -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(d.get('sourcesContent',[])) )" | \
  grep -iE 'key|secret|password|token|api_|sk_|pk_|bearer|internal|localhost|192\.168|10\.'
```

**If nothing sensitive found:** Downgrade to informational / don't submit (open-source project).
**If secrets found:** Escalate to HIGH and submit immediately.

---

## References

- CWE-540: https://cwe.mitre.org/data/definitions/540.html
- OWASP Source Code Disclosure: https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference

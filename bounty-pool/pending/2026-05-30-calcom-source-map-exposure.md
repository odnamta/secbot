# Production JavaScript Source Maps Publicly Accessible

**Severity:** Medium | **CVSS:** 6.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
**Platform:** HackerOne | **Program:** Cal.com
**Confidence:** Medium | **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**OWASP:** A01:2021 - Broken Access Control

> ⚠️ **Review Before Submitting:** Verify the source map contains meaningful sensitive content (business logic, API keys, internal URLs, auth logic) rather than just boilerplate UI code. Run step 3 below to inspect the actual exposed files. Cal.com HackerOne has accepted source map reports before, but they may rate this as informational if the exposed code is generic.

## Summary

JavaScript source maps are publicly accessible on `app.cal.com` in production. The file at `/_next/static/chunks/38892383c615aecb.js.map` returns HTTP 200 and contains the `sourcesContent` field with original, unminified TypeScript source code for 4 files. Attackers can reconstruct complete application logic without deobfuscating minified bundles.

## Steps to Reproduce

**1. Confirm the source map is accessible:**
```bash
curl -s -o /dev/null -w "%{http_code}" \
  'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map'
# Returns: 200
```

**2. Inspect the source map content:**
```bash
curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | head -c 500
# Returns: {"version":3,"sources":[...],"sourcesContent":[...], ...}
```

**3. Extract file names and source content:**
```bash
curl -s 'https://app.cal.com/_next/static/chunks/38892383c615aecb.js.map' | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('Source files:')
for src in data.get('sources', []):
    print(' ', src)
print()
contents = data.get('sourcesContent', [])
print(f'Files with original source: {sum(1 for c in contents if c)}/{len(contents)}')
if contents:
    print('\\nFirst 500 chars of source[0]:')
    print(contents[0][:500] if contents[0] else '(empty)')
"
```

**4. Find additional source maps by scanning JS bundle paths:**
```bash
# Get the main page and extract .js bundle URLs
curl -s 'https://app.cal.com/login' | grep -oE '"/_next/static/chunks/[^"]+\.js"' | head -20 | \
  while read -r path; do
    clean="${path//\"/}"
    map_url="https://app.cal.com${clean}.map"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
    echo "$code $map_url"
  done
```

## Impact

Exposed source maps allow an attacker to:

1. **Read business logic and auth flows:** Unminified TypeScript code reveals validation logic, feature flags, and authorization checks — helping identify bypasses without blackbox testing.
2. **Discover API endpoints and parameters:** Internal tRPC procedure names, API routes, and undocumented endpoints are visible in source code before they appear in crawlers or documentation.
3. **Find hardcoded secrets/config:** Developer shortcuts (hardcoded tokens, staging credentials, internal URLs) sometimes appear in source maps. Check `sourcesContent` for strings matching API keys, tokens, or internal hostnames.
4. **Accelerate vulnerability discovery:** What would take days of reverse-engineering minified JS takes minutes with source maps.

## Suggested Fix

**Option 1 (Recommended) — Remove source maps from production build:**
```javascript
// next.config.js
module.exports = {
  productionBrowserSourceMaps: false,  // Default is false — ensure this isn't set to true
};
```

**Option 2 — Block at CDN/server level:**
```nginx
# Nginx: Block .map files
location ~* \.map$ {
    return 404;
}
```

```
# Vercel: Add to vercel.json headers
{
  "headers": [
    {
      "source": "/_next/static/:path*.map",
      "headers": [{ "key": "X-Robots-Tag", "value": "noindex" }]
    }
  ]
}
# Or use middleware to return 404 for .map requests
```

**Option 3 — Keep maps but protect them:**
Generate source maps and upload to an error tracking service (Sentry, Datadog) with authenticated access, rather than serving them publicly.

## References

- CWE-200: Exposure of Sensitive Information
- Next.js `productionBrowserSourceMaps` docs: https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps
- OWASP Testing Guide — Source Code Disclosure (WSTG-INFO-05)

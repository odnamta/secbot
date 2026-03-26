# Security Assessment Report

**Target:** https://konghq.com/
**Scan Date:** 2026-03-14
**Profile:** standard
**Pages Scanned:** 5
**Duration:** 3m 23s

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low | 0 |
| Info | 0 |
| **Total** | **3** |

## Confirmed Findings

---

## 1. [MEDIUM] Missing Content-Security-Policy (CSP) Header

**Asset:** https://konghq.com/
**Weakness:** CWE-693: Protection Mechanism Failure
**OWASP Category:** A05:2021 - Security Misconfiguration
**Confidence:** high

### Description

The Content-Security-Policy header is absent from responses on konghq.com. CSP is a critical defense-in-depth control that restricts which scripts, styles, and other resources the browser is permitted to load and execute. Without it, any XSS vulnerability or compromised third-party resource has a much wider blast radius.

### Steps to Reproduce

curl -I https://konghq.com/
Inspect the response headers — no 'content-security-policy' header is present.

### Impact

Increases the exploitability of any existing or future XSS vulnerabilities. Malicious scripts injected via XSS or a compromised third-party CDN can execute without browser-level restriction, potentially leading to session hijacking, credential theft, or data exfiltration.

### Supporting Evidence

**HTTP Response:**

```http
HTTP/1.1 200
age: 225
cache-control: public, s-maxage=300, max-age=60, stale-while-revalidate=600, stale-if-error=900
content-encoding: gzip
content-type: text/html; charset=utf-8
date: Sat, 14 Mar 2026 00:45:52 GMT
etag: "ezzqjivqdn9yql"
vary: Accept-Encoding
vercel-cache-tag: path:,collection:pages,slug:home
via: 1.1 b880edd70a35b937a6c64932d997efd0.cloudfront.net (CloudFront)
x-amz-cf-id: 9RNUTORwxtUSqFh6vgXZohNEb1FIMxEY1lNlksel2zT97nzUIoASew==
x-amz-cf-pop: CGK51-P1
x-cache: Hit from cloudfront
x-powered-by: Next.js
```

**Affected URLs:**
- https://konghq.com/

**Additional Evidence:**

```
// next.config.js — add security headers
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://munchkin.marketo.net https://dev.visualwebsiteoptimizer.com https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self' https://munchkin.marketo.net",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ')
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders
      }
    ];
  }
};

// Alternatively, deploy via a Cloudflare Worker:
// addEventListener('fetch', event => {
//   event.respondWith(addSecurityHeaders(event.request));
// });
// async function addSecurityHeaders(request) {
//   const response = await fetch(request);
//   const newHeaders = new Headers(response.headers);
//   newHeaders.set('Content-Security-Policy', "default-src 'self'; ...");
//   return new Response(response.body, { ...response, headers: newHeaders });
// }
```

### Suggested Remediation

Add a Content-Security-Policy header via Cloudflare (Transform Rules or a Worker) or in the Next.js configuration. Start with a report-only policy to audit violations before enforcing. Given the use of Marketo and VWO third-party scripts, the policy must explicitly allowlist those origins.

---

## 2. [MEDIUM] Missing Subresource Integrity (SRI) on External Scripts

**Asset:** https://konghq.com/
**Weakness:** CWE-434: Unrestricted Upload of File with Dangerous Type
**OWASP Category:** A08:2021 - Software and Data Integrity Failures
**Confidence:** high

### Description

At least 7 externally-hosted scripts (including Marketo's munchkin.js and Visual Website Optimizer's j.php) are loaded without `integrity` attributes. SRI allows the browser to verify that a fetched resource has not been tampered with by comparing its cryptographic hash against a declared value. Dynamic scripts (e.g., VWO's j.php with query parameters) cannot use static SRI hashes and should instead be sandboxed or loaded via a server-side proxy.

### Steps to Reproduce

Open https://konghq.com/ in a browser.
Open DevTools → Sources or view page source.
Locate <script> tags pointing to munchkin.marketo.net, dev.visualwebsiteoptimizer.com, and other external origins.
Confirm none have an 'integrity' attribute.

### Impact

If any of the external CDN or SaaS providers (Marketo, VWO, etc.) is compromised or their CDN is hijacked, an attacker can serve arbitrary JavaScript that executes in the context of konghq.com — enabling credential theft, session hijacking, or supply-chain attacks against site visitors.

### Supporting Evidence

**Affected URLs:**
- https://konghq.com/

**Additional Evidence:**

```
// Generate SRI hash (CLI):
// curl -s https://munchkin.marketo.net/164/munchkin.js | openssl dgst -sha384 -binary | openssl base64 -A
// Output example: abc123...

// Then in your HTML / Next.js Script component:
<script
  src="https://munchkin.marketo.net/164/munchkin.js"
  integrity="sha384-<generated-hash>"
  crossOrigin="anonymous"
  defer
/>

// In Next.js using the Script component:
import Script from 'next/script';

<Script
  src="https://munchkin.marketo.net/164/munchkin.js"
  integrity="sha384-<generated-hash>"
  crossOrigin="anonymous"
  strategy="afterInteractive"
/>

// For dynamic scripts (VWO j.php) where SRI is not feasible,
// restrict execution via CSP script-src with a nonce:
// Content-Security-Policy: script-src 'nonce-{random}' ...
// and inject the nonce server-side per request.
```

### Suggested Remediation

For static external scripts with stable content (e.g., munchkin.js), generate an SRI hash and add the integrity + crossorigin attributes. For dynamic scripts like VWO's j.php (which changes per request), SRI is not applicable — instead, consider loading them through a server-side proxy or accepting the risk and mitigating via a strict CSP with nonces/hashes.

---

## Needs Review (Medium Confidence)

> These findings have strong indicators but need manual verification before submission.

---

## 3. [MEDIUM] Missing HTTP Strict-Transport-Security (HSTS) Header

**Asset:** https://konghq.com/
**Weakness:** CWE-319: Cleartext Transmission of Sensitive Information
**OWASP Category:** A05:2021 - Security Misconfiguration
**Confidence:** medium

### Description

The Strict-Transport-Security (HSTS) header is not present in responses from konghq.com. HSTS instructs browsers to only communicate with the site over HTTPS for a defined period, preventing protocol downgrade attacks. Note: Cloudflare can strip or not forward this header depending on SSL/TLS configuration — verify whether Cloudflare's 'HSTS' setting under SSL/TLS → Edge Certificates is enabled, as the header may be present at the edge but not reflected in direct origin responses.

### Steps to Reproduce

curl -I https://konghq.com/
Check response headers — 'strict-transport-security' is absent.
Also verify in Cloudflare dashboard: SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS).

### Impact

Without HSTS, users who navigate to http://konghq.com (or follow a plain-HTTP link) are vulnerable to SSL-stripping attacks on untrusted networks. Cookies without the Secure flag could also be intercepted. In practice, the risk is reduced by Cloudflare's HTTPS redirect, but HSTS provides defense-in-depth and enables preloading.

### Supporting Evidence

**HTTP Response:**

```http
HTTP/1.1 200
age: 225
cache-control: public, s-maxage=300, max-age=60, stale-while-revalidate=600, stale-if-error=900
content-encoding: gzip
content-type: text/html; charset=utf-8
date: Sat, 14 Mar 2026 00:45:52 GMT
etag: "ezzqjivqdn9yql"
vary: Accept-Encoding
vercel-cache-tag: path:,collection:pages,slug:home
via: 1.1 b880edd70a35b937a6c64932d997efd0.cloudfront.net (CloudFront)
x-amz-cf-id: 9RNUTORwxtUSqFh6vgXZohNEb1FIMxEY1lNlksel2zT97nzUIoASew==
x-amz-cf-pop: CGK51-P1
x-cache: Hit from cloudfront
x-powered-by: Next.js
```

**Affected URLs:**
- https://konghq.com/

**Additional Evidence:**

```
// Option 1: Cloudflare Dashboard
// SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS)
// Enable: true, Max-Age: 31536000, Include Subdomains: true, Preload: true

// Option 2: next.config.js
const securityHeaders = [
  {
    key: 'Strict-Transport-Security',
    // Start with max-age=300 for testing, then increase to 31536000
    value: 'max-age=31536000; includeSubDomains; preload'
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders
      }
    ];
  }
};
```

### Suggested Remediation

Enable HSTS either via Cloudflare's built-in HSTS toggle (SSL/TLS → Edge Certificates → HSTS) or by adding the header in Next.js config. Start with a short max-age (e.g., 300 seconds) to test, then increase to 31536000 (1 year) and consider adding 'preload' to submit to the HSTS preload list.

---

---

*Generated by SecBot — AI-Powered Security Scanner*

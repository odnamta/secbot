# Missing Content-Security-Policy Header

**Severity:** high | **CVSS:** 7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** high

## Description
The application does not set a Content-Security-Policy (CSP) header on any response. Without CSP, the browser has no instruction to block inline scripts, unauthorized external script sources, or data exfiltration — making the confirmed DOM XSS finding significantly more dangerous and easier to exploit.

## Steps to Reproduce
1. curl -I https://www.moneybird.com/
2. Observe that no 'content-security-policy' header is present in the response

## Impact
Absence of CSP removes a critical defense-in-depth layer. The existing DOM XSS vulnerability can be exploited without any browser-level mitigation. Attackers can load external scripts, exfiltrate data to arbitrary domains, and perform UI redressing.

## Suggested Fix
Deploy a strict CSP header. Start with a report-only policy to identify violations before enforcing. Use nonces for inline scripts rather than 'unsafe-inline'. Set this header at the web server or CDN layer for all responses.

## Affected URLs
- https://www.moneybird.com/

## Reproduction Command
```bash
curl -sI \
  'https://www.moneybird.com/'
```

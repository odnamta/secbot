# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** medium | **CVSS:** 6.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** medium — UNVERIFIED (scanner detected sink match; human browser test required before submission)

## Description
The homepage directly writes URL fragment content into the DOM via innerHTML without sanitization. An attacker can craft a malicious URL containing an HTML/JS payload in the fragment (e.g., #<img src=x onerror=alert(1)>) and trick a user into clicking it, causing arbitrary JavaScript execution in the victim's browser.

## Steps to Reproduce
1. Open a browser (curl will NOT work — URL fragments are processed client-side only)
2. Navigate to: `https://www.moneybird.com/#<img src=x onerror=alert(1)>`
3. Observe whether an alert dialog fires
4. The scanner confirmed the payload (`<img src=x onerror=...>`) reached an `innerHTML` sink with unencoded HTML characters — execution depends on whether the browser renders the injected element

**Note:** This requires human browser verification before submission. The scanner detected a DOM sink receiving unencoded HTML, but did not confirm script execution.

## Impact
If confirmed: an attacker can craft a malicious `moneybird.com` URL and send it to victims. Because the page is on the trusted `moneybird.com` domain, users are more likely to interact with injected content. Potential impact includes phishing overlays, credential harvesting, and redirection to attacker-controlled pages. Note: `www.moneybird.com` is the marketing homepage; users are not authenticated here, so session hijacking is not directly applicable.

## Suggested Fix
Never assign unsanitized URL fragment data to innerHTML. Use textContent for plain text, or sanitize with DOMPurify before any HTML insertion. Audit all code paths that read from `window.location.hash`.

## Affected URLs
- https://www.moneybird.com/

## Verification
Open the following URL in a browser to confirm execution:
```
https://www.moneybird.com/#<img src=x onerror=alert(1)>
```
If the alert fires, update confidence to `high` and submit. If the payload is escaped or the onerror does not fire, discard this finding.

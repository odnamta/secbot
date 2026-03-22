# postMessage Handlers Missing Origin Validation

**Severity:** medium | **CVSS:** 6.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**Platform:** HackerOne | **Program:** Moneybird
**Confidence:** medium

## Description
The homepage registers 3 postMessage event listeners that do not validate event.origin before processing the message. Any window with a reference to this page (e.g., a popup opener, iframe embedder, or cross-origin frame) can send arbitrary messages that will be processed without authentication of the sender.

## Steps to Reproduce
1. Open https://www.moneybird.com/ in a browser
2. From a different origin (e.g., attacker.com), open a reference to the Moneybird window
3. Send arbitrary postMessage payloads: targetWindow.postMessage({arbitrary: 'data'}, '*')
4. Observe whether the handlers process the data and what side effects occur

## Impact
Depending on what the handlers do with received data, this could enable cross-origin state manipulation, token theft, triggering of privileged actions, or serving as an amplification vector for the existing XSS. Automated testing could not fully enumerate all handler logic, so manual review is warranted.

## Suggested Fix
Always validate event.origin against an allowlist of trusted origins at the top of every postMessage handler. Reject messages from unexpected origins immediately.

## Affected URLs
- https://www.moneybird.com/

## Reproduction Command
```bash
curl -s -i -L \
  'https://www.moneybird.com/'
```

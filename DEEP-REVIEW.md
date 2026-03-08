# SecBot Deep Review -- Brutally Honest Assessment

**Reviewer:** Claude Opus 4.6, acting as senior security engineer
**Date:** 2026-03-08
**Version reviewed:** v0.8.0 (published on npm)
**Codebase:** 13,184 lines of TypeScript (src), 12,656 lines of tests

---

## A. Reality Check

### Is this tool actually useful?

**For the owner's own apps: Yes, genuinely useful.** The passive scanner alone (security headers, cookie flags, info leakage, mixed content, cross-origin policy) provides real value as a CI gate. The "scan our own finance app, iterate until clean" story in the README is legitimate -- that workflow works and is the strongest use case.

**For anyone else: Marginally.** An experienced developer who wants a quick "how bad are my headers" check might use this over manually running `curl -I`. But anyone with real security needs will reach for established tools.

### How does it compare to existing free tools?

| Tool | What it does better than SecBot |
|------|-------------------------------|
| **Nuclei** | 8,000+ community templates, massive CVE coverage, protocol-level scanning, mature plugin ecosystem. SecBot has 11 active checks. |
| **Nikto** | 6,700+ checks for known server misconfigurations, default files, outdated software. SecBot checks zero of these. |
| **OWASP ZAP** | Full intercepting proxy, active scanner, fuzzer, spider, authentication handling, scripting, massive community. Years of battle-testing. |
| **Semgrep** | SAST (code-level), completely different angle. SecBot is DAST only. |
| **Burp Suite (Community)** | Intercepting proxy, repeater, intruder, decoder -- the manual testing workflow that SecBot's "bounty" mode tries to replace. |

**The honest comparison:** SecBot is a toy scanner wearing an enterprise costume. That is not inherently bad -- every tool starts somewhere. But publishing it on npm as if it is ready for external consumption is premature.

### Is the npm publish premature?

**Yes.** Here is why:

1. **No real-world validation.** The roadmap literally says "Step 0: First Real Scan -- THIS MUST HAPPEN BEFORE ANY NEW FEATURES" and that step has not been completed. You published before running your own scan.
2. **The name "secbot" on npm is prime real estate.** You have claimed a generic, desirable package name for a v0.8 experiment. If the project dies (which most experiments do), that name is wasted.
3. **Security tools carry liability.** If someone uses secbot to scan a target they do not own, your tool facilitates unauthorized testing. The consent prompt only works in TTY mode -- in CI/CD (where the GitHub Action is designed to run), there is no consent check.
4. **No SECURITY.md, no vulnerability disclosure policy.** For a security tool, this is ironic.

---

## B. Security Quality

### Are the 11 active checks actually finding real vulnerabilities?

**Some yes, most are barely above baseline.**

**Good checks (would catch real bugs):**

1. **XSS (reflected via URL params)** -- The `checkDangerousReflection()` function is well-designed. It correctly distinguishes between HTML-encoded reflections (safe) and unencoded reflections in dangerous contexts (script tags, event handlers, unquoted attributes). The false-positive regression tests against a secure server confirm this works. DOM XSS detection via sink monitoring (`document.write`, `eval`, `innerHTML` via MutationObserver) is genuinely clever and something most simple scanners miss.

2. **SQLi (error-based)** -- The SQL error pattern list covers MySQL, PostgreSQL, MSSQL, Oracle, and SQLite. This is comprehensive and will catch the most common case: apps that leak SQL errors to users. The multi-round boolean-blind confirmation with consistency thresholds is smart -- it avoids the classic false positive where dynamic pages naturally vary in size.

3. **CORS** -- Tests origin reflection, null origin, and overly-permissive preflight. Correctly ignores wildcard ACAO on static assets. This is a solid implementation.

4. **Passive checks** -- Security headers, cookie flags, info leakage. These are straightforward but correct. The `SKIP_HTTPONLY_PATTERNS` list (excluding analytics cookies from HttpOnly warnings) shows attention to false-positive reduction.

**Mediocre checks (technically work but limited real-world value):**

5. **SSTI** -- The approach (inject `{{71829*71829}}`, look for `5159404241` in response) is textbook correct but extremely narrow. It only catches apps that directly evaluate user input as templates -- which is rare in modern frameworks. The control payload confirmation is a nice touch, but the scope is limited to the most obvious cases.

6. **SSRF** -- Only tests URL parameters matching specific names (`url`, `link`, `src`, etc.). Real SSRF often hides in JSON body parameters, multipart uploads, XML external entities, or webhook configurations. The DNS canary integration is good in theory but requires an external callback server that most users will not set up.

7. **Command Injection** -- Same pattern as SSTI: inject payload, look for marker in response. Only catches the most blatant cases where command output is reflected. Real-world cmdi usually requires blind detection, which the timing-based approach handles but with a coarse 4-second threshold that will miss faster-executing commands.

8. **Directory Traversal** -- Looks for `root:x:0:0` patterns in responses. This is the "hello world" of traversal detection. Modern apps return JSON error responses, custom 404 pages, or simply 403s -- none of which this catches. The check also only activates for `deep` profile by default, so `standard` scans miss it entirely.

**Weak checks (questionable value):**

9. **IDOR** -- Correctly requires dual auth sessions (good -- single-session IDOR testing is meaningless). But the detection logic (body similarity via Jaccard + JSON key comparison) is fragile. A list endpoint that returns the same page structure regardless of whether you have access (just with different data) will trigger false positives. An API that returns 200 with `{"error": "unauthorized"}` will be missed if the body structure matches the success case.

10. **TLS** -- Uses Node.js `tls` module directly, bypassing Playwright. Checks protocol version, certificate validity, and HSTS. This is fine but adds minimal value over `testssl.sh` or SSLLabs, which check cipher suites, key exchange, certificate chains, and known vulnerabilities (BEAST, POODLE, DROWN, etc.) in far more depth.

11. **SRI** -- Checks for missing `integrity` attributes on external scripts/stylesheets. Technically correct but extremely low-impact. Most modern applications use bundlers that inline or self-host assets. This is a compliance checkbox, not a vulnerability.

### False positive / negative issues

**False positives:** The codebase shows genuine effort to reduce false positives:
- HTML encoding detection before flagging XSS
- Baseline comparison before flagging SSTI/CMDi
- Multi-round boolean-blind confirmation for SQLi
- CORS static asset filtering
- Cookie name pattern matching to skip analytics cookies

**False negatives (the bigger problem):**
- XSS: No testing of POST body parameters reflected in non-form contexts (API responses rendered client-side)
- SQLi: No testing of JSON body parameters, header injection, or second-order SQLi
- SSRF: No testing of POST bodies, XML/JSON payloads, or redirect-based SSRF
- No CRLF injection
- No HTTP request smuggling
- No WebSocket testing
- No GraphQL-specific checks
- No JWT testing
- No deserialization testing
- No file upload testing
- No race condition detection

### Does the AI pipeline add genuine value?

**Planner: Minor value.** It decides which checks to run based on recon data. But the fallback logic does the same thing with simple heuristics. The AI adds maybe 5-10% improvement in check selection. Not worth the API cost and latency for most users.

**Validator: Moderate value.** Having Claude review raw findings and filter false positives is the best use of AI in this pipeline. But the fallback (mark everything as valid) means without an API key, you get zero benefit. And the batch-of-10 approach means a scan with 50 findings costs 5 API calls.

**Reporter: Low value.** Generating human-readable reports with fix suggestions is nice but not essential. The rule-based fallback produces adequate reports. The AI just makes them read better.

**Verdict on AI:** The AI pipeline is a wrapper, not a moat. It is the equivalent of feeding scanner output to ChatGPT and asking "which of these are real?" Any user could do this manually. The value is in automating that step, but it is not a competitive advantage.

### Would a real pentester use any of these checks?

**No.** A real pentester would use Burp Suite Pro for intercepting, repeating, and modifying requests. They would use Nuclei for automated template-based scanning. They would use SecBot for... nothing. The checks are too shallow for professional use and the tool does not integrate into the manual testing workflow (though the Burp XML export is a step in the right direction).

---

## C. Code Quality

### Architecture

**Genuinely good.** This is the strongest aspect of the project.

- Clean 9-phase pipeline with clear separation of concerns
- Each active check implements the `ActiveCheck` interface independently
- Plugin system for custom checks
- Config file support with CLI override precedence
- Proper browser lifecycle management (shared context across phases)
- Signal handler cleanup (SIGINT/SIGTERM)
- Auth temp file cleanup with `0o600` permissions
- Request logger for accountability

The architecture is what you'd expect from a well-designed tool by a competent developer. It is extensible, modular, and follows TypeScript best practices (strict mode, proper typing).

### Test quality

**912 tests -- and they are meaningful.**

The test suite is genuinely impressive for a side project:

- **Integration tests** against a real Express vulnerable server fixture -- not mocked HTTP responses
- **False-positive regression tests** against a properly secured server -- ensuring checks produce zero findings when the target is safe
- **Unit tests** covering dedup, scope enforcement, JSON parsing, payload structure, AI response handling, WAF fingerprinting, rate limiting, session management, CLI validation
- **60 test files** covering all major subsystems

The vulnerable server fixture (`test/fixtures/vulnerable-server.ts`) is well-designed: it has intentional vulnerabilities for each check type AND a `/safe` endpoint that is properly secured. This is exactly how you should test a security scanner.

**Criticism:** The integration tests only run against the built-in vulnerable server. There are no tests against real-world-like applications (e.g., a Next.js app with API routes, a Django app with CSRF protection). The tool has never been validated against anything except its own test fixture.

### Dependencies

5 runtime dependencies. All reasonable:
- `@anthropic-ai/sdk` -- AI features
- `chalk` -- terminal colors
- `commander` -- CLI framework
- `dotenv` -- env file loading
- `playwright` -- browser automation

**Security concern: Playwright is 975 KB unpacked and pulls in a full Chromium browser.** For a CLI tool installed globally via npm, this is enormous. Users running `npm install -g secbot` will download hundreds of megabytes of browser binaries. This should be documented prominently.

No obvious supply chain risks in the dependency tree. Express is a dev dependency only (test fixture).

### Error handling

Generally good. Each check wraps its work in try/catch, logs debug messages on failure, and continues. The browser is cleaned up in a `finally` block. Auth temp files are cleaned up on both success and error paths.

**One concern:** The `execSync` in the vulnerable server test fixture (`test/fixtures/vulnerable-server.ts:178`) actually executes shell commands. This is fine for testing but if anyone accidentally starts that server in a non-test context, it is a real command injection vulnerability. It should have a comment-level warning.

### Edge cases

- Rate limiting is implemented but not tested against real rate-limiting servers
- Proxy support exists but is not tested
- The stealth profile (randomized delays, UA rotation) has not been validated against real WAFs
- The OOB callback server binds to `127.0.0.1` only -- good security choice
- Credential handling properly warns about CLI visibility and prefers env vars

---

## D. What's Missing (Critical)

### Checks a real security scanner needs

| Category | What's Missing | Impact |
|----------|---------------|--------|
| **Auth** | JWT none-algorithm, token reuse, session fixation, privilege escalation, OAuth redirect abuse | These are the bread and butter of bug bounties |
| **API** | GraphQL introspection, batching attacks, REST mass assignment, API key leaks in responses | Modern apps are API-first |
| **Race conditions** | TOCTOU, concurrent request abuse, double-spend | High-impact, easy wins on bug bounties |
| **File upload** | Extension bypass, content-type mismatch, path traversal via filename, polyglot files | Common vulnerability class |
| **Deserialization** | Java/PHP/Python/Ruby/Node deserialization gadgets | Critical severity when found |
| **CRLF injection** | Header injection via CRLF in parameters | Can lead to HTTP response splitting |
| **HTTP smuggling** | CL/TE, TE/CL, TE/TE request smuggling | Critical, unique to HTTP/1.1 |
| **WebSocket** | WS injection, CSWSH (cross-site WebSocket hijacking) | Growing attack surface |
| **Subdomain takeover** | Dangling DNS records pointing to unclaimed services | Common, easy bounty |
| **Known CVE scanning** | Check JS libraries, server software against CVE databases | Basic hygiene that Nuclei excels at |
| **Business logic** | Checkout manipulation, coupon abuse, password reset flaws | Cannot be automated with payloads |
| **Information disclosure** | `.git/config`, `.env`, `backup.sql`, `phpinfo.php`, common backup/config files | Simple but effective |

### What would make this competitive for bug bounties?

1. **Recon integration.** Bug bounty starts with asset discovery: subdomain enumeration, port scanning, tech fingerprinting at scale. SecBot starts at the wrong point in the kill chain.
2. **Scope management.** Auto-parsing HackerOne/Bugcrowd program scope to prevent out-of-scope testing. This is both a legal requirement and a differentiator.
3. **Finding deduplication against public disclosures.** Submitting a known/fixed vulnerability wastes everyone's time.
4. **Chain detection.** "Open redirect + SSRF = internal SSRF" is the kind of insight that wins bounties. Individual findings are commodities.

---

## E. Honest Verdict

### Kill it, pivot it, or keep building?

**Keep building -- but with a massive scope correction.**

Here is the reasoning:

**Why not kill it:**
- The architecture is solid and extensible
- 912 meaningful tests show disciplined engineering
- The passive scanner is genuinely useful for CI/CD
- The AI integration (particularly validation) has a path to being differentiated
- The developer is learning security by building, which is the best way to learn

**Why not pivot:**
- The current direction (DAST scanner with AI interpretation) is sound
- The market gap (developer-friendly security scanning with AI noise reduction) is real
- No fundamental architectural flaw requires starting over

**What needs to change immediately:**

1. **Stop calling it a bug bounty tool.** It is not. It is a developer security hygiene tool. The bounty report format is window dressing without the checks to back it up. Reposition as: "Security header checker and basic vulnerability scanner for your own apps."

2. **Unpublish from npm or rename.** v0.8.0 with zero real-world scans on the npm registry is a liability. Either (a) unpublish and republish when there are 10+ successful real-world scans documented, or (b) rename to something less generic to avoid squatting a premium npm name.

3. **Complete Step 0 from your own roadmap.** Run the tool against your own apps. Document the results. Fix the false positives. This is the single most important thing that has not been done.

### Three most impactful things to do next

**1. Run 10 real scans and document results (1-2 days)**
Scan your own apps: GIS-ERP, GLS-ERP, atmando-platform, Cekatan, dioatmando.com. For each scan:
- Record: raw findings, false positives, true positives, missed vulnerabilities
- Fix false positives in the scanner code
- Add integration tests for any false positive patterns discovered
This will improve the tool more than any new feature.

**2. Add information disclosure checks (1 day)**
The highest ROI new check category. Scan for:
- `/.git/config`, `/.env`, `/.env.local`, `/.env.production`
- `/backup.sql`, `/dump.sql`, `/db.sql`
- `/phpinfo.php`, `/info.php`
- `/wp-admin/`, `/admin/`, `/.well-known/`
- Source map files (`.js.map`)
- `robots.txt` and `sitemap.xml` for hidden paths
These are trivial to implement, produce zero false positives, and find real issues.

**3. Add JavaScript library CVE checking (2-3 days)**
During the crawl phase, you already collect `page.scripts`. Cross-reference loaded JS libraries against a CVE database (e.g., retire.js dataset, Snyk vulnerability DB). This is a high-value passive check that runs on every scan without additional requests.

---

## F. Hosting Decision

### Does secbot need hosting/dashboard?

**No. CLI-only is the right call for now.**

Reasons:
- The tool's value is in the scan pipeline, not the UI
- A dashboard adds maintenance burden without improving detection quality
- The HTML report output is sufficient for sharing results
- Building a dashboard is a classic "feel productive without shipping value" trap

### Should scheduled scans be set up?

**Yes, but only against your own apps as a cron job.**

Recommended setup:
```bash
# Weekly scan of your own apps (Mac Mini cron)
0 3 * * 0 secbot scan https://gis-erp.vercel.app --profile standard --no-ai -f json -o ~/secbot-reports/gis-erp/
0 3 * * 0 secbot scan https://gls-erp.vercel.app --profile standard --no-ai -f json -o ~/secbot-reports/gls-erp/
```

This serves dual purpose:
1. Continuous security monitoring of your own apps (the primary use case)
2. Ongoing validation of the scanner itself (dogfooding)

Do NOT run scheduled scans against targets you do not own. Do NOT expose the results publicly.

---

## Summary Table

| Dimension | Grade | Notes |
|-----------|-------|-------|
| Architecture | **A-** | Clean, modular, extensible. Best aspect of the project. |
| Test quality | **A** | 912 meaningful tests with FP regression. Impressive. |
| Active check depth | **D+** | 11 checks, most are surface-level. Missing entire vulnerability classes. |
| Passive check quality | **B+** | Solid header/cookie/leak checks with good FP reduction. |
| AI integration | **C+** | Works but is not a moat. Wrapper over Claude, not a differentiator. |
| Real-world readiness | **F** | Zero documented real-world scans. Published before tested. |
| Competitive position | **D** | Cannot compete with Nuclei, ZAP, or Burp on any axis today. |
| Documentation | **B+** | README is thorough. CLAUDE.md is excellent. |
| npm publish decision | **F** | Premature. Squatting a prime name for an untested tool. |
| Overall | **C** | Solid engineering, weak security depth, premature release. |

**Bottom line:** This is a well-engineered tool built by someone who is not (yet) a security professional. The code quality exceeds the security knowledge. The path forward is to use the tool on real targets, learn from what it finds (and misses), and iterate. Stop adding features and start scanning.

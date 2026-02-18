# SecBot — CLI Prompt for Claude Code

> Copy-paste this into a new Claude Code CLI window opened at `experiments/secbot/`

---

## Prompt

You are building **SecBot** — an AI-powered security testing CLI tool. Think "Playwright for security": a developer-friendly tool that scans web apps for vulnerabilities with a single command and uses AI to interpret results.

### What to build (Phase 1 MVP)

A TypeScript CLI tool that:

1. **Accepts a target URL**: `npx secbot scan https://myapp.com`
2. **Uses Playwright** to automate browser navigation (handles SPAs, JavaScript-heavy apps, authentication)
3. **Runs passive security checks** on all intercepted HTTP traffic:
   - Missing/weak security headers (CSP, HSTS, X-Frame-Options, etc.)
   - Cookie security flags (HttpOnly, Secure, SameSite)
   - Information leakage (server version headers, verbose errors, stack traces)
   - Mixed content (HTTP resources on HTTPS pages)
   - Sensitive data in URLs
4. **Runs active security checks**:
   - XSS probe injection on form inputs and URL parameters
   - SQL injection detection on form inputs
   - Open redirect testing
   - CORS misconfiguration testing
   - Directory traversal probes on API endpoints
5. **Feeds raw findings to an LLM** (Claude API via Anthropic SDK) that:
   - Deduplicates and prioritizes findings
   - Filters false positives (target: <10 actionable findings per scan)
   - Explains each vulnerability in plain developer language
   - Provides reproduction steps
   - Suggests code-level fixes
   - Assigns a confidence score (high/medium/low)
6. **Outputs a structured report**: terminal summary + JSON file + optional HTML report

### Tech stack

- **Language**: TypeScript (strict mode)
- **Runtime**: Node.js 20+
- **CLI framework**: `commander` or `yargs`
- **Browser automation**: Playwright
- **HTTP interception**: Playwright's `page.route()` / `page.on('response')` for passive scanning
- **AI**: Anthropic SDK (`@anthropic-ai/sdk`) — use Claude Sonnet 4.5 for interpretation
- **Output**: `chalk` for terminal colors, write JSON + HTML reports to `./secbot-reports/`
- **Package manager**: npm
- **Build**: tsup or tsx for running TypeScript directly

### Project structure

```
secbot/
  package.json
  tsconfig.json
  src/
    index.ts              # CLI entry point (commander)
    scanner/
      browser.ts          # Playwright browser automation + crawling
      passive.ts          # Passive checks (headers, cookies, info leaks)
      active.ts           # Active checks (XSS, SQLi, CORS, redirects)
      types.ts            # RawFinding, ScanConfig, ScanResult types
    ai/
      interpreter.ts      # LLM-powered result interpretation
      prompts.ts          # System/user prompts for the AI
    reporter/
      terminal.ts         # Terminal output (chalk)
      json.ts             # JSON report writer
      html.ts             # HTML report generator
    config/
      defaults.ts         # Default scan profiles (quick/standard/deep)
      payloads.ts         # XSS/SQLi test payloads
    utils/
      logger.ts           # Structured logging
```

### CLI interface

```bash
# Basic scan
npx secbot scan https://myapp.com

# Authenticated scan (provide Playwright storage state)
npx secbot scan https://myapp.com --auth ./storageState.json

# Quick scan (headers + cookies only, no active testing)
npx secbot scan https://myapp.com --profile quick

# Deep scan (all checks, follow links, test all forms)
npx secbot scan https://myapp.com --profile deep

# Output formats
npx secbot scan https://myapp.com --format json --output ./report.json
npx secbot scan https://myapp.com --format html --output ./report.html
```

### Key design decisions

1. **No dependency on ZAP/Burp** in Phase 1 — build our own lightweight scanner using Playwright's built-in HTTP interception. This keeps the tool zero-config (`npx secbot scan <url>` should just work).
2. **AI interpretation is the core differentiator** — raw scanner output is noisy. The AI layer should reduce 100+ raw findings to <10 actionable ones with fix suggestions.
3. **Respect robots.txt and rate limits** — include sensible defaults. Add `--ignore-robots` flag for authorized testing only.
4. **Auth support via Playwright storageState** — users export cookies from their browser, SecBot loads them for authenticated scanning.
5. **Progressive output** — show findings as they're discovered (streaming), not just at the end.

### Environment variables

```
ANTHROPIC_API_KEY=your-api-key    # Required for AI interpretation
SECBOT_MAX_PAGES=50               # Max pages to crawl (default: 50)
SECBOT_TIMEOUT=30000              # Per-page timeout in ms (default: 30s)
```

### Bug Bounty Report Format

SecBot should generate reports compatible with HackerOne/Bugcrowd submission format:

```markdown
## Title: [Vulnerability Type] in [Component/Endpoint]

### Severity: [Critical/High/Medium/Low]
### CVSS Score: [calculated]

### Description
[What the vulnerability is and why it matters]

### Steps to Reproduce
1. Navigate to [URL]
2. [Exact steps]
3. Observe [result]

### Impact
[What an attacker could do with this vulnerability]

### Remediation
[Specific code-level fix suggestion]

### Evidence
[Screenshots, HTTP request/response logs, payload used]
```

Add a `--format bounty` flag that outputs in this format. This is critical — the tool should be usable for both internal security review AND bug bounty submissions.

### First milestone

Get this working end-to-end against `https://atmando-finance.vercel.app` (our own Finance app):
1. Crawl the public pages
2. Check all security headers
3. Check cookie flags
4. Test any visible forms for XSS
5. Feed results to Claude for interpretation
6. Output a terminal report + bounty-format report

### What NOT to do in Phase 1

- No SaaS/dashboard (that's Phase 3)
- No CI/CD integration yet (Phase 2)
- No MCP server yet (Phase 2)
- No multi-step attack chaining (Phase 3)
- No SAST/code analysis (Phase 3)
- No Docker/containerization yet
- Don't over-engineer the scanner — start with header checks and XSS probes, iterate from there

### OWASP Top 10 (2025) coverage targets for Phase 1

| Category | Check | Priority |
|----------|-------|----------|
| A03: Injection | XSS probes on forms/params, basic SQLi detection | HIGH |
| A05: Security Misconfiguration | Security headers, CORS, verbose errors, default pages | HIGH |
| A02: Cryptographic Failures | TLS version, mixed content, weak cookie flags | HIGH |
| A01: Broken Access Control | Test for IDOR patterns, missing auth on API endpoints | MEDIUM |
| A06: Vulnerable Components | Check JS libraries against known CVE databases | MEDIUM |
| A10: SSRF | Out-of-band detection via callback URLs | LOW (Phase 2) |

### Important context

- This is the start of a SaaS product. Write clean, extensible code from day one.
- The scanner should be modular — easy to add new check types later.
- We plan to open-source the core scanner and charge for the AI interpretation layer.
- The tool must NEVER perform destructive actions (no data modification, no DoS, no exploitation beyond detection).
- Always include a consent/disclaimer prompt before scanning external targets.

Initialize the project with `npm init`, install dependencies, and start building from `src/index.ts` → `src/scanner/browser.ts` → `src/scanner/passive.ts`. Get the passive scanner working first, then add active checks.

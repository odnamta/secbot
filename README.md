# SecBot

**AI-powered security testing CLI -- Playwright for security.**

SecBot scans web applications for OWASP Top 10 vulnerabilities with a single command. It uses Playwright for browser automation, runs 17 check types (6 passive + 11 active), and optionally uses Claude AI to plan attacks, validate findings, and generate actionable reports. It works fully without an API key via rule-based fallback.

> **Status:** v0.7.0 -- under active development. Not production-hardened yet.

## Quick Start

```bash
# Install globally
npm install -g secbot

# Scan a target you own
secbot scan https://your-app.example.com

# Quick scan, no AI
secbot scan https://your-app.example.com --profile quick --no-ai

# Deep scan with JSON + HTML reports
secbot scan https://your-app.example.com --profile deep -f terminal,json,html
```

## How It Works

SecBot runs a 9-phase pipeline:

```
Phase 0: Discovery     Route discovery (Next.js manifests, --urls file)
Phase 1: Crawl         Playwright browser crawl + HTTP interception
Phase 2: Recon         Tech fingerprinting, WAF detection, endpoint mapping
Phase 3: AI Plan       Claude analyzes recon, recommends checks to run
Phase 4: Passive Scan  Headers, cookies, info leaks, mixed content, CORS policy
Phase 5: Active Scan   AI-selected checks (11 types)
  Pre-dedup            Deduplicate raw findings before AI validation (saves tokens)
Phase 6: AI Validate   Claude validates each finding (real or false positive?)
Phase 7: AI Report     Deduplicate, prioritize, explain, suggest fixes
Phase 8: Output        Terminal + JSON + HTML + bug bounty markdown + SARIF + JUnit
```

The browser is reused across crawl and active scan phases. Every AI call has a rule-based fallback, so the tool works fully without an Anthropic API key.

## CLI Reference

```
secbot scan <url>

Options:
  -p, --profile <profile>       Scan profile: quick | standard | deep | stealth (default: standard)
  -a, --auth <path>             Playwright storage state JSON for authenticated scanning
  --idor-alt-auth <path>        Second user auth state for IDOR testing (requires --auth)
  -f, --format <formats>        Output formats: terminal,json,html,bounty,sarif,junit (comma-separated)
  -o, --output <path>           Output directory (default: ./secbot-reports)
  --max-pages <n>               Maximum pages to crawl
  --timeout <ms>                Per-page timeout in milliseconds
  --ignore-robots               Ignore robots.txt restrictions
  --scope <patterns>            Scope: "*.example.com,-admin.example.com"
  --urls <file>                 File with URLs to scan (one per line)
  --log-requests                Log all HTTP requests (JSONL)
  --callback-url <url>          Callback URL for blind SSRF/OOB detection
  --callback-server <port>      Auto-start built-in OOB callback server
  --oob-wait <seconds>          Wait time for delayed OOB callbacks (default: 30)
  --rate-limit <n>              Maximum requests per second
  --exclude-checks <checks>     Comma-separated check names to skip (e.g. "traversal,cmdi")
  --baseline <file>             Baseline JSON -- only report new findings
  --proxy <url>                 HTTP or SOCKS5 proxy (e.g. socks5://host:1080)
  --export-burp                 Export traffic as Burp Suite XML (requires --log-requests)
  --export-har                  Export traffic as HAR 1.2 (requires --log-requests)
  --login-url <url>             Login page URL for credential-based auth
  --credentials-file <path>     File containing credentials (user:pass)
  --no-ai                       Skip AI, use rule-based fallback
  --verbose                     Debug logging
```

## Scan Profiles

| Profile    | Max Pages | Timeout | Concurrency | Delay  | Use Case                        |
|------------|-----------|---------|-------------|--------|---------------------------------|
| `quick`    | 5         | 15s     | 3           | 50ms   | Fast smoke test, CI gate        |
| `standard` | 25        | 30s     | 5           | 100ms  | Default, balanced               |
| `deep`     | 100       | 60s     | 10          | 100ms  | Thorough scan, all checks       |
| `stealth`  | 3         | 30s     | 1           | 500ms  | Low-noise, randomized delays    |

## Security Checks

### Active Checks (11)

| Check | Category | Description |
|-------|----------|-------------|
| XSS | `xss` | Reflected, DOM-based, and stored cross-site scripting |
| SQLi | `sqli` | Error-based, blind boolean, blind timing, UNION, NoSQL |
| CORS | `cors-misconfiguration` | Origin reflection, null origin, wildcard with credentials |
| Open Redirect | `open-redirect` | URL parameter redirect manipulation |
| Directory Traversal | `directory-traversal` | Path traversal via file-like parameters |
| SSRF | `ssrf` | Internal IP, cloud metadata, DNS rebinding, OOB detection |
| SSTI | `ssti` | Server-side template injection (Jinja2, Twig, EJS, etc.) |
| Command Injection | `command-injection` | OS command injection (Unix + Windows payloads) |
| IDOR | `idor` | Insecure direct object reference (requires dual auth sessions) |
| TLS | `tls` | Certificate validation, protocol version, cipher strength |
| SRI | `sri` | Missing Subresource Integrity on CDN scripts/styles |

### Passive Checks (6 categories)

| Category | What it checks |
|----------|----------------|
| `security-headers` | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Permissions-Policy |
| `cookie-flags` | HttpOnly, Secure, SameSite on session cookies |
| `info-leakage` | Server/X-Powered-By headers, HTML comments, source maps |
| `mixed-content` | HTTP resources loaded on HTTPS pages |
| `sensitive-url-data` | Tokens, keys, passwords in URL query strings |
| `cross-origin-policy` | COOP, COEP, CORP headers |

## Output Formats

| Format     | Flag      | Description                                          |
|------------|-----------|------------------------------------------------------|
| Terminal   | `terminal`| Colored CLI output with severity breakdown           |
| JSON       | `json`    | Machine-readable findings for CI/CD integration      |
| HTML       | `html`    | Standalone HTML report                               |
| Bug Bounty | `bounty`  | HackerOne/Bugcrowd markdown format                   |
| SARIF      | `sarif`   | Static Analysis Results Interchange Format           |
| JUnit      | `junit`   | JUnit XML for CI test runners                        |

Additional exports with `--log-requests`:
- `--export-burp` -- Burp Suite XML for further manual testing
- `--export-har` -- HAR 1.2 archive

## AI Features

SecBot uses Claude AI for three stages:

1. **Planner** -- Analyzes recon data and recommends which active checks to run and in what order, based on detected tech stack and attack surface.
2. **Validator** -- Assesses each raw finding: real vulnerability or false positive? Processes in batches of 10.
3. **Reporter** -- Deduplicates, prioritizes, explains impact, and suggests fixes with code examples.

All three stages fall back to rule-based logic when `ANTHROPIC_API_KEY` is not set or when `--no-ai` is passed. The scanner produces useful results either way -- AI improves signal-to-noise ratio.

## Configuration File

SecBot looks for config in this order:
1. `.secbotrc.json`
2. `secbot.config.json`
3. `package.json` `"secbot"` key

CLI arguments override config file values. Example `.secbotrc.json`:

```json
{
  "target": "https://your-app.example.com",
  "profile": "standard",
  "format": "terminal,json",
  "scope": "*.example.com,-admin.example.com",
  "excludeChecks": ["traversal"],
  "maxPages": 50,
  "rateLimit": 5,
  "rateLimits": {
    "*.example.com": 10,
    "api.example.com": 3,
    "default": 5
  },
  "logRequests": true,
  "pluginDir": "./my-plugins"
}
```

## Environment Variables

```bash
ANTHROPIC_API_KEY=             # Required for AI features (optional -- fallback works without)
SECBOT_MODEL=                  # AI model override (default: claude-sonnet-4-5-20250929)
SECBOT_MAX_PAGES=50            # Max pages to crawl
SECBOT_TIMEOUT=30000           # Per-page timeout (ms)
```

## Plugins

SecBot supports custom check plugins. Place `.js`, `.mjs`, `.ts`, or `.mts` files in `~/.secbot/plugins/` (or set `pluginDir` in config). You can also install npm packages named `secbot-plugin-*`.

A plugin exports an object implementing the `ActiveCheck` interface:

```typescript
// ~/.secbot/plugins/my-check.ts
export default {
  name: 'my-custom-check',
  category: 'xss',
  async run(context, targets, config) {
    // Your check logic using Playwright BrowserContext
    return []; // Return RawFinding[]
  },
};
```

## Example Output

```
===============================================
  SecBot Security Scan Report
===============================================

Summary
  Target:     https://example.com
  Profile:    standard
  Pages:      12
  Duration:   34s
  Raw:        8 findings
  Actionable: 3 findings

Severity Breakdown
  CRITICAL  1
  HIGH      1
  MEDIUM    1

Findings

  [1] CRITICAL -- SQL Injection in "query" parameter
      URL:    https://example.com/api/v1/data?query=test
      OWASP:  A03:2021 Injection
      Impact: Attacker can read/modify/delete database contents.
      Fix:    Use parameterized queries instead of string concatenation.

  [2] HIGH -- Reflected XSS in "q" parameter
      URL:    https://example.com/search?q=test
      OWASP:  A03:2021 Injection
      Impact: Attacker can execute JavaScript in victim's browser.
      Fix:    HTML-encode all user input before rendering.

  [3] MEDIUM -- Missing Content-Security-Policy header
      URL:    https://example.com/
      OWASP:  A05:2021 Security Misconfiguration
      Impact: No CSP allows inline scripts and unrestricted resource loading.
      Fix:    Add Content-Security-Policy header with restrictive policy.

Top Priorities
  -> Fix SQL injection in /api/v1/data -- exploitable now
  -> Add output encoding for reflected XSS in /search
  -> Deploy Content-Security-Policy header site-wide
```

## Real-World Scan Results

SecBot was used to audit a Next.js + Supabase finance app across 4 iterative scans:

| Scan | Profile | Raw | Actionable | Highest | What Changed |
|------|---------|-----|------------|---------|--------------|
| Initial | standard | 5 | 3 | HIGH | Missing CSP, X-Frame-Options, security headers |
| After static headers | standard | 2 | 1 | MEDIUM | CSP had unsafe-inline/unsafe-eval |
| After nonce CSP | deep | 1 | 1 | LOW | X-Powered-By leaking framework |
| **Final** | **deep** | **0** | **0** | **Clean** | All checks passed |

The AI planner correctly skipped XSS/SQLi on the initial scan -- no forms or parameterized URLs on a Next.js SPA.

## Exit Codes

| Code | Meaning                                    |
|------|--------------------------------------------|
| `0`  | Scan complete, no high/critical findings   |
| `1`  | Scan complete, high or critical findings   |
| `2`  | Scan error (crash, invalid config, etc.)   |

Useful for CI gates: `secbot scan $URL --no-ai -f json && echo "Clean" || echo "Issues found"`

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev -- scan http://localhost:3000

# Build
npm run build

# Run tests
npm run test

# Watch mode
npm run test:watch

# Type check
npx tsc --noEmit
```

### Testing

Tests use Vitest with an Express-based vulnerable server fixture that has intentional security flaws for each check type. The test suite includes:

- **Unit tests** -- Deduplication, scope enforcement, payload structure, JSON parsing
- **Integration tests** -- Each active check against the vulnerable fixture server
- **False-positive regression** -- Checks produce zero findings against a properly secured endpoint

### Adding a New Check

1. Create `src/scanner/active/your-check.ts` implementing the `ActiveCheck` interface
2. Add payloads to `src/config/payloads/your-check.ts`
3. Register in `CHECK_REGISTRY` in `src/scanner/active/index.ts`
4. Add integration test in `test/integration/your-check.test.ts`

## Safety

SecBot is designed for authorized testing only:

- **Non-destructive** -- No data modification, no denial of service
- **Consent prompt** -- Warns before scanning external (non-localhost) targets
- **robots.txt** -- Respected by default (override with `--ignore-robots`)
- **Rate limiting** -- Configurable per-domain rate limits with adaptive backoff
- **Request logging** -- Full JSONL audit trail with `--log-requests`

## Built With

- [TypeScript](https://www.typescriptlang.org/) -- Strict mode
- [Playwright](https://playwright.dev/) -- Browser automation + HTTP interception
- [Anthropic SDK](https://docs.anthropic.com/) -- Claude AI for planning, validation, reporting
- [Commander](https://github.com/tj/commander.js/) -- CLI framework
- [Chalk](https://github.com/chalk/chalk) -- Terminal styling
- [Vitest](https://vitest.dev/) -- Unit + integration testing

## License

MIT

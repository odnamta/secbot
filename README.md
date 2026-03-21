# SecBot

**AI-powered web security scanner. One command, 43 active checks, bounty-ready reports.**

SecBot is a DAST (Dynamic Application Security Testing) CLI that combines Playwright browser automation with Claude AI to scan web applications for OWASP Top 10 vulnerabilities. It produces findings with CVSS 3.1 scores, curl reproduction commands, and screenshot evidence -- ready for bug bounty submission or CI/CD gating.

Every AI call has a rule-based fallback. The scanner works fully without an API key.

> **Version:** 1.0.0 -- Validated against 4 target tiers.

## Quick Start

```bash
# Install
npm install -g secbot-cli

# Scan a target you own
secbot scan https://your-app.example.com

# Quick scan, no AI
secbot scan https://your-app.example.com --profile quick --no-ai

# Deep scan with all report formats
secbot scan https://your-app.example.com --profile deep -f terminal,json,html,bounty,sarif

# Stealth scan through a proxy
secbot scan https://your-app.example.com --profile stealth --proxy http://127.0.0.1:8080

# Authenticated scan with session cookies
secbot scan https://your-app.example.com --auth-cookie "session=abc123"

# Interactive mode
secbot interactive https://your-app.example.com

# Autonomous bounty hunting
secbot hunt
```

## How It Works

SecBot runs a 9-phase pipeline:

```
Phase 0: Discovery       Route discovery (Next.js manifests, --urls file, JS bundle endpoint extraction)
Phase 1: Crawl            Playwright browser crawl + HTTP interception + SPA framework detection
Phase 2: Recon            Tech fingerprinting, WAF detection, endpoint mapping, CT subdomain enumeration
Phase 3: AI Plan          Claude analyzes recon, selects checks + payload context (tech-aware)
Phase 4: Passive Scan     Headers, cookies, info leaks, mixed content, cross-origin policy, JS secrets
Phase 5: Active Scan      Up to 43 checks, parallel where safe, 120s per-check timeout
  5a: Pre-dedup           Deduplicate raw findings before AI validation (saves tokens)
  5b: AI Response Analysis  Claude analyzes HTTP responses for subtle vulnerabilities
Phase 6: AI Validate      Claude validates each finding (real vuln or false positive?)
Phase 7: AI Report        Deduplicate, prioritize, CVSS score, explain, suggest fixes
Phase 8: Output           Terminal + JSON + HTML + bounty markdown + SARIF + JUnit
```

The browser is reused across crawl and active scan phases. Browser crashes are detected and reported in the check audit trail without aborting the scan.

## Feature Highlights

- **CVSS 3.1 scoring** on every finding with vector string
- **Auto-generated curl commands** for one-click reproduction
- **Screenshot evidence** for XSS and clickjacking findings (via Playwright)
- **15+ pre-filter heuristics** to eliminate false positives before AI validation (cross-origin isolation, same-org SRI, third-party cookies, CORS on error responses, framework-aware CSP, CDN header awareness, and more)
- **Auto-verify** pipeline: Playwright re-confirms 12 check types (XSS, SQLi, CORS, CSRF, open-redirect, CRLF, host-header, security-headers, SRI, cookie-flags, clickjacking, info-disclosure)
- **Stealth profile**: Gaussian-distributed delays, referrer chain simulation, UA rotation, human-like mouse/scroll behavior
- **Self-learning loop**: outcome tracking, FP memory, tech stack effectiveness profiles, WAF bypass payload stats -- all fed back into the planner
- **DNS pinning + private IP blocking** for SSRF self-defense
- **Proxy-aware** throughout: `--proxy` is respected by all checks
- **Per-check timeout** (120s) prevents stalls; check audit trail records status, duration, and errors
- **Source map exposure detection** with content analysis (sourcesContent, embedded secrets)
- **Adaptive payload encoding**: 8 WAF bypass strategies, context-aware payload prioritization from recon
- **Scan history + trend tracking**: per-target history, new/resolved finding diffs

## Security Checks

### Active Checks (43)

| # | Check | Category | Description |
|---|-------|----------|-------------|
| 1 | XSS | `xss` | Reflected (GET/POST/JSON), DOM-based, stored, blind, polyglot, HPP bypass |
| 2 | SQLi | `sqli` | Error-based, time-based blind, boolean-blind, UNION, NoSQL (GET/POST/JSON) |
| 3 | CORS | `cors-misconfiguration` | Origin reflection, null origin, wildcard-with-credentials, SameSite-aware |
| 4 | Open Redirect | `open-redirect` | 16 bypass payloads (backslash, @-sign, whitespace, encoding tricks) |
| 5 | Directory Traversal | `directory-traversal` | Path traversal via file-like parameters |
| 6 | SSRF | `ssrf` | Internal IP, cloud metadata (AWS/GCP/Azure/DO/Alibaba), DNS rebinding, OOB |
| 7 | SSTI | `ssti` | Server-side template injection (Jinja2, Twig, EJS, Freemarker, etc.) |
| 8 | Command Injection | `command-injection` | OS command injection (Unix + Windows payloads) |
| 9 | IDOR | `idor` | Insecure direct object reference (Jaccard + JSON key similarity, dual auth) |
| 10 | TLS | `tls` | Certificate validation, protocol version, cipher strength |
| 11 | SRI | `sri` | Missing Subresource Integrity on CDN scripts/styles |
| 12 | Info Disclosure | `info-disclosure` | Exposed .git, .env, source maps, robots.txt, backups, JS secrets (14 patterns), HTML comments |
| 13 | JS CVE | `js-cve` | Built-in vulnerability database (9 libraries, 16 CVEs) |
| 14 | CRLF Injection | `crlf-injection` | HTTP response splitting via header injection |
| 15 | Rate Limit | `rate-limit` | Brute-force protection testing on auth/API endpoints |
| 16 | JWT | `jwt` | None-algorithm bypass, weak secret detection, missing expiry, sensitive data |
| 17 | Race Condition | `race-condition` | TOCTOU concurrent request abuse on state-changing endpoints |
| 18 | GraphQL | `graphql` | Introspection, depth limits, batch queries, sensitive mutation discovery |
| 19 | Host Header | `host-header` | Direct Host, X-Forwarded-Host/Server/URL, cache poisoning |
| 20 | API Versioning | `api-versioning` | Probe older /api/v1/ endpoints for version-specific vulns |
| 21 | File Upload | `file-upload` | Shell/polyglot/MIME bypass |
| 22 | Business Logic | `business-logic` | Price manipulation, workflow bypass |
| 23 | WebSocket | `websocket` | Auth bypass, injection |
| 24 | Access Control | `broken-access-control` | Admin endpoint replay, method override, header bypass |
| 25 | Subdomain Takeover | `subdomain-takeover` | Dangling CNAME detection (14 service fingerprints) |
| 26 | OAuth | `oauth` | OAuth flow testing |
| 27 | Cache Poisoning | `cache-poisoning` | Web cache poisoning detection |
| 28 | CSRF | `csrf` | Missing token detection, cross-origin POST verification |
| 29 | Prototype Pollution | `prototype-pollution` | Query `__proto__`, JSON body, client-side |
| 30 | XXE | `xxe` | File read, parameter entity, XInclude |
| 31 | Insecure Deserialization | `insecure-deserialization` | Java, PHP, Python, Node, Ruby, .NET, YAML |
| 32 | Request Smuggling | `request-smuggling` | CL.TE, TE.CL, TE.TE timing-based detection |
| 33 | LDAP Injection | `ldap-injection` | Error-based + blind auth bypass (10 payloads, 17 error patterns) |
| 34 | User Enumeration | `info-disclosure` | Response discrepancy analysis (CWE-204) |
| 35 | Mass Assignment | `broken-access-control` | Over-posting probe (22 fields, CWE-915) |
| 36 | Content-Type Confusion | `csrf` | CSRF bypass via content-type manipulation (CWE-436) |
| 37 | Method Override | `broken-access-control` | HTTP method override ACL bypass (3 headers + 3 params) |
| 38 | Email Injection | `crlf-injection` | SMTP header injection (5 CRLF payloads, CWE-93) |
| 39 | BFLA | `broken-access-control` | Broken function-level authorization, 4-phase probing (API5:2023) |
| 40 | Clickjacking | `clickjacking` | Active iframe framing test with Playwright + screenshot evidence |
| 41 | Timing Attack | `info-disclosure` | Username enumeration via response timing side-channels (CWE-208) |
| 42 | Verbose Errors | `info-disclosure` | Stack traces, framework debug pages (CWE-209/215) |
| 43 | XPath Injection | `sqli` | Error-based + boolean-based (15 error patterns, CWE-643) |

**Meta check:** Vulnerability chain detection (7 rules: redirect+SSRF, XSS+CSRF, info+IDOR, CORS+XSS, JWT+rate-limit, and more).

### Passive Checks (6 categories)

| Category | What It Checks |
|----------|----------------|
| `security-headers` | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Permissions-Policy, Referrer-Policy |
| `cookie-flags` | HttpOnly, Secure, SameSite on session cookies (70+ third-party cookie patterns filtered) |
| `info-leakage` | Server/X-Powered-By headers, HTML comments, source maps, JS secrets |
| `mixed-content` | HTTP resources loaded on HTTPS pages |
| `sensitive-url-data` | Tokens, keys, passwords in URL query strings |
| `cross-origin-policy` | COOP, COEP, CORP headers |

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
  --scope <patterns>            Scope patterns: "*.example.com,-admin.example.com"
  --scope-file <path>           Bug bounty scope file (HackerOne/Bugcrowd format)
  --urls <file>                 File with URLs to scan (one per line)
  --subdomains                  Enable subdomain enumeration (DNS brute-force + CT logs)
  --log-requests                Log all HTTP requests (JSONL audit trail)
  --callback-url <url>          Callback URL for blind SSRF/OOB detection
  --callback-server <port>      Auto-start built-in OOB callback server
  --oob-wait <seconds>          Wait time for delayed OOB callbacks (default: 30)
  --rate-limit <n>              Maximum requests per second
  --exclude-checks <checks>     Comma-separated check names to skip (e.g. "traversal,cmdi")
  --baseline <file>             Baseline JSON -- only report new findings
  --proxy <url>                 HTTP or SOCKS5 proxy (e.g. http://host:8080 or socks5://host:1080)
  --export-burp                 Export traffic as Burp Suite XML (requires --log-requests)
  --export-har                  Export traffic as HAR 1.2 (requires --log-requests)
  --login-url <url>             Login page URL for credential-based auth
  --credentials <user:pass>     Username:password pair for login
  --credentials-file <path>     File containing credentials (user:pass on first line)
  --auth-cookie <cookies>       Pre-set cookies (name1=value1;name2=value2)
  --auth-header <header>        Inject auth header (e.g. "Authorization: Bearer token123")
  --auth-supabase <email:pass>  Authenticate via Supabase password grant
  -y, --yes                     Auto-confirm consent for CI/CD (required in non-TTY)
  --no-ai                       Skip AI, use rule-based fallback
  --verbose                     Debug logging

secbot hunt                     Autonomous bounty hunting (YAML program registry)
secbot outcome <id>             Record bounty outcome for self-learning
secbot interactive <url>        Interactive REPL mode
```

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Terminal | `terminal` | Colored CLI output with severity breakdown and top priorities |
| JSON | `json` | Machine-readable findings with CVSS scores, curl commands, evidence packs |
| HTML | `html` | Standalone dark-theme report with inline evidence and screenshots |
| Bug Bounty | `bounty` | HackerOne/Bugcrowd markdown with reproduction steps and impact analysis |
| SARIF | `sarif` | Static Analysis Results Interchange Format for GitHub/Azure DevOps |
| JUnit | `junit` | JUnit XML for CI test runners |

Additional exports with `--log-requests`:
- `--export-burp` -- Burp Suite XML for manual testing
- `--export-har` -- HAR 1.2 archive

## Scan Profiles

| Profile | Max Pages | Timeout | Concurrency | Delay | Use Case |
|---------|-----------|---------|-------------|-------|----------|
| `quick` | 5 | 15s | 3 | 50ms | Fast smoke test, CI gate |
| `standard` | 25 | 30s | 5 | 100ms | Default balanced scan |
| `deep` | 100 | 60s | 10 | 100ms | Thorough scan, all checks |
| `stealth` | 3 | 30s | 1 | 200-800ms | Gaussian delays, referrer chains, UA rotation, human simulation |

## AI Pipeline

SecBot uses Claude AI (Sonnet 4.6 by default) for three stages:

1. **Planner** -- Analyzes recon data, selects which of the 43 checks to run, and generates payload context from detected tech stack (database engine, template language, OS).
2. **Validator** -- Assesses each raw finding: real vulnerability or false positive? Processes in batches of 10 with tech-aware prompts.
3. **Reporter** -- Deduplicates, assigns CVSS 3.1 scores, explains impact, and generates fix suggestions with code examples.

All three stages fall back to rule-based logic when `ANTHROPIC_API_KEY` is not set or `--no-ai` is passed. The scanner produces useful results either way -- AI improves the signal-to-noise ratio.

## Configuration

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
SECBOT_MODEL=                  # AI model override (default: claude-sonnet-4-6)
SECBOT_CREDENTIALS=            # Credentials (user:pass) -- secure alternative to --credentials
SECBOT_MAX_PAGES=50            # Max pages to crawl
SECBOT_TIMEOUT=30000           # Per-page timeout (ms)
SECBOT_TOKEN_BUDGET=           # Max AI tokens per scan
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no high/critical findings |
| `1` | Scan complete, high or critical findings found |
| `2` | Scan error (crash, invalid config, etc.) |

CI gate example: `secbot scan $URL --no-ai -f json -y && echo "Clean" || echo "Issues found"`

## Plugins

Place `.js`, `.mjs`, `.ts`, or `.mts` files in `~/.secbot/plugins/` (or set `pluginDir` in config). You can also install npm packages named `secbot-plugin-*`.

A plugin exports an object implementing the `ActiveCheck` interface:

```typescript
export default {
  name: 'my-custom-check',
  category: 'xss',
  parallel: true, // safe to run concurrently?
  async run(context, targets, config) {
    return []; // Return RawFinding[]
  },
};
```

## Development

```bash
npm install               # Install dependencies
npm run dev -- scan <url> # Run in dev mode (tsx)
npm run build             # Build with tsc
npm run test              # Run tests (vitest)
npm run test:watch        # Watch mode
npx tsc --noEmit          # Type check
```

### Testing

Tests use Vitest with an Express-based vulnerable server fixture that has intentional security flaws for each check type:

- **Unit tests** -- Payload structure, dedup, scope enforcement, pre-filter heuristics, encoding strategies
- **Integration tests** -- Each active check against the vulnerable fixture server
- **False-positive regression** -- Checks produce zero findings against properly secured endpoints

### Adding a New Check

1. Create `src/scanner/active/your-check.ts` implementing the `ActiveCheck` interface
2. Add payloads to `src/config/payloads/your-check.ts` (if applicable)
3. Register in `CHECK_REGISTRY` in `src/scanner/active/index.ts`
4. Add integration test in `test/integration/your-check.test.ts`

## Safety

SecBot is designed for authorized testing only:

- **Non-destructive** -- No data modification, no denial of service
- **Consent prompt** -- Warns before scanning external (non-localhost) targets; `--yes` required in non-TTY
- **robots.txt** -- Respected by default (override with `--ignore-robots`)
- **Rate limiting** -- Configurable per-domain rate limits with adaptive backoff
- **Request logging** -- Full JSONL audit trail with `--log-requests`
- **DNS pinning** -- Private IP blocking prevents SSRF against the scanner's own network
- **Prompt injection sanitization** -- AI evidence fields are sanitized before prompt construction
- **Auth credential safety** -- Temp files written with 0o600 permissions, cleaned up after scan

## Built With

- [TypeScript](https://www.typescriptlang.org/) -- Strict mode, Node.js 20+
- [Playwright](https://playwright.dev/) -- Browser automation, HTTP interception, screenshot evidence
- [Anthropic SDK](https://docs.anthropic.com/) -- Claude AI for planning, validation, reporting
- [Commander](https://github.com/tj/commander.js/) -- CLI framework
- [Chalk](https://github.com/chalk/chalk) -- Terminal styling
- [Vitest](https://vitest.dev/) -- Unit + integration testing

## License

MIT

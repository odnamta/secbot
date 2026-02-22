# CLAUDE.md — SecBot

## Project Overview

**SecBot** is an AI-powered security testing CLI tool — "Playwright for security."
Developer-friendly tool that scans web apps for OWASP Top 10 vulnerabilities with a single command. Claude AI drives the entire pipeline — planning attacks, validating findings, and writing reports.

## Status
- Version: v0.7.0
- 11 active check types + 6 passive check categories
- 907 tests (unit + integration + false-positive regression)
- AI prompt injection sanitization enabled

## Tech Stack
- **Language:** TypeScript 5 (strict mode)
- **Runtime:** Node.js 20+
- **CLI:** commander
- **Browser automation:** Playwright
- **AI:** Anthropic SDK (Claude Sonnet 4.5) — plans, validates, reports
- **Output:** chalk (terminal), JSON, HTML, bug bounty markdown, SARIF, JUnit
- **Testing:** Vitest (unit + integration), Express vulnerable server fixture

## Architecture

```
Phase 0: Discovery     → Route discovery (Next.js build manifest, --urls file)
Phase 1: Crawl         → Playwright browser (crawl + intercept traffic, SPA framework detection)
Phase 2: Recon         → Tech fingerprinting, enhanced WAF detection, endpoint mapping
Phase 3: AI Plan       → Claude analyzes recon, recommends which checks to run
Phase 4: Passive Scan  → Headers, cookies, info leaks, mixed content, cross-origin policy, sensitive URL data
Phase 5: Active Scan   → AI-selected checks (11 types — see CHECK_REGISTRY)
  ↓ Pre-dedup          → Deduplicate raw findings before AI validation (save tokens)
Phase 6: AI Validate   → Claude validates each finding (real vuln or false positive?)
Phase 7: AI Report     → Claude deduplicates, prioritizes, explains, suggests fixes
Phase 8: Output        → Terminal + JSON + HTML + bug bounty markdown + SARIF + JUnit
```

Browser is reused across phases (crawl -> active) instead of launching twice.
Every AI call has a rule-based fallback — tool works fully without an API key.
Exit codes: 0 = clean, 1 = findings (high/critical), 2 = error.

## Key Files
```
src/
  index.ts                    # CLI entry — 9-phase pipeline orchestrator (Phase 0-8)
  scanner/
    browser.ts                # Playwright crawling + HTTP interception + SPA hydration
    passive.ts                # Header/cookie/info-leak/cross-origin/sensitive-URL checks
    recon.ts                  # Tech fingerprinting, WAF detection + enhanced fingerprinting
    waf-fingerprint.ts        # Enhanced WAF fingerprinting with bypass recommendations
    types.ts                  # All TypeScript types
    screenshot.ts             # Page/finding screenshot capture
    middleware.ts             # Request/response middleware pipeline (WAF detector, CSRF, logger)
    discovery/
      index.ts                # Route discovery orchestrator
      types.ts                # DiscoveredRoute type
      nextjs-extractor.ts     # Extract routes from Next.js build manifest
      url-file-loader.ts      # Load URLs from --urls file
      framework-detector.ts   # SPA framework detection + hydration wait
      spa-crawler.ts          # SPA-aware crawling helpers
    auth/
      authenticator.ts        # Credential-based authentication
      login-detector.ts       # Login page heuristic detection
      session-manager.ts      # Session refresh + expiry detection
    active/
      index.ts                # ActiveCheck interface, CHECK_REGISTRY, runner, plugin loader
      xss.ts                  # XSS (reflected, DOM, stored, blind + polyglot + HPP bypass)
      sqli.ts                 # SQLi (error-based, time-based blind, boolean-blind, union, NoSQL)
      cors.ts                 # CORS misconfiguration check
      redirect.ts             # Open redirect check
      traversal.ts            # Directory traversal check
      ssrf.ts                 # SSRF + DNS canary integration
      ssti.ts                 # Server-Side Template Injection check
      cmdi.ts                 # OS Command Injection check
      idor.ts                 # IDOR check (Jaccard + JSON key similarity)
      tls.ts                  # TLS/Crypto security check
      sri.ts                  # Subresource Integrity check
    oob/
      callback-server.ts      # OOB HTTP callback server (binds 127.0.0.1)
      blind-payloads.ts       # Blind XSS/SQLi/SSRF payload generators
      dns-canary.ts           # DNS canary subdomain generator
      delayed-detection.ts    # Delayed OOB detection wait
  ai/
    client.ts                 # Anthropic client + askClaude() + JSON parser + token budget
    planner.ts                # AI analyzes recon -> AttackPlan
    validator.ts              # AI validates findings -> ValidatedFinding[]
    reporter.ts               # AI generates final report -> InterpretedFinding[]
    fallback.ts               # Rule-based fallback when AI unavailable
    prompts.ts                # Prompt builder with injection sanitization
  reporter/
    terminal.ts               # Chalk-colored terminal output
    json.ts                   # JSON report
    html.ts                   # HTML report (standalone dark theme)
    bounty.ts                 # Bug bounty markdown (HackerOne/Bugcrowd format)
    bounty-export.ts          # Platform-specific bounty formatting
  config/
    defaults.ts               # Scan profiles (quick/standard/deep/stealth)
    file.ts                   # .secbotrc.json config file loader
    payloads/
      xss.ts                  # XSS payloads (~40 payloads, XSSPayload interface)
      sqli.ts                 # SQLi payloads + error patterns (SLEEP(5) for blind)
      redirect.ts             # Open redirect payloads
      traversal.ts            # Directory traversal payloads
      ssrf.ts                 # SSRF payloads (callback URLs, internal IPs)
      ssti.ts                 # SSTI payloads (large multiplications for uniqueness)
      cmdi.ts                 # Command injection payloads (Unix + Windows)
      index.ts                # Re-exports
  plugins/
    loader.ts                 # Plugin discovery + loading (~/.secbot/plugins/ + npm)
    types.ts                  # Plugin interface types
  utils/
    logger.ts                 # Structured logging (debug/info/warn/error)
    scope.ts                  # Scope enforcement (glob pattern matching)
    request-logger.ts         # JSONL request logging for accountability
    dedup.ts                  # Pre-deduplication engine
    shared.ts                 # Shared utilities (delay, normalizeUrl, etc.)
    stealth.ts                # User-agent rotation + request jitter
    rate-limiter.ts           # Token bucket rate limiter with backoff
    domain-rate-limiter.ts    # Per-domain rate limiting
    ai-cache.ts               # SHA-256 keyed AI response cache
    baseline.ts               # Baseline diff for incremental scanning
    cli-validation.ts         # CLI option validation
    payload-mutator.ts        # Encoding strategies for WAF bypass
    param-pollution.ts        # HTTP Parameter Pollution variants
    polyglot-payloads.ts      # Polyglot XSS/SQLi payloads
  interactive/
    repl.ts                   # Interactive REPL mode
test/
  setup.ts                    # Vitest global setup
  fixtures/
    vulnerable-server.ts      # Express server with intentional vulns
    vulnerable-server.test.ts # Fixture self-test
  unit/                       # Unit tests (dedup, discovery, JSON parser, passive, scope, TLS, payloads)
  integration/                # Integration tests (all 11 checks + full-scan + false-positive regression)
```

## Commands
```bash
npm run dev                   # Run in dev mode (tsx)
npm run build                 # Build with tsc
npm run test                  # Run tests (vitest)
npm run test:watch            # Run tests in watch mode
npx secbot scan <url>         # Run a scan
```

## CLI Options
```bash
secbot scan <url>
  -p, --profile <profile>     # quick | standard | deep | stealth (default: standard)
  -a, --auth <path>           # Playwright storage state JSON for auth scanning
  -f, --format <formats>      # terminal,json,html,bounty (comma-separated)
  -o, --output <path>         # Output directory (default: ./secbot-reports)
  --max-pages <n>             # Max pages to crawl
  --timeout <ms>              # Per-page timeout
  --ignore-robots             # Ignore robots.txt
  --scope <patterns>          # Scope: "*.example.com,-admin.example.com"
  --urls <file>               # File with URLs to scan (one per line)
  --log-requests              # Log all HTTP requests (JSONL)
  --idor-alt-auth <path>      # Second user auth state for IDOR testing
  --credentials <user:pass>   # Login credentials (prefer --credentials-file or SECBOT_CREDENTIALS)
  --credentials-file <path>   # File containing credentials (user:pass on first line)
  --login-url <url>           # Login page URL for credential auth
  --proxy <url>               # HTTP proxy URL
  --callback-server <port>    # OOB callback server port
  --baseline <path>           # Baseline JSON for incremental scanning
  --exclude-checks <names>    # Comma-separated check names to skip
  --no-ai                     # Skip AI, use rule-based fallback
  --verbose                   # Debug logging
```

## Environment Variables
```
ANTHROPIC_API_KEY=            # Required for AI features (optional — fallback works without)
SECBOT_MODEL=                 # AI model override (default: claude-sonnet-4-5-20250929)
SECBOT_CREDENTIALS=           # Credentials (user:pass) — secure alternative to --credentials
SECBOT_MAX_PAGES=50           # Max pages to crawl
SECBOT_TIMEOUT=30000          # Per-page timeout (ms)
SECBOT_TOKEN_BUDGET=          # Max AI tokens per scan
```

## CheckCategory (17 types)

**Passive (6):** `security-headers`, `cookie-flags`, `info-leakage`, `mixed-content`, `sensitive-url-data`, `cross-origin-policy`

**Active (11):** `xss`, `sqli`, `open-redirect`, `cors-misconfiguration`, `directory-traversal`, `ssrf`, `ssti`, `command-injection`, `idor`, `tls`, `sri`

## Rules
- NEVER perform destructive actions (no data modification, no DoS)
- Always show consent/disclaimer before scanning external targets
- Respect robots.txt by default (override with --ignore-robots)
- Rate limit requests (max 10 concurrent, 100ms delay between)
- Target <10 actionable findings per scan (AI must filter noise)
- Scanner must be modular — each check type is a separate file in `active/`
- New checks: implement the `ActiveCheck` interface, add to `CHECK_REGISTRY` in `active/index.ts`
- Pre-dedup runs before AI validation to save tokens
- Exit codes: 0 = clean, 1 = findings (high/critical), 2 = error
- AI evidence fields sanitized against prompt injection
- Auth temp files written with 0o600 permissions and cleaned up after scan

## Testing Target
First scan target: `https://atmando-finance.vercel.app` (our own app)

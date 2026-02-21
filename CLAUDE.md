# CLAUDE.md — SecBot

## Project Overview

**SecBot** is an AI-powered security testing CLI tool — "Playwright for security."
Developer-friendly tool that scans web apps for OWASP Top 10 vulnerabilities with a single command. Claude AI drives the entire pipeline — planning attacks, validating findings, and writing reports.

## Status
- Version: v1.0.0
- Phase 1 complete — developer security tool ready
- 12 active check types + 6 passive check categories
- 160+ tests (unit + integration)

## Tech Stack
- **Language:** TypeScript 5 (strict mode)
- **Runtime:** Node.js 20+
- **CLI:** commander
- **Browser automation:** Playwright
- **AI:** Anthropic SDK (Claude Sonnet 4.5) — plans, validates, reports
- **Output:** chalk (terminal), JSON, HTML, bug bounty markdown
- **Testing:** Vitest (unit + integration), Express vulnerable server fixture

## Architecture

```
Phase 0: Discovery     → Route discovery (Next.js build manifest, --urls file)
Phase 1: Crawl         → Playwright browser (crawl + intercept traffic, seed discovered routes)
Phase 2: Recon         → Tech fingerprinting, WAF detection, endpoint mapping
Phase 3: AI Plan       → Claude analyzes recon, recommends which checks to run
Phase 4: Passive Scan  → Headers, cookies, info leaks, mixed content, cross-origin policy, sensitive URL data
Phase 5: Active Scan   → AI-selected checks (12 types — see CHECK_REGISTRY)
  ↓ Pre-dedup          → Deduplicate raw findings before AI validation (save tokens)
Phase 6: AI Validate   → Claude validates each finding (real vuln or false positive?)
Phase 7: AI Report     → Claude deduplicates, prioritizes, explains, suggests fixes
Phase 8: Output        → Terminal + JSON + HTML + bug bounty markdown
```

Browser is reused across phases (crawl -> active) instead of launching twice.
Every AI call has a rule-based fallback — tool works fully without an API key.
Exit codes: 0 = clean, 1 = findings (high/critical), 2 = error.

## Key Files
```
src/
  index.ts                    # CLI entry — 9-phase pipeline orchestrator (Phase 0-8)
  scanner/
    browser.ts                # Playwright crawling + HTTP interception, browser reuse
    passive.ts                # Header/cookie/info-leak/cross-origin/sensitive-URL checks
    recon.ts                  # Tech fingerprinting, WAF/framework detection, endpoint mapping
    types.ts                  # All TypeScript types
    discovery/
      index.ts                # Route discovery orchestrator
      types.ts                # DiscoveredRoute type
      nextjs-extractor.ts     # Extract routes from Next.js build manifest
      url-file-loader.ts      # Load URLs from --urls file
    active/
      index.ts                # ActiveCheck interface, CHECK_REGISTRY, runner (AI picks checks)
      xss.ts                  # XSS check (reflected, DOM, stored — form + URL param injection)
      sqli.ts                 # SQL injection check (error-based, blind, union)
      cors.ts                 # CORS misconfiguration check
      redirect.ts             # Open redirect check
      traversal.ts            # Directory traversal check
      ssrf.ts                 # Server-Side Request Forgery check
      ssti.ts                 # Server-Side Template Injection check
      cmdi.ts                 # OS Command Injection check
      idor.ts                 # Insecure Direct Object Reference check
      tls.ts                  # TLS/Crypto security check
      sri.ts                  # Subresource Integrity check
  ai/
    client.ts                 # Shared Anthropic client + askClaude() + JSON parser
    planner.ts                # AI analyzes recon -> AttackPlan
    validator.ts              # AI validates findings -> ValidatedFinding[]
    reporter.ts               # AI generates final report -> InterpretedFinding[]
    fallback.ts               # Rule-based fallback when AI unavailable
    prompts.ts                # System/user prompts for planner, validator, reporter
  reporter/
    terminal.ts               # Chalk-colored terminal output
    json.ts                   # JSON report
    html.ts                   # HTML report
    bounty.ts                 # Bug bounty markdown (HackerOne/Bugcrowd format)
  config/
    defaults.ts               # Scan profiles (quick/standard/deep)
    payloads.ts               # Re-exports all payloads
    payloads/
      xss.ts                  # XSS payloads (~40 payloads, XSSPayload interface)
      sqli.ts                 # SQLi payloads + error patterns
      redirect.ts             # Open redirect payloads
      traversal.ts            # Directory traversal payloads
      ssrf.ts                 # SSRF payloads (callback URLs, internal IPs)
      ssti.ts                 # SSTI payloads (Jinja2, Twig, EJS, etc.)
      cmdi.ts                 # Command injection payloads (Unix + Windows)
      index.ts                # Re-exports
  utils/
    logger.ts                 # Structured logging (debug/info/warn/error)
    scope.ts                  # Scope enforcement (glob pattern matching)
    request-logger.ts         # JSONL request logging for accountability
    dedup.ts                  # Pre-deduplication engine (category+URL+evidence hash)
    shared.ts                 # Shared utilities
test/
  setup.ts                    # Vitest global setup
  fixtures/
    vulnerable-server.ts      # Express server with intentional vulns for integration tests
    vulnerable-server.test.ts # Fixture self-test
  unit/
    dedup.test.ts             # Deduplication engine tests
    discovery.test.ts         # Route discovery tests
    json-parser.test.ts       # AI JSON response parser tests
    passive.test.ts           # Passive check tests
    scope.test.ts             # Scope enforcement tests
    tls.test.ts               # TLS check tests
    xss-payloads.test.ts      # XSS payload structure tests
  integration/
    full-scan.test.ts         # Full pipeline integration test
    xss.test.ts               # XSS scanner integration test
    sqli.test.ts              # SQLi scanner integration test
    cors.test.ts              # CORS scanner integration test
    redirect.test.ts          # Redirect scanner integration test
    traversal.test.ts         # Traversal scanner integration test
    ssrf.test.ts              # SSRF scanner integration test
    ssti.test.ts              # SSTI scanner integration test
    cmdi.test.ts              # Command injection scanner integration test
    idor.test.ts              # IDOR scanner integration test
    sri.test.ts               # SRI scanner integration test
```

## Commands
```bash
npm run dev                   # Run in dev mode (tsx)
npm run build                 # Build with tsup
npm run test                  # Run tests (vitest)
npm run test:watch            # Run tests in watch mode
npx secbot scan <url>         # Run a scan
```

## CLI Options
```bash
secbot scan <url>
  -p, --profile <profile>     # quick | standard | deep (default: standard)
  -a, --auth <path>           # Playwright storage state JSON for auth scanning
  -f, --format <formats>      # terminal,json,html,bounty (comma-separated)
  -o, --output <path>         # Output directory (default: ./secbot-reports)
  --max-pages <n>             # Max pages to crawl
  --timeout <ms>              # Per-page timeout
  --ignore-robots             # Ignore robots.txt
  --scope <patterns>          # Scope: "*.example.com,-admin.example.com"
  --urls <file>               # File with URLs to scan (one per line)
  --log-requests              # Log all HTTP requests (JSONL)
  --no-ai                     # Skip AI, use rule-based fallback
  --verbose                   # Debug logging
```

## Environment Variables
```
ANTHROPIC_API_KEY=            # Required for AI features (optional — fallback works without)
SECBOT_MAX_PAGES=50           # Max pages to crawl
SECBOT_TIMEOUT=30000          # Per-page timeout (ms)
```

## CheckCategory (17 types)

**Passive (6):** `security-headers`, `cookie-flags`, `info-leakage`, `mixed-content`, `sensitive-url-data`, `cross-origin-policy`

**Active (11):** `xss`, `sqli`, `open-redirect`, `cors-misconfiguration`, `directory-traversal`, `ssrf`, `ssti`, `command-injection`, `idor`, `tls`, `sri`

## AI Pipeline (3 calls per scan)
1. **Planner** — analyzes recon data, recommends which active checks to run and in what order
2. **Validator** — assesses each finding as real vulnerability or false positive (batches of 10)
3. **Reporter** — deduplicates, prioritizes, explains, suggests fixes with code examples

All three fall back to rule-based logic if `ANTHROPIC_API_KEY` is not set.

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
- Core scanner will be open-sourced; AI layer is the paid differentiator

## Testing Target
First scan target: `https://atmando-finance.vercel.app` (our own app)

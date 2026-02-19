# CLAUDE.md — SecBot

## Project Overview

**SecBot** is an AI-powered security testing CLI tool — "Playwright for security."
Developer-friendly tool that scans web apps for OWASP Top 10 vulnerabilities with a single command. Claude AI drives the entire pipeline — planning attacks, validating findings, and writing reports.

## Status
- Version: v0.0.1
- Phase: 1 (CLI + OWASP Top 10 + AI-driven pipeline)

## Tech Stack
- **Language:** TypeScript 5 (strict mode)
- **Runtime:** Node.js 20+
- **CLI:** commander
- **Browser automation:** Playwright
- **AI:** Anthropic SDK (Claude Sonnet 4.5) — plans, validates, reports
- **Output:** chalk (terminal), JSON, HTML, bug bounty markdown

## Architecture

```
Phase 1: Crawl          → Playwright browser (crawl + intercept traffic)
Phase 2: Recon          → Tech fingerprinting, WAF detection, endpoint mapping
Phase 3: AI Plan        → Claude analyzes recon, recommends which checks to run
Phase 4: Passive Scan   → Headers, cookies, info leaks, mixed content
Phase 5: Active Scan    → AI-selected checks (XSS, SQLi, CORS, redirect, traversal)
Phase 6: AI Validate    → Claude validates each finding (real vuln or false positive?)
Phase 7: AI Report      → Claude deduplicates, prioritizes, explains, suggests fixes
Phase 8: Output         → Terminal + JSON + HTML + bug bounty markdown
```

Browser is reused across phases (crawl → active) instead of launching twice.
Every AI call has a rule-based fallback — tool works fully without an API key.

## Key Files
```
src/
  index.ts                    # CLI entry — 8-phase pipeline orchestrator
  scanner/
    browser.ts                # Playwright crawling + HTTP interception, browser reuse
    passive.ts                # Header/cookie/info-leak checks
    recon.ts                  # Tech fingerprinting, WAF/framework detection, endpoint mapping
    active/
      index.ts                # Check registry + runner (AI picks checks from plan)
      xss.ts                  # XSS check (form + URL param injection)
      sqli.ts                 # SQL injection check (form injection)
      cors.ts                 # CORS misconfiguration check
      redirect.ts             # Open redirect check
      traversal.ts            # Directory traversal check
    types.ts                  # All TypeScript types
  ai/
    client.ts                 # Shared Anthropic client + askClaude() + JSON parser
    planner.ts                # AI analyzes recon → AttackPlan
    validator.ts              # AI validates findings → ValidatedFinding[]
    reporter.ts               # AI generates final report → InterpretedFinding[]
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
      xss.ts                  # XSS payloads + markers
      sqli.ts                 # SQLi payloads + error patterns
      redirect.ts             # Open redirect payloads
      traversal.ts            # Directory traversal payloads
      index.ts                # Re-exports
  utils/
    logger.ts                 # Structured logging (debug/info/warn/error)
    scope.ts                  # Scope enforcement (glob pattern matching)
    request-logger.ts         # JSONL request logging for accountability
```

## Commands
```bash
npm run dev                   # Run in dev mode (tsx)
npm run build                 # Build with tsup
npm run test                  # Run tests (vitest)
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
- New checks: create file in `active/`, add to `CHECK_REGISTRY` in `active/index.ts`
- Core scanner will be open-sourced; AI layer is the paid differentiator

## Testing Target
First scan target: `https://atmando-finance.vercel.app` (our own app)

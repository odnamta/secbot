# CLAUDE.md — SecBot

## Project Overview

**SecBot** is an AI-powered security testing CLI tool — "Playwright for security."
Developer-friendly tool that scans web apps for OWASP Top 10 vulnerabilities with a single command and uses Claude AI to interpret, deduplicate, and explain findings.

## Status
- Version: v0.0.0 (initializing)
- Phase: 1 (CLI + OWASP Top 10 + LLM interpretation)

## Tech Stack
- **Language:** TypeScript 5 (strict mode)
- **Runtime:** Node.js 20+
- **CLI:** commander
- **Browser automation:** Playwright
- **AI:** Anthropic SDK (Claude Sonnet 4.5)
- **Output:** chalk (terminal), JSON, HTML reports

## Architecture

```
CLI → Playwright browser (crawl + intercept traffic)
    → Passive scanner (headers, cookies, info leaks)
    → Active scanner (XSS, SQLi, CORS, redirects)
    → LLM interpreter (dedupe, prioritize, explain, suggest fixes)
    → Reporter (terminal + JSON + HTML)
```

## Key Files
```
src/
  index.ts              # CLI entry (commander)
  scanner/
    browser.ts          # Playwright crawling + HTTP interception
    passive.ts          # Header/cookie/info-leak checks
    active.ts           # XSS/SQLi/CORS probes
    types.ts            # RawFinding, ScanConfig, ScanResult
  ai/
    interpreter.ts      # Claude-powered result interpretation
    prompts.ts          # LLM prompts
  reporter/
    terminal.ts         # Terminal output
    json.ts             # JSON report
    html.ts             # HTML report
  config/
    defaults.ts         # Scan profiles (quick/standard/deep)
    payloads.ts         # Test payloads
```

## Commands
```bash
npm run dev             # Run in dev mode (tsx)
npm run build           # Build with tsup
npm run test            # Run tests (vitest)
npx secbot scan <url>   # Run a scan
```

## Environment Variables
```
ANTHROPIC_API_KEY=      # Required for AI interpretation
SECBOT_MAX_PAGES=50     # Max pages to crawl
SECBOT_TIMEOUT=30000    # Per-page timeout (ms)
```

## Rules
- NEVER perform destructive actions (no data modification, no DoS)
- Always show consent/disclaimer before scanning external targets
- Respect robots.txt by default (override with --ignore-robots)
- Rate limit requests (max 10 concurrent, 100ms delay between)
- Target <10 actionable findings per scan (AI must filter noise)
- Scanner must be modular — each check type is a separate file
- Core scanner will be open-sourced; AI layer is the paid differentiator

## Testing Target
First scan target: `https://atmando-finance.vercel.app` (our own app)

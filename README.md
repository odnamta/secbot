# SecBot

AI-powered security testing CLI — "Playwright for security."

Scan web apps for OWASP Top 10 vulnerabilities with a single command. Claude AI drives the entire pipeline — planning attacks, validating findings, and writing reports.

## Quick Start

```bash
npm install
npx secbot scan https://your-app.com
```

## How It Works

```
Phase 1: Crawl        Playwright browser crawls target, intercepts all HTTP traffic
Phase 2: Recon        Tech fingerprinting, WAF detection, framework detection
Phase 3: AI Plan      Claude analyzes recon, picks which checks to run
Phase 4: Passive      Headers, cookies, info leaks, mixed content
Phase 5: Active       AI-selected checks: XSS, SQLi, CORS, redirect, traversal
Phase 6: AI Validate  Claude validates each finding — real vuln or false positive?
Phase 7: AI Report    Claude deduplicates, prioritizes, explains, suggests fixes
Phase 8: Output       Terminal + JSON + HTML + bug bounty markdown
```

Works without an API key too — every AI call has a rule-based fallback.

## CLI Usage

```bash
# Standard scan
secbot scan https://your-app.com

# Quick scan (5 pages, headers + cookies only)
secbot scan https://your-app.com --profile quick

# Deep scan (100 pages, all checks)
secbot scan https://your-app.com --profile deep

# Multiple output formats
secbot scan https://your-app.com --format terminal,json,html,bounty

# Authenticated scan
secbot scan https://your-app.com --auth ./storage-state.json

# Bug bounty mode with scope + request logging
secbot scan https://target.com --scope "*.target.com,-admin.target.com" --log-requests --format bounty

# No AI (rule-based fallback)
secbot scan https://your-app.com --no-ai
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --profile` | `quick` / `standard` / `deep` | `standard` |
| `-f, --format` | `terminal,json,html,bounty` | `terminal` |
| `-o, --output` | Output directory | `./secbot-reports` |
| `-a, --auth` | Playwright storage state for auth | — |
| `--scope` | Scope patterns: `"*.example.com,-admin.example.com"` | same-origin |
| `--log-requests` | Log all HTTP requests to JSONL | off |
| `--max-pages` | Max pages to crawl | profile-dependent |
| `--timeout` | Per-page timeout (ms) | profile-dependent |
| `--ignore-robots` | Ignore robots.txt | off |
| `--no-ai` | Skip AI, use rule-based fallback | off |
| `--verbose` | Debug logging | off |

## Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...   # Required for AI features (optional — fallback works without)
SECBOT_MAX_PAGES=50            # Override max pages
SECBOT_TIMEOUT=30000           # Override timeout (ms)
```

## Real-World Scan Results

SecBot was used to audit [atmando-finance.vercel.app](https://atmando-finance.vercel.app) (a Next.js + Supabase finance app). Here's the progression:

### Scan 1 — Initial (standard profile)

```
Raw: 5 findings → Actionable: 3 findings

#1 [HIGH]   Missing Content Security Policy (CSP)
#2 [MEDIUM] Missing Clickjacking Protection (X-Frame-Options)
#3 [LOW]    Missing Security Headers Bundle (XCTO, Referrer-Policy, Permissions-Policy)
```

AI recommended 3 checks (cors, traversal, redirect) and **skipped XSS/SQLi** — no forms or parameterized URLs on a Next.js SPA.

**Fix applied:** Added all 5 security headers via `next.config.ts`.

### Scan 2 — After static headers (standard profile)

```
Raw: 2 findings → Actionable: 1 finding

#1 [MEDIUM] CSP Weakened by unsafe-inline and unsafe-eval
```

Headers were present but CSP contained `'unsafe-inline'` and `'unsafe-eval'` for Next.js compatibility.

**Fix applied:** Implemented nonce-based CSP via middleware — per-request nonce with `'strict-dynamic'`, no unsafe directives.

### Scan 3 — After nonce-based CSP (deep profile)

```
Raw: 1 finding → Actionable: 1 finding

#1 [LOW] Information Disclosure via X-Powered-By Header
```

All 5 checks ran, only found `X-Powered-By: Next.js` leaking the framework.

**Fix applied:** `poweredByHeader: false` in `next.config.ts`.

### Scan 4 — Final (deep profile)

```
Raw: 0 findings → Actionable: 0 findings

No actionable vulnerabilities found!
```

Clean deep scan — all 5 checks (cors, traversal, xss, redirect, sqli) passed.

### Summary

| Scan | Profile | Raw | Actionable | Highest |
|------|---------|-----|------------|---------|
| Initial | standard | 5 | 3 | HIGH |
| After static headers | standard | 2 | 1 | MEDIUM |
| After nonce CSP | deep | 1 | 1 | LOW |
| **Final** | **deep** | **0** | **0** | **None** |

## Tech Stack

- **TypeScript** — strict mode
- **Playwright** — browser automation + HTTP interception
- **Anthropic SDK** — Claude Sonnet 4.5 for planning, validation, reporting
- **commander** — CLI framework
- **chalk** — terminal colors

## License

MIT

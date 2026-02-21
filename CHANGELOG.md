# Changelog

All notable changes to SecBot are documented here.

## [0.6.0] - 2026-02-21

### Added
- **12 security check types:** XSS (reflected + DOM + stored), SQLi (error + blind + union + NoSQL), CORS, open redirect, directory traversal, SSRF, SSTI, command injection, IDOR (dual-auth), TLS/crypto, SRI, deep security headers
- **Route discovery:** Next.js sitemap/manifest extraction, common path probing, `--urls` file flag
- **Pre-deduplication engine:** Groups identical findings before AI validation, saves 80%+ tokens
- **AI pipeline:** Plan → Validate → Report with rule-based fallback (`--no-ai`)
- **CI/CD exit codes:** 0 = clean, 1 = HIGH/CRITICAL, 2 = scan error
- **SIGINT/SIGTERM cleanup:** Graceful browser shutdown on interrupt
- **Test infrastructure:** Vulnerable Express test server, 160 tests (unit + integration)
- **`--idor-alt-auth` flag:** Dual-session IDOR testing (single-session removed as false-positive-prone)
- **`SECBOT_MODEL` env var:** Configurable AI model (default: claude-sonnet-4-5-20250929)

### Fixed
- IDOR check now requires dual auth sessions — eliminates guaranteed false positives
- SQLi blind detection thresholds raised (3000ms timing, 35% boolean) — reduces false positives on dynamic pages
- Command injection test fixture uses real `execSync` instead of string reflection
- Extracted duplicated code: `measureResponseTime`, `normalizeUrl`, `delay` into `utils/shared.ts`
- Removed `secbot-reports/` from git tracking

### Changed
- Version downgraded from 1.0.0 to 0.6.0 — honest assessment of production readiness

## [0.1.0] - 2026-02-19

### Added
- Initial MVP: 8-phase scan pipeline with Playwright browser automation
- 5 check types: XSS, SQLi, CORS, open redirect, directory traversal
- Claude AI integration for attack planning, finding validation, and report generation
- Terminal, JSON, HTML, and bug bounty report formats
- Request logging for accountability (`--log-requests`)
- Scope enforcement with glob patterns
- robots.txt respect (opt-out with `--ignore-robots`)

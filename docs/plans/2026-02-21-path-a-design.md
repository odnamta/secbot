# SecBot Path A Design — Developer Security Tool

**Date:** 2026-02-21
**Status:** Approved
**Target:** Internal tool for Dio's Next.js + Supabase apps
**Approach:** Foundation-first (tests + infra, then improve checks, then add checks)
**Version target:** v1.0.0

---

## Decisions

- **Target user:** Dio + Gama team (internal). Open source considered later.
- **Usage:** Manual CLI now, CI/CD-ready output (exit codes + JSON).
- **Crawling:** Next.js route extraction + `--urls` fallback. Full SPA crawling deferred to Path B.
- **Check scope:** Go wide — fix existing 5 + add 7 new OWASP categories.
- **Testing:** Unit + integration tests with local vulnerable test server.
- **Execution order:** Foundation-first. Tests and infra before new features.

---

## Section 1: Infrastructure & Quality Foundation

### 1a. Test harness
- Local vulnerable test server (`test/fixtures/vulnerable-server.ts`) — Express app with intentional vulns: reflected XSS, SQLi-like errors, missing headers, open CORS, open redirects, path traversal, SSRF endpoints, SSTI templates, command injection params.
- Unit tests for pure functions: `parseJsonResponse`, `isInScope`, payload detection, severity ordering, dedup logic.
- Integration tests: scan local test server, assert findings match planted vulns, no false positives on safe endpoints.

### 1b. Pre-deduplication engine
- Between Phase 5 and 6: group identical findings by `(type, severity, title)`.
- Collapse duplicates into one finding with `affectedUrls: string[]`.
- Saves 80%+ AI token cost.

### 1c. Infrastructure fixes
- **SIGINT handler:** Catch SIGINT/SIGTERM, call `closeBrowser()`, write partial results.
- **Version from package.json:** Dynamic import, remove hardcoded strings.
- **Dead code removal:** Unused `randomUUID`, duplicate `severityOrder`, dead type categories.
- **Debug logging:** Replace silent `catch {}` with `logger.debug()`.
- **CI/CD exit codes:** 0 = clean, 1 = HIGH/CRITICAL, 2 = scan error.

---

## Section 2: Improve Existing Checks

### 2a. XSS
- DOM XSS detection via URL fragment injection + sink monkey-patching.
- Basic stored XSS: re-crawl pages after injection to detect persistence.
- Fix marker-payload coupling (embed markers in payloads directly).
- Expand payloads: 11 -> ~40 (encoding variants, event handlers, template literals).

### 2b. SQLi
- Boolean-based blind: compare `OR 1=1` vs `OR 1=2` response diffs.
- Timing: median of 3 measurements instead of single.
- NoSQL injection payloads (`$gt`, `$ne`, `$regex`).
- Union-based: `ORDER BY N` probing + `UNION SELECT NULL,...`.
- Expand payloads: 14 -> ~30.

### 2c. CORS
- Actively send `Origin: null` as a test case.
- Distinguish API vs static assets — only flag CORS on API endpoints.
- Test credential reflection: `Allow-Credentials: true` with wildcard.

### 2d. Open Redirect
- Expand parameter names: `callback`, `redir`, `forward`, `ref`, `out`, `continue`, `target`, `path`, `link`, `returnUrl`, `redirectUrl`.
- Header-based redirect: `Host` header injection.

### 2e. Directory Traversal
- Remove API-only filter. Test any URL with file-like parameters.
- Path parameter detection: `/files/download/report.pdf` pattern.

### 2f. Passive checks
- Cookie heuristics: skip HttpOnly warnings for `csrf*`, `locale`, `theme`, `_ga*`, analytics cookies.
- Deduplicate header findings at scan level, not per-page.

---

## Section 3: New Check Types

All follow existing plugin pattern: new file in `src/scanner/active/`, registered in `CHECK_REGISTRY`.

### 3a. SSRF
- Inject internal URLs (`127.0.0.1`, `169.254.169.254`, `[::1]`) into URL-accepting params.
- Detect: cloud metadata in response, internal IP indicators, timing differences.

### 3b. SSTI
- Inject math expressions (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) into inputs.
- Detect: `49` in response where it wasn't before.

### 3c. Command Injection
- Inject shell metacharacters (`` `sleep 5` ``, `; sleep 5`, `$(sleep 5)`).
- Detect: timing-based, median of 3 trials.

### 3d. IDOR
- Detect sequential ID patterns in URLs. Try incrementing/decrementing IDs.
- Compare responses. Requires auth context — skip without auth.

### 3e. TLS/Crypto
- Node.js `tls.connect()` to check TLS version, cipher suites, cert validity, HSTS preload.
- Flag TLS 1.0/1.1, weak ciphers, expired/self-signed certs.

### 3f. Subresource Integrity (SRI)
- Check `<script>` and `<link>` tags from CDNs for `integrity` attributes.
- Flag external resources without SRI.

### 3g. Security Headers Deep Check
- `Permissions-Policy` validation, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`.

---

## Section 4: Crawling & Route Discovery

### 4a. Next.js route extraction
- Parse `sitemap.xml` if available.
- Fetch Next.js build manifests (`/_next/static/chunks/pages-manifest.json`).
- Common path probing (`/api/*`, `/login`, `/dashboard`, `/settings`).
- Merge with `<a>` tag crawling. Deduplicate.

### 4b. `--urls` flag
- Text file, one URL per line. Added to crawl queue directly.

### 4c. Architecture for Path B
- `RouteDiscoverer` interface: `LinkCrawler` (current), `NextJsExtractor` (new), `UrlFileLoader` (new).
- Path B adds `SPACrawler` as drop-in implementation.

---

## Section 5: Output & CI/CD Readiness

### 5a. Exit codes
- `0` — No HIGH/CRITICAL findings
- `1` — HIGH or CRITICAL findings present
- `2` — Scan error

### 5b. JSON output enhancements
- Add `exitCode`, `scanDuration`, `pagesScanned`, `checksRun`.
- Add `summary.passedChecks` — check types that ran clean (compliance evidence).

### 5c. Version management
- Read from `package.json` at runtime. No hardcoded versions.

---

## Path B Roadmap (deferred — long-term)

| Feature | Description |
|---|---|
| Full SPA crawling | pushState/replaceState interception, button clicking, JS router |
| WAF evasion payloads | Encoding variants, polyglots, PayloadsAllTheThings integration |
| `--proxy` flag | Burp Suite / mitmproxy integration |
| Auth flows | OAuth, Bearer token, session refresh mid-scan |
| Interactive mode | Iterative probe-adjust-retest workflow |
| Screenshot capture | Playwright screenshots as exploitation proof |
| Rate limit config | Per-program request limits for bounty programs |
| Open source | npm publish, GitHub community, contributor onboarding |

---

## Success Criteria

Path A is done when:
1. All 12 check types implemented and tested (5 improved + 7 new)
2. Unit + integration test suite passing
3. Pre-dedup reduces AI token usage by 50%+
4. Clean scan on all Atmando apps (Finance, Vault, Dashboard, Kids, Education)
5. CI/CD-ready exit codes and JSON output
6. `--urls` flag works for route supplementation
7. SIGINT cleanup works reliably
8. Version bumped to v1.0.0

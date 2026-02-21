# SecBot Roadmap — Path A Completion → Path B

**Date:** 2026-02-21
**Current:** v0.6.0 (167 tests, 12 check types, foundation solid)
**Path A target:** v1.0.0 — reliable developer security tool for internal apps
**Path B target:** v2.0.0 — useful for real bug bounty against external targets

---

## Where We Are (v0.6.0)

**Works well:** Scanning own Next.js/Supabase apps for missing headers, weak CORS, cookie flags, basic reflected XSS, SQL error patterns. Route discovery via Next.js manifests. AI-powered validation reduces noise. Clean scan on atmando-finance confirmed.

**Doesn't work:** Anything behind a WAF (every payload gets blocked), blind vulnerabilities (SSRF, blind XSS), SPAs that load data after render, targets requiring login flows, rate-limited targets. Zero WAF evasion, zero out-of-band detection.

**Architecture:** Extensible `ActiveCheck` interface, pluggable `RouteDiscoverer`, 3-stage AI pipeline with rule-based fallback. Browser reused across phases. Pre-dedup saves tokens. But no plugin system, no proxy support, no request middleware, no adaptive rate limiting.

---

## Path A: Developer Security Tool (v0.6.0 → v1.0.0)

Goal: Make SecBot genuinely reliable for scanning your own apps in CI/CD. Zero false positives on clean apps. Every finding is actionable.

### A.2 — Harden Detection (v0.7.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **WAF-aware payload encoding** | Add URL-encode, double-encode, and HTML-entity variants for XSS + SQLi payloads. Use recon WAF detection to pick encoding strategy. | 3 hr |
| 2 | **Adaptive rate limiting** | Replace fixed `requestDelay` with adaptive system: exponential backoff on 429/503, configurable `--rate-limit <req/sec>`. Add request queue with backpressure. | 3 hr |
| 3 | **Token tracking + budget** | Track tokens consumed per scan. Add `SECBOT_TOKEN_BUDGET` env var (default: unlimited). Log token usage in JSON output. | 1 hr |
| 4 | **AI response caching** | Cache recon→plan mapping (same target within 24h = skip planner). Cache validator results by finding hash. File-based cache in `~/.secbot/cache/`. | 2 hr |
| 5 | **Dynamic planner prompts** | Only include check types relevant to discovered targets in the planner prompt (no forms? skip XSS form context). Reduces tokens ~40%. | 1 hr |
| 6 | **SSRF DNS canary** | Add optional `--callback-url <url>` flag. Inject callback URLs into SSRF payloads. Check for hits after scan. Document how to set up a simple listener. | 2 hr |
| 7 | **False-positive rate testing** | Add `test/fp-rate/` suite: scan known-safe targets (Next.js starter, Express hello-world) and assert 0 findings. Run in CI. | 2 hr |

**Exit criteria:** Scan all 5 Atmando apps clean. Zero false positives. Token usage visible.

### A.3 — CI/CD Integration (v0.8.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **`--exclude-checks` flag** | Skip expensive checks (traversal, cmdi, timing-based SQLi) for quick CI runs. | 30 min |
| 2 | **SARIF output** | Add `sarif` format option for GitHub Code Scanning integration. | 2 hr |
| 3 | **GitHub Action wrapper** | `action.yml` that runs SecBot scan and posts results as PR comment. | 2 hr |
| 4 | **Baseline/diff mode** | `--baseline <file>` compares current findings against previous scan. Only report new findings. Essential for CI — avoids noise from known issues. | 3 hr |
| 5 | **JUnit XML output** | For Jenkins/GitLab CI integration. | 1 hr |
| 6 | **Config file support** | `.secbotrc.json` or `secbot.config.ts` — persist target, profile, scope, excluded checks. No more repeating CLI args. | 2 hr |

**Exit criteria:** SecBot runs in GitHub Actions on atmando-finance PR checks. New findings block merge. Known issues baselined.

### A.4 — Polish & Release (v1.0.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **AI mock tests** | Unit tests for planner, validator, reporter with mocked Claude responses. Test prompt construction, JSON parsing edge cases, fallback triggers. | 3 hr |
| 2 | **Reporter output tests** | Test HTML, JSON, bounty markdown output structure. Snapshot tests. | 1 hr |
| 3 | **CLI argument validation** | Validate all CLI inputs (profile values, URL format, file existence for --auth/--urls). Friendly error messages. | 1 hr |
| 4 | **npm publish setup** | `"files"` field in package.json, CJS+ESM dual format via tsup, publish CI workflow on git tag. | 2 hr |
| 5 | **Scan 5 Atmando apps clean** | Run SecBot against Finance, Vault, Dashboard, Kids, Education. Fix any false positives. Document results. | 2 hr |
| 6 | **Version bump to 1.0.0** | Update package.json, CHANGELOG, README. Tag release. | 30 min |

**Exit criteria:** Published to npm. All Atmando apps scan clean. Full test suite (unit + integration + FP rate + AI mocks). GitHub Actions CI green.

---

## Path B: Bug Bounty Tool (v1.0.0 → v2.0.0)

Goal: Make SecBot useful for testing external targets behind WAFs, with full SPA support, auth automation, and out-of-band detection.

### B.1 — SPA Crawling (v1.1.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **JavaScript route interception** | Monkey-patch `pushState`/`replaceState` to capture client-side navigation. Listen for `hashchange`. Add discovered routes to crawl queue. | 3 hr |
| 2 | **Click-through navigation** | After initial load, click all interactive elements (buttons, [role=button], anchors without href). Wait for navigation/XHR, capture new URLs. | 4 hr |
| 3 | **XHR/fetch interception** | Intercept `XMLHttpRequest` and `fetch` calls via `addInitScript`. Capture API endpoints automatically (no manual `--urls` needed). | 2 hr |
| 4 | **Framework detection + strategy** | Detect React Router / Next.js / Vue Router / Angular Router from DOM markers. Apply framework-specific crawling strategy (e.g., React: look for `<Link>` components). | 3 hr |
| 5 | **`SPACrawler` implementation** | Implement `RouteDiscoverer` that combines all above. Drop-in alongside `NextJsExtractor`. | 2 hr |
| 6 | **Wait-for-hydration** | After page load, wait for framework hydration signals (React: `__NEXT_DATA__`, Vue: `__VUE_APP__`, Angular: `ng-version`). Then extract DOM. | 1 hr |

**Exit criteria:** SecBot discovers all routes on a React SPA (create-react-app + React Router) without `--urls`.

### B.2 — WAF Evasion (v1.2.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **Payload mutation engine** | `PayloadMutator` class that applies transforms: URL-encode, double-encode, Unicode normalization, HTML entities, null-byte injection, case randomization, SQL comment insertion. Each check feeds payloads through mutator. | 4 hr |
| 2 | **WAF fingerprinting** | Enhance recon to identify specific WAF (Cloudflare, AWS WAF, ModSecurity, Sucuri). Map WAF → known bypass techniques. | 2 hr |
| 3 | **Polyglot payloads** | Add context-aware polyglots (XSS+SQLi combos, payloads that work in multiple injection contexts). | 2 hr |
| 4 | **HTTP parameter pollution** | Duplicate parameters, array notation (`param[]=`), JSON body injection alongside URL params. | 2 hr |
| 5 | **Chunked transfer encoding** | Send payloads via chunked transfer to bypass WAF content inspection. | 2 hr |
| 6 | **`--stealth` profile** | New scan profile: random User-Agent rotation, jittered delays (50-500ms), no concurrent requests, payload obfuscation enabled by default. | 1 hr |

**Exit criteria:** SecBot finds reflected XSS on a Cloudflare-protected test target using encoded payloads.

### B.3 — Proxy & Traffic Control (v1.3.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **`--proxy` flag** | Route all Playwright traffic through HTTP/SOCKS proxy. Supports `http://`, `socks5://`. | 2 hr |
| 2 | **Request middleware** | Add pre-request hooks: modify headers, add auth tokens, inject custom payloads. Pipeline architecture: `request → middleware[] → send`. | 3 hr |
| 3 | **Response middleware** | Post-response hooks: capture for Burp import, detect WAF block pages, extract tokens. | 2 hr |
| 4 | **Burp Suite export** | Export all requests/responses as Burp XML for manual follow-up. | 2 hr |
| 5 | **HAR file generation** | Export full traffic as HAR (HTTP Archive) — works with any proxy tool. | 1 hr |

**Exit criteria:** SecBot scan visible in Burp Suite via proxy. HAR export importable into browser dev tools.

### B.4 — Auth Flow Automation (v1.4.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **Login form detection** | Heuristic detection of login forms (username/password fields, submit button). Auto-fill with provided credentials. | 3 hr |
| 2 | **`--login-url` + `--credentials`** | CLI flags for automated login before scan. Extract and save storage state. | 2 hr |
| 3 | **CSRF token extraction** | Detect CSRF tokens in forms/headers. Auto-include in subsequent requests. | 2 hr |
| 4 | **Session refresh** | Monitor for 401/403 during scan. Re-authenticate using stored login flow. Resume scan from where it left off. | 3 hr |
| 5 | **OAuth handler** | Support OAuth2 redirect flows: open login page, detect redirect to callback, capture token. | 4 hr |
| 6 | **Multi-role scanning** | Define multiple user roles in config file. Scan once per role. Compare findings across roles (privilege escalation detection). | 3 hr |

**Exit criteria:** SecBot logs into a Supabase-auth app, maintains session through full scan, re-authenticates on expiry.

### B.5 — Out-of-Band Detection (v1.5.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **Callback server** | Built-in HTTP+DNS listener that runs during scan. Generates unique callback URLs per payload. Detects blind SSRF, blind XSS, blind SQLi. | 4 hr |
| 2 | **`--callback-server`** | Auto-start callback server on specified port. Use with ngrok/Cloudflare tunnel for external targets. | 2 hr |
| 3 | **DNS canary** | Generate unique subdomain per payload (`<uuid>.callback.secbot.local`). Detect DNS lookups from target. | 3 hr |
| 4 | **Blind XSS payloads** | Inject payloads that phone home to callback server. Detect stored XSS that fires on admin pages. | 2 hr |
| 5 | **Delayed detection** | After active scan, wait configurable period (default: 30s) for delayed callbacks. Report findings from callbacks received after injection. | 1 hr |

**Exit criteria:** SecBot detects blind SSRF on test fixture via DNS callback. Detects blind XSS via HTTP callback.

### B.6 — Interactive Mode & Reporting (v2.0.0)

| # | Task | What Changes | Effort |
|---|------|-------------|--------|
| 1 | **Interactive REPL** | `secbot interactive <url>` — probe, review findings, adjust payloads, re-test. TUI with keyboard navigation. | 5 hr |
| 2 | **Screenshot capture** | Playwright screenshot on confirmed findings. Embed in HTML report as proof of exploitation. | 2 hr |
| 3 | **Finding export for HackerOne/Bugcrowd** | One-click copy-paste format for bounty platforms. Include all evidence, PoC, impact assessment. | 1 hr |
| 4 | **Plugin directory** | Load custom checks from `~/.secbot/plugins/` or npm packages (`secbot-plugin-*`). Hot-reload in interactive mode. | 4 hr |
| 5 | **Rate limit config** | Per-domain request limits from config file. Respect program-specific rate limits for bounty targets. | 1 hr |
| 6 | **Version bump to 2.0.0** | Tag release. Full documentation. npm publish. | 1 hr |

**Exit criteria:** Full interactive workflow on an external target. Plugin system works. Published v2.0.0.

---

## Version Summary

| Version | Milestone | Key Capabilities Added |
|---------|-----------|----------------------|
| **v0.6.0** | Current | 12 checks, AI pipeline, route discovery, CI exit codes |
| **v0.7.0** | Hardened detection | WAF-aware encoding, adaptive rate limiting, token tracking, SSRF canary |
| **v0.8.0** | CI/CD ready | SARIF output, GitHub Action, baseline/diff, config file |
| **v1.0.0** | Developer tool done | npm published, all Atmando apps clean, full test suite |
| **v1.1.0** | SPA crawling | JS route interception, click-through, XHR capture |
| **v1.2.0** | WAF evasion | Payload mutation, polyglots, HTTP param pollution, stealth mode |
| **v1.3.0** | Proxy support | Burp integration, request/response middleware, HAR export |
| **v1.4.0** | Auth automation | Login detection, session refresh, OAuth, multi-role |
| **v1.5.0** | OOB detection | Callback server, DNS canary, blind XSS/SSRF/SQLi |
| **v2.0.0** | Bug bounty ready | Interactive mode, screenshots, plugin system |

---

## Priority Calls

**If time is limited, the highest-impact items are:**

1. **A.2: WAF-aware encoding + adaptive rate limiting** — unlocks scanning any target without getting blocked
2. **A.3: Baseline/diff mode** — makes CI integration useful (no noise from known issues)
3. **B.1: SPA crawling** — most modern apps are SPAs; without this, SecBot misses 80% of routes
4. **B.2: Payload mutation engine** — single biggest gap for real vulnerability detection
5. **B.5: Callback server** — unlocks blind vulnerability detection (SSRF, stored XSS, blind SQLi)

**What to skip if pragmatic:**
- B.4 OAuth handler (complex, low ROI — manual pre-auth works)
- B.6 Interactive mode (nice-to-have, not essential)
- B.6 Plugin directory (internal tool doesn't need it)

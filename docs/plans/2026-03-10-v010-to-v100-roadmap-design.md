# SecBot Roadmap: v0.10 → v1.0

**Created:** 2026-03-10
**Goal:** Close all identified gaps, graduate from "check runner" to "intelligent bounty hunter"
**Approach:** Milestone-based (v0.11 → v0.12 → v0.13 → v1.0)
**Hunting strategy:** Validate on own apps (GIS-ERP, GLS-ERP, Cekatan, Atmando), then public bounty programs
**AI strategy:** AI-heavy — every scan uses AI for payload selection, response analysis, business logic inference (~$0.50-1.00/scan)

## Current State (v0.10.0)

- 20 active checks, 6 passive, 5 chain rules, 14 disclosure dedup rules
- 1252 tests, 75 test files, zero false positives across 8 scans
- Juice Shop: 9 actionable findings (1 critical, 3 high, 3 medium, 2 low)
- Scan speed: 18min for 22 pages (too slow)
- Payload context module exists but is not consumed by any check

## Identified Gaps

1. **Speed:** Active checks run sequentially (18min for 22 pages)
2. **Payload context unused:** Inferences (PHP→MySQL, Angular→DOM XSS) not wired into checks
3. **Shallow recon:** DNS-only subdomain enum, recon doesn't share knowledge with framework-detector
4. **Narrow coverage:** Missing file upload, broken access control, business logic, WebSocket, API versioning
5. **Surface-level auth:** No auto-login, no OAuth, no multi-step auth
6. **AI underused:** Post-processor only, doesn't drive payload selection or response analysis

---

## v0.11 — "Speed & Depth"

*Make what we have faster and smarter. No new check types.*

### Parallel Active Checks
- Group checks by interference level:
  - **Safe to parallelize** (read-only, no state changes): CORS, SRI, TLS, info-disclosure, js-cve, host-header, JWT
  - **Must be sequential** (send payloads, may trigger WAF): XSS, SQLi, SSRF, SSTI, CMDi, CRLF, traversal
  - **Needs isolation** (concurrent requests by design): race-condition
- Run safe group concurrently (Promise.allSettled), then sequential group one-by-one
- Expected speedup: 18min → ~4-5min

### Wire Payload Context into Active Checks
- **SQLi:** Prioritize MySQL payloads for PHP, MSSQL for .NET, PostgreSQL for Python/Ruby, MongoDB for Node. Skip irrelevant DB-specific payloads.
- **SSTI:** Try Jinja2 for Django/Flask, Twig for Laravel/Symfony, Handlebars/Pug/EJS for Express, ERB for Rails, Freemarker/Velocity for Java. Skip irrelevant engines.
- **XSS:** SPA framework detected → prioritize DOM XSS, reduce reflected XSS attempts. Server-rendered → prioritize reflected.
- **CMDi:** Unix payloads for Linux/Mac servers, Windows payloads for IIS/.NET. Skip irrelevant OS payloads.
- Implementation: Each check reads `config.payloadContext` and reorders/filters its payload list.

### Recon ↔ Framework-Detector Merge
- After crawl, if `pages[].framework` detected Angular/React/Vue/etc, feed that into `recon.framework` instead of running weaker body-based detection.
- Single source of truth for framework info.

### Deliverables
- [ ] Parallel check runner in `active/index.ts`
- [ ] PayloadContext consumption in sqli.ts, ssti.ts, xss.ts, cmdi.ts
- [ ] Recon framework merge
- [ ] Benchmark: scan Juice Shop, measure time reduction
- [ ] All existing tests still pass + new tests for parallel runner

---

## v0.12 — "Coverage"

*Find more vulnerability types. Expand the attack surface.*

### New Active Checks

**File Upload Check** (`active/file-upload.ts`)
- Detect file upload forms (input[type=file])
- Test: shell upload (.php, .jsp, .asp), polyglot files (GIF89a + PHP), double extension (.php.jpg), MIME type bypass, size limit bypass
- Severity: critical (RCE via shell upload), high (stored XSS via SVG/HTML upload)
- Safety: upload to temp path, never execute

**Broken Access Control** (`active/access-control.ts`)
- Requires `--auth` (regular user) + `--idor-alt-auth` (admin or different role)
- Crawl as admin → collect admin-only endpoints
- Replay admin endpoints as regular user → if 200, it's broken access control
- Also test: HTTP method override (POST→PUT→DELETE), header bypass (X-Original-URL)

**Business Logic Checks** (`active/business-logic.ts`)
- Price manipulation: modify price/quantity params (negative, zero, decimal abuse)
- Coupon/promo reuse: replay discount codes
- Workflow bypass: skip steps in multi-step processes (go from step 1 to step 3)
- Requires understanding of e-commerce/transactional patterns from page content

**WebSocket Testing** (`active/websocket.ts`)
- Discover ws:// endpoints from page scripts and upgrade headers
- Test: connect without auth token, inject payloads in messages, test origin validation
- Severity: high (auth bypass), medium (injection)

**API Versioning Discovery** (`active/api-version.ts`)
- For each /api/v2/ endpoint found, probe /api/v1/ — older versions often lack auth/rate-limiting
- Compare response schemas between versions
- Severity: medium-high (auth bypass on old API)

### Recon Expansion
**Certificate Transparency Subdomain Enum** (`recon/ct-enum.ts`)
- Query crt.sh API: `https://crt.sh/?q=%.example.com&output=json`
- Merge with DNS brute-force results
- Deduplicate, resolve IPs, check for CNAME takeover opportunities

### Authentication Upgrade
**Auto-Login via Form Detection** (upgrade `auth/authenticator.ts`)
- Detect login forms using existing `login-detector.ts` heuristics
- Fill username/password from `--credentials`, submit, capture session
- Handle common post-login redirects (302, meta refresh, JS redirect)
- Store session as Playwright storage state for rest of scan

### Deliverables
- [ ] 5 new active checks + tests
- [ ] CT subdomain enumeration
- [ ] Auto-login form detection
- [ ] Validate on own apps (GIS-ERP has auth, Cekatan has multi-tenant)
- [ ] Juice Shop re-scan: target 15+ actionable findings

---

## v0.13 — "Intelligence"

*Scanner thinks like a bounty hunter. AI drives decisions, not just validation.*

### AI-Driven Form Targeting
- Before injecting generic payloads, AI analyzes form fields + page context
- AI sees: field names, labels, surrounding text, form action, HTTP method
- AI decides: "This is a search form → test XSS. This is a payment form → test price manipulation. This is a file path → test traversal."
- Reduces wasted requests, increases finding quality

### AI Response Analysis
- After each active check response, AI analyzes:
  - Error messages for stack traces, DB info, internal paths
  - Behavioral differences (200 vs 403 vs 500) for auth bypass signals
  - Response time anomalies for blind injection confirmation
- Currently rule-based — upgrade to AI for subtle pattern detection

### Business Logic Inference
- AI reads page HTML/text to understand what the app does
- Generates app-specific test cases: "This is a booking system → test double-booking, test cancellation refund, test date manipulation"
- Most expensive AI feature (~$0.30/scan) but highest bounty ROI

### Multi-Subdomain Scanning
- `--subdomains` discovers subdomains (DNS + CT from v0.12)
- Auto-add in-scope subdomains as additional scan targets
- Run full pipeline on each subdomain (crawl → recon → scan)
- Aggregate findings across all subdomains in single report

### OAuth Flow Support
- Detect OAuth2 login buttons (Google, GitHub, Facebook, SAML)
- Support authorization_code flow with browser automation
- Capture tokens, inject into subsequent requests
- Extends auto-login from v0.12

### AI Chain Detection
- Beyond 5 hardcoded rules: AI analyzes all findings together
- Proposes novel chains based on actual findings and target context
- Example: "SSRF on image proxy + internal admin panel without auth = unauthenticated admin access"

### Deliverables
- [ ] AI form targeting integrated into XSS, SQLi, business-logic checks
- [ ] AI response analyzer as post-check hook
- [ ] Business logic inference module
- [ ] Multi-subdomain orchestration
- [ ] OAuth flow handler
- [ ] AI chain proposer
- [ ] Cost tracking: log AI spend per scan

---

## v1.0 — "Bounty Ready"

*Polish, publish, start earning.*

### Ship
- [ ] `npm publish` as `secbot-cli`
- [ ] README with getting started, examples, CI/CD integration
- [ ] GitHub Actions workflow example (scan on PR)
- [ ] Example reports (redacted)

### Operate
- [ ] Weekly cron on Mac Mini scanning own apps via Nara
- [ ] Alert on new findings → Nara Telegram notification
- [ ] Scan comparison mode: `secbot diff scan-a.json scan-b.json`

### Harden
- [ ] Stealth mode: realistic browser fingerprints, human-like timing jitter
- [ ] Anti-bot bypass: Cloudflare challenge solving, CAPTCHA detection
- [ ] HackerOne/Bugcrowd one-click report formatting

### Validate
- [ ] Scan 5 public bounty programs (read-only, respect scope)
- [ ] Target: find 1 valid bounty within first month
- [ ] Iterate based on what real programs expose

---

## Dependency Graph

```
v0.11 (Speed & Depth)
  ├── Parallel checks (no deps)
  ├── Payload context wiring (uses existing payload-context.ts)
  └── Recon framework merge (uses existing framework-detector)
         │
v0.12 (Coverage)
  ├── File upload (needs form detection from crawl)
  ├── Broken access control (benefits from v0.11 speed)
  ├── Business logic (needs payload context from v0.11)
  ├── WebSocket (independent)
  ├── API versioning (independent)
  ├── CT subdomain enum (extends existing subdomain.ts)
  └── Auto-login (extends existing auth/)
         │
v0.13 (Intelligence)
  ├── AI form targeting (needs v0.12 coverage checks)
  ├── AI response analysis (benefits from v0.12 check types)
  ├── Business logic inference (needs v0.12 business logic check)
  ├── Multi-subdomain (needs CT enum from v0.12)
  ├── OAuth (extends auto-login from v0.12)
  └── Smart chains (needs v0.12 finding types)
         │
v1.0 (Ship)
  └── Polish, docs, publish, cron, stealth
```

## Success Metrics

| Milestone | Metric |
|-----------|--------|
| v0.11 | Juice Shop scan < 5 min, payload context logged per check |
| v0.12 | 15+ actionable findings on Juice Shop, file upload + access control detected |
| v0.13 | AI generates app-specific test cases, novel chain detected |
| v1.0 | Published on npm, first valid bounty submitted |

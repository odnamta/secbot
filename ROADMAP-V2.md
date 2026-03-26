# SecBot v2.0 Roadmap — "Own the Engine, Use the Data"

> **Goal:** Best automated bounty hunter. Self-sustaining from bug bounty revenue.
>
> **Core insight:** SecBot's moat is AI (planning, validation, chaining, reporting, learning). Everything else — recon, content discovery, template matching — is commodity work. Don't depend on external tool binaries. Build our own lean engine powered by community data (SecLists wordlists, Nuclei-format templates, public APIs). Zero external binary dependencies. Just `npm install secbot`.
>
> **Philosophy:** Own the engine. Use the data. Be smarter, not bigger.

## Why This Approach

| Approach | Pros | Cons |
|----------|------|------|
| Build everything from scratch | Full control | 6 months, reinventing the wheel |
| Shell out to external binaries | Fast to build | Fragile, 7+ deps, can't `npm install` |
| **Own engine + community data** | **Full control, zero deps, 2-3 weeks** | **Must maintain our engine** |

The tools (subfinder, nuclei, ffuf) are just HTTP requests + parsing. The real value is in the **data** they use — wordlists, templates, API data sources — all MIT licensed, community-maintained. We consume the data natively in TypeScript.

## Where SecBot Becomes BETTER Than Existing Tools

1. **AI-guided discovery.** ffuf brute-forces 137K paths blindly. SecBot's AI sees "this is Rails" and tests 500 Rails-specific paths. 500 smart requests > 137K dumb ones.
2. **Cross-phase intelligence.** Nuclei runs templates in isolation. SecBot chains: subdomain enum → content discovery → param discovery → injection testing → confirmed vuln. End-to-end, no tool can do this.
3. **AI validation.** Nuclei reports every match (70% noise). SecBot validates each finding and writes a bounty-quality report.
4. **Self-improving templates.** When a finding gets rejected, SecBot updates the template with an exclusion. Nuclei templates are static.
5. **Single package.** `npm install secbot` → everything works. No Go, no Rust, no Python binaries.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    SecBot v2.0                        │
│              (single npm package)                     │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │            AI Layer (Claude) — THE MOAT       │    │
│  │                                               │    │
│  │  AI Plan: "This is Django+Postgres. Test      │    │
│  │   these 12 endpoints for SQLi, skip WP paths" │    │
│  │  AI Validate: "This is real, not FP because…" │    │
│  │  AI Chain: "Open redirect + SSRF = internal"  │    │
│  │  AI Report: bounty-quality submission draft    │    │
│  │  AI Learn: "CSRF on Rails: 40% accept rate"   │    │
│  └──────────────────────────────────────────────┘    │
│                        │                             │
│  ┌─────────────────────┼────────────────────────┐    │
│  │         Fast HTTP Engine (fetch/undici)        │    │
│  │         ~500-1000 req/sec, rate-limited        │    │
│  │                                               │    │
│  │  • Content Discovery (SecLists wordlists)     │    │
│  │  • Subdomain Enum (crt.sh + SecurityTrails)   │    │
│  │  • Template Scan (Nuclei-format YAML)         │    │
│  │  • Param Discovery (response diffing)         │    │
│  │  • Port Probing (common ports)                │    │
│  │  • HTTP checks (CORS, headers, CSRF, etc.)    │    │
│  └──────────────────────────────────────────────┘    │
│                        │                             │
│  ┌─────────────────────┼────────────────────────┐    │
│  │         Browser Engine (Playwright)            │    │
│  │         ~5 req/sec, JS execution               │    │
│  │                                               │    │
│  │  • SPA Crawling + JS extraction               │    │
│  │  • DOM XSS / Stored XSS / Clickjacking        │    │
│  │  • Auth flows + cookie extraction              │    │
│  │  • Screenshot evidence                         │    │
│  └──────────────────────────────────────────────┘    │
│                                                      │
│  config/                                             │
│    wordlists/      ← SecLists (MIT, auto-updatable)  │
│    templates/      ← Nuclei format (MIT, extendable) │
│    params/         ← Common param names (MIT)         │
│    tech-wordlists/ ← Per-framework paths (custom)     │
└──────────────────────────────────────────────────────┘
```

## Implementation Plan

### Week 1: Foundation + Content Discovery

#### Day 1-2: Fast HTTP Engine
**What:** A rate-limited, stealth-aware HTTP client for non-browser checks.
**Why:** Prerequisite for everything. 80% of new features don't need Playwright.
**Build:**
```typescript
// src/scanner/fast-http.ts
export class FastHTTP {
  // fetch/undici wrapper with:
  // - Rate limiting (respects stealth profile)
  // - User-agent rotation (existing stealth.ts)
  // - Response fingerprinting (status, length, headers hash)
  // - Timeout handling
  // - Cookie/auth header injection
  // - Retry with backoff
  async get(url: string, opts?: RequestOpts): Promise<FastResponse>
  async post(url: string, body: any, opts?: RequestOpts): Promise<FastResponse>
  async probe(url: string): Promise<ProbeResult>  // alive check (HEAD → GET fallback)
}
```
**Files:** `src/scanner/fast-http.ts`
**Tests:** Unit tests with Express fixture server
**Effort:** ~200 lines of code

#### Day 2-3: Content Discovery
**What:** Directory/file brute-forcing using wordlists on the fast engine.
**Why:** 80% of exploitable endpoints are NOT linked from the homepage.
**Build:**
```typescript
// src/scanner/discovery/content-discovery.ts
export async function discoverContent(
  baseUrl: string,
  http: FastHTTP,
  options: {
    wordlist: string;         // path to wordlist file
    extensions?: string[];    // ['.php', '.asp', '.bak', '.sql']
    recursive?: boolean;      // brute-force subdirs of 200 responses
    techStack?: string[];     // filter wordlist by detected tech
  }
): Promise<DiscoveredEndpoint[]>
```
**How it works:**
1. Load wordlist (start with curated 5K list, not full 137K — AI can prioritize)
2. AI pre-filter: given the tech stack, which 500 paths are most likely to exist?
3. Fire requests via fast engine, track response codes
4. 200 = accessible (add to scan targets)
5. 403 = exists but forbidden (log, might indicate interesting area)
6. 301/302 = follow redirect, add destination
7. If recursive: directories that return 200 get their own brute-force pass
**Files:** `src/scanner/discovery/content-discovery.ts`
**Wordlists:** `config/wordlists/common-paths.txt` (curated top 5K from SecLists)
**Effort:** ~300 lines

#### Day 3-4: Subdomain Enumeration Upgrade
**What:** Replace 70 DNS prefixes with real enumeration.
**Why:** Forgotten subdomains = forgotten security.
**Build:**
- Expand DNS brute-force wordlist: `config/wordlists/subdomains-5000.txt` (from SecLists)
- Add SecurityTrails API client (free tier: 50 queries/month) — `src/scanner/recon/securitytrails.ts`
- Keep existing crt.sh (already works)
- Add HTTP probing: for each discovered subdomain, check if it serves HTTP on ports 80, 443, 8080, 8443, 3000, 5000, 8000
- Feed all alive HTTP hosts back into the scanner as additional targets
**Files:** update `src/scanner/recon/subdomain.ts`, new `src/scanner/recon/http-probe.ts`
**Effort:** ~250 lines (mostly the API client + probe logic)

#### Day 4-5: Hidden Parameter Discovery
**What:** Find parameters that aren't in HTML.
**Why:** Hidden params (debug, admin, test, verbose, internal) are where injection bugs live.
**Build:**
```typescript
// src/scanner/discovery/param-discovery.ts
export async function discoverParams(
  url: string,
  http: FastHTTP,
  knownParams: string[],     // from crawl
  wordlist: string[],        // common param names
): Promise<DiscoveredParam[]>
```
**How it works:**
1. Send baseline request (no extra params), fingerprint response
2. For each candidate param name, send request with `?param=secbot_test`
3. Compare response fingerprint to baseline
4. If status code, body length, or header set differs → param is processed by backend
5. Feed discovered params into XSS/SQLi/SSRF checks
**Files:** `src/scanner/discovery/param-discovery.ts`
**Wordlist:** `config/wordlists/params-top500.txt` (curated from Arjun/Burp lists)
**Effort:** ~200 lines

**Week 1 diagnostic:** Run against 3 registry targets. Compare endpoints discovered vs v1. Expect 10-50x more endpoints found.

### Week 2: Template Engine + JS Analysis

#### Day 6-8: Template Engine (Nuclei-Compatible)
**What:** YAML-based vulnerability template scanner.
**Why:** Known issues = 10x more likely to be accepted than generic findings.
**Build:**
```typescript
// src/scanner/templates/engine.ts
interface Template {
  id: string;
  info: { name: string; severity: string; tags: string[]; reference?: string };
  match?: { tech?: string; port?: number };  // pre-filter by tech stack
  requests: TemplateRequest[];
}

interface TemplateRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;                    // supports {{BaseURL}} variable
  headers?: Record<string, string>;
  body?: string;
  matchers: Matcher[];             // ALL must match (AND logic)
  matchers_condition?: 'and' | 'or';
  extractors?: Extractor[];        // capture values for chaining
}

interface Matcher {
  type: 'status' | 'body' | 'header' | 'regex' | 'word';
  // status: [200, 301]
  // body/word: ["admin panel", "phpinfo"]
  // header: ["X-Powered-By: Express"]
  // regex: ["version\\s*:\\s*(\\d+\\.\\d+)"]
  values: (string | number)[];
  negative?: boolean;              // invert match (must NOT match)
}
```
**Template format** (Nuclei-compatible subset):
```yaml
id: exposed-git-config
info:
  name: "Exposed .git/config"
  severity: medium
  tags: [git, exposure, misconfig]
  description: "Git configuration file is publicly accessible"
match:
  tech: any
requests:
  - method: GET
    path: "{{BaseURL}}/.git/config"
    matchers:
      - type: body
        words: ["[core]", "[remote"]
        condition: or
      - type: status
        status: [200]
```
**Starter templates (200):**
- Exposed files: .git, .env, .DS_Store, wp-config.php.bak, etc. (30)
- Admin panels: /admin, /wp-admin, /phpmyadmin, /adminer, etc. (30)
- Debug endpoints: /debug, /actuator, /health, /server-status, etc. (30)
- Default credentials: common product default logins (20)
- API docs: /swagger, /api-docs, /graphql/playground, /openapi.json (20)
- Known CVEs: top 50 most reported CVEs per year (50)
- Tech-specific misconfigs: Spring, Django, Rails, Laravel, Express (20)
**Files:** `src/scanner/templates/engine.ts`, `src/scanner/templates/loader.ts`, `config/templates/*.yaml`
**Effort:** ~400 lines (engine) + YAML templates

#### Day 8-10: Deep JavaScript Analysis
**What:** Extract full attack surface from JS bundles.
**Why:** Modern apps expose endpoints, params, GraphQL queries, and even API keys in JS.
**Build:**
```typescript
// src/scanner/discovery/js-analysis.ts
export async function analyzeJavaScript(
  scripts: ScriptInfo[],  // URLs + content from crawl phase
): Promise<JSAnalysisResult> {
  return {
    endpoints: [],      // /api/v1/users, /graphql, etc.
    params: [],         // extracted parameter names
    graphqlOps: [],     // queries and mutations
    secrets: [],        // API keys, tokens (extend existing)
    webpackChunks: [],  // lazy-loaded route chunks
    sourceMapUrls: [],  // .map files to analyze
  };
}
```
**Extraction patterns:**
- `fetch('/api/...')`, `axios.get('/...')`, `$.ajax({url: '...'})` — full URL + method
- Webpack: `webpackJsonp`, `__webpack_modules__`, chunk manifest for lazy routes
- GraphQL: `query { ... }`, `mutation { ... }` in template literals
- Route definitions: `path: '/admin'`, `component: AdminPanel`
- Parameter names: object keys in fetch body, URL search params
**Files:** new `src/scanner/discovery/js-analysis.ts`, update existing JS scanning
**Effort:** ~350 lines

**Week 2 diagnostic:** Run against 3 registry targets. Expect template matches (exposed files, debug endpoints) and JS-discovered endpoints that weren't visible in the crawl.

### Week 3: Depth + Self-Improvement + First Bounties

#### Day 11-12: Two-User Authorization Testing
**What:** Crawl as User A, replay as User B. Find IDOR/BFLA.
**Why:** Access control bugs are the #1 accepted bounty finding type.
**Build:**
- After crawling as User A (primary auth), collect all authenticated requests
- Replay each request using User B's session (--idor-alt-auth)
- Compare responses: same data returned = IDOR
- Test admin endpoints with non-admin session = privilege escalation
- Generate access control matrix
**Files:** update `src/scanner/active/idor.ts`, `src/scanner/active/bfla.ts`
**Effort:** ~250 lines

#### Day 12-13: Interactsh OOB Client
**What:** Real out-of-band detection for blind SSRF/XSS.
**Why:** Blind vulns are high-severity and require external callback.
**Build:**
- HTTP client for Interactsh API (register, poll for interactions)
- Generate unique Interactsh URLs per injection point
- Inject OOB URLs in SSRF, XSS, XXE payloads
- After injection phase, poll for hits
- Map hits back to injection points → confirmed blind vuln
**Files:** new `src/scanner/oob/interactsh-client.ts`
**Effort:** ~200 lines

#### Day 13-14: Self-Improvement Loop v1
**What:** Learn from scan results and bounty outcomes.
**Build:**
- **Gap analysis:** After scanning a target, check HackerOne/Bugcrowd disclosed reports for that program. Compare what humans found vs what SecBot found. Log gaps.
- **Confidence calibration:** Track accepted/rejected ratio per finding type per tech stack. Adjust thresholds.
- **Template learning:** When a template match is confirmed FP, add negative matcher to template. When a new vuln pattern is found manually, create a template for it.
- **Regression suite:** Weekly scan of Juice Shop + DVWA + TestFire. Alert if detection count drops.
**Files:** update `src/learning/outcomes.ts`, new `src/learning/gap-analysis.ts`
**Effort:** ~300 lines

#### Day 14: Auto-Update for Data
**What:** Keep wordlists and templates current.
**Build:**
- `secbot update` command that pulls latest:
  - SecLists wordlists (git sparse checkout of relevant dirs)
  - Custom template repository
  - CVE database updates
- Run weekly via scheduled agent or cron
**Files:** new `src/cli/update.ts`
**Effort:** ~100 lines

**Week 3: HUNT.** Run full v2 pipeline against all 19 registry targets. Triage findings. Submit the best ones. Get first bounty.

## Pipeline After v2.0

```
Phase 0:  Route Discovery     → Build manifests, --urls file (existing)
Phase 1:  Browser Crawl       → Playwright SPA crawling + JS collection (existing)
Phase 2:  Recon               → Tech fingerprint, WAF detect (existing)
Phase 2b: Subdomain Enum      → 5K+ wordlist + crt.sh + SecurityTrails API  [NEW]
Phase 2c: HTTP Probing        → Alive check all subdomains on common ports  [NEW]
Phase 2d: Content Discovery   → AI-guided directory brute-force  [NEW]
Phase 2e: JS Deep Analysis    → Endpoints, params, GraphQL from JS bundles  [NEW]
Phase 2f: Param Discovery     → Hidden param fuzzing on all endpoints  [NEW]
Phase 3:  AI Plan             → Claude sees FULL attack surface, plans smart  [ENHANCED]
Phase 4:  Passive Scan        → Headers, cookies, info leaks (existing)
Phase 5:  Template Scan       → Known CVE/misconfig YAML templates  [NEW]
Phase 6:  Active Scan         → 43 existing checks + auth testing  [ENHANCED]
Phase 6b: AI Analysis         → Claude analyzes HTTP responses (existing)
Phase 7:  AI Validate         → Claude validates, filters FPs (existing)
Phase 8:  AI Report           → Bounty-quality reports with evidence (existing)
Phase 9:  Output              → All formats (existing)
Phase 10: Self-Improve        → Gap analysis + confidence calibration  [NEW]
```

## Data Sources (All MIT / Free Tier)

| Data | Source | License | Auto-Update |
|------|--------|---------|-------------|
| Subdomain wordlist | SecLists/Discovery/DNS | MIT | `secbot update` |
| Directory wordlist | SecLists/Discovery/Web-Content | MIT | `secbot update` |
| Parameter names | SecLists/Discovery/Web-Content/burp-parameter-names.txt | MIT | `secbot update` |
| Vuln templates | Custom repo (Nuclei-compatible YAML) | MIT | `secbot update` |
| Tech-specific paths | Custom curated per framework | Custom | Manual + AI |
| Subdomain data | crt.sh API | Free | Live API |
| Subdomain data | SecurityTrails API | Free tier (50/mo) | Live API |
| CVE data | NVD API / GitHub Advisory DB | Public | `secbot update` |

## Success Metrics

| Metric | v1.1 (now) | Week 1 | Week 2 | Week 3 |
|--------|-----------|--------|--------|--------|
| Endpoints per target | 3-20 | 100-500 | 200-1000 | 200-1000 |
| Non-browser req/sec | 5-10 | 500+ | 500+ | 500+ |
| Known vuln templates | 16 | 16 | 200+ | 200+ |
| Subdomain discovery | 70 prefixes | 5K+ | 5K+ | 5K+ |
| Accepted bounties | 0 | 0 | 0 | 1+ target |
| Attack surface visible | ~5% | ~40% | ~70% | ~80% |

## Long-Term Vision

```
Month 1:  v2.0 shipped. First accepted bounty.
Month 2:  Self-improvement loop running. Revenue > $500/mo.
Month 3:  19 programs actively hunted. Template library growing from outcomes.
Month 6:  Revenue > $2K/mo. SecBot is the AI layer other hunters want.
Year 1:   Open-source the engine. Sell premium templates + AI layer as SaaS.
Year 2:   "SecBot Pro" — hunters pay $50/mo for AI-powered bounty automation.
```

## For The Main Agent

Read this file and implement in order:

1. **Fast HTTP engine** (Day 1-2)
2. **Content discovery** (Day 2-3)
3. **Subdomain enumeration upgrade** (Day 3-4)
4. **Hidden param discovery** (Day 4-5)
5. → **DIAGNOSTIC SCAN on 3 real targets** ← validate before continuing
6. **Template engine** (Day 6-8)
7. **Deep JS analysis** (Day 8-10)
8. → **DIAGNOSTIC SCAN on 3 real targets** ← validate before continuing
9. **Two-user auth testing** (Day 11-12)
10. **Interactsh OOB** (Day 12-13)
11. **Self-improvement loop** (Day 13-14)
12. **Auto-updater** (Day 14)
13. → **FULL HUNT against all 19 registry targets** ← go time

After each diagnostic scan: analyze what improved, what's still missing, adjust next phase.

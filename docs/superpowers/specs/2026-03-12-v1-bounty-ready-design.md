# SecBot v1.0 "Bounty Ready" — Design Spec

**Goal:** Transform SecBot from a security scanning prototype into an autonomous bounty hunting machine that earns money, learns from results, and gets smarter over time.

**Architecture:** Validation-driven development. Scan real targets first, fix real gaps, then automate. Self-sustaining loop: SecBot finds bugs → bounty money → fund API tokens → find more bugs.

**Platform:** HackerOne first, Bugcrowd later. Never auto-submit — always human review before submission.

---

## Pillar 1: Validation Sprint

Before writing any code, run SecBot against 3 tiers of real targets to measure where it breaks.

### Tier 1 — Own apps (safe, no legal risk)
- `atmando-finance.vercel.app`
- `cekatan.com`
- GIS-ERP (internal via Tailscale)

### Tier 2 — Public intentionally-vulnerable apps (different tech stacks)
- DVWA (PHP/MySQL — tests SQLi depth beyond Node)
- WebGoat (Java — tests SSTI/CMDi against different backends)
- HackTheBox free web challenges

### Tier 3 — Real HackerOne programs
- Pick 3-5 programs with "safe harbor" that explicitly allow automated scanning
- Programs with broad scope and no rate-limit restrictions

### Deliverable
For each scan, log: what was found, what was missed, what false-positived, what got blocked by WAF, how long it took. This becomes the gap backlog that drives Pillars 2-3.

---

## Pillar 2: Detection Hardening

Fix gaps found in validation + add proven bounty money-makers regardless.

### Must Build (high payout, easy to automate, low FP)

**Subdomain takeover detection:**
- Already have subdomain enumeration (DNS brute-force + CT logs)
- Add: resolve each subdomain's CNAME → check if target service is claimable (GitHub Pages, Heroku, S3, Azure, etc.)
- Maintain a database of fingerprints for dangling services (error pages, default pages)
- Near-zero false positive rate. $500-2000 per finding.

**IDOR depth:**
- Current check does Jaccard + JSON key similarity
- Add: systematic parameter manipulation — identify numeric/UUID parameters, swap values between authenticated users
- Requires `--idor-alt-auth` (already supported)
- Compare response bodies: if user A gets user B's data, confirmed IDOR

**Mutation XSS / CSP bypass:**
- Add mutation XSS payloads: `<svg/onload>`, `<math><mi>`, `<details/open/ontoggle>`, `<img src=x onerror>`
- CSP analysis: if CSP has `unsafe-eval`, `data:`, or `*.googleapis.com`, test bypass vectors
- Template literal injection: `{{constructor.constructor('alert(1)')()}}` for Angular/Vue

### Should Build (medium effort, solid payout)

**OAuth flow testing:**
- Detect OAuth endpoints (authorization_endpoint, token_endpoint)
- Test: missing `state` parameter, open redirect in redirect_uri, token leakage in URL fragments
- Test: scope escalation (request higher permissions than granted)

**Cache poisoning:**
- Beyond host-header (already implemented)
- Test unkeyed headers: X-Forwarded-Scheme, X-Original-URL, X-Rewrite-URL
- Detect cache hit/miss via response headers, confirm poisoned response is served to others

### Skip (hard to automate safely)
- Second-order SQLi — needs human reasoning about data flow
- HTTP request smuggling — dangerous on shared infrastructure
- Deep business logic — too context-dependent

### Detection Verification
Every finding must be verified with a second, different payload before being marked `confidence: high`. Single-payload matches are `confidence: medium` at best.

---

## Pillar 3: False Positive Elimination

Zero false positives in submitted reports. One bad submission tanks HackerOne reputation permanently.

### Confidence Scoring System

Each check produces `confidence: high | medium | low` based on evidence strength:

| Level | Criteria | Action |
|-------|----------|--------|
| `high` | Deterministic proof — payload executed, error contains injected string, CNAME is claimable | Auto-include in bounty report |
| `medium` | Strong indicator — timing difference, reflected input without execution, suspicious header | Queue for human review |
| `low` | Heuristic match — "this header looks wrong," generic pattern | Log only, never submit |

### Two-Pass Validation
1. **Rule-based pre-filter:** Discard findings below minimum evidence thresholds before spending AI tokens
2. **AI validation:** Claude reviews remaining findings with full recon context + tech stack awareness

### Auto-Verify (Playwright execution)
- **XSS:** Execute payload in Playwright, check if DOM mutation / dialog fires
- **SQLi:** Confirm with second different payload to rule out coincidence
- **IDOR:** Compare response bodies between two authenticated users
- **Subdomain takeover:** Resolve CNAME, verify target service is actually claimable
- **CORS:** Send actual cross-origin request, verify credentials are included

### Submission Threshold
Only `confidence: high` findings go into bounty draft reports. `medium` goes into "review manually" section. `low` gets logged but never submitted.

---

## Pillar 4: Stealth & Evasion

Most bounty targets have WAFs. Getting blocked on page 3 means nothing else matters.

### Layer 1 — Behavioral (blend in as real user)
- Visit homepage first, follow links naturally (no alphabetical spidering)
- Mouse movement / scroll simulation before form interaction
- Respect Referer chains — plausible referrer on every request
- Human-like delay distribution (Gaussian curve, not uniform random)

### Layer 2 — Fingerprint (look like a real browser)
- Consistent browser profile per scan (UA + WebGL + canvas + timezone match)
- Use `playwright-extra` stealth plugin if needed
- Don't mix Chrome UA with Firefox fingerprint

### Layer 3 — Payload delivery (survive WAF inspection)
- Existing: 6 encoding strategies (url, double-url, html-entity, unicode, mixed, sql-comment)
- Add: `String.fromCharCode()` construction, chunked transfer encoding, JSON Unicode escaping
- **Adaptive strategy:** If payload gets blocked (403/406), switch encoding before trying next payload. Don't burn all payloads with same encoding.

### Layer 4 — Rate adaptation
- Detect rate limiting (429, CAPTCHA pages, connection resets)
- Auto-backoff: exponential delay increase on detection
- Extend `DomainRateLimiter` to auto-detect and adapt

### Explicitly skip
- IP rotation / proxy chains — cost, complexity, most programs don't need it
- CAPTCHA auto-solving — handled by escalation queue (Pillar 4b)
- TLS fingerprint manipulation — diminishing returns

---

## Pillar 4b: Human Escalation Queue

SecBot does 95% of work autonomously, queues the 5% that needs a human.

### Two Operating Modes

**Autonomous mode (cron, overnight):**
- Hits CAPTCHA → skip endpoint, flag it, keep scanning everything else
- Finds ambiguous finding → queue for human review
- Encounters 2FA/SMS → flag, move on
- Result: morning report with findings + "needs your help" queue

**Assisted mode (human at keyboard):**
- Hits CAPTCHA → opens browser visually, human solves it, scanning continues
- Co-pilot model — bot drives, human handles roadblocks
- For high-value targets where maximum coverage matters

### Queue Format
```json
{
  "target": "example.com",
  "scanDate": "2026-03-12T08:00:00Z",
  "completed": 47,
  "needsHuman": 3,
  "blocked": [
    { "url": "/admin/login", "reason": "captcha", "type": "recaptcha-v2" },
    { "url": "/api/reset", "reason": "2fa-required" },
    { "url": "/checkout", "reason": "ambiguous-finding", "confidence": "medium" }
  ]
}
```

Stored at `~/.secbot/queue/{program}/{date}.json`.

### Notification
SecBot sends Telegram message via Nara: "Finished scanning example.com — 4 findings ready to submit, 3 endpoints need your help."

---

## Pillar 5: Self-Defense Hardening

SecBot visits adversarial websites. Targets could intentionally attack the scanner.

### Threat: Prompt injection via HTTP responses
Malicious site embeds "ignore previous instructions" in response body to manipulate Claude.
- **Mitigation:** Strengthen `sanitizeForPrompt()`. Wrap all evidence in explicit `<evidence>` delimiters. System prompt instructs Claude to treat evidence as untrusted data, never follow instructions within it.

### Threat: Payload reflection attacks
SecBot sends XSS payload, site reflects it, Playwright executes it.
- **Mitigation:** Isolated browser context per active check. Disable JS execution during payload reflection analysis (inspect raw HTML). No shared cookies/storage between check runs.

### Threat: Resource exhaustion
Infinite redirects, huge response bodies, WebSocket floods.
- **Mitigation:** Hard limits — max 10 redirects, max 1MB response body, max 30s per request, max 100 WebSocket messages per connection.

### Threat: Scanner fingerprinting
Target detects scanning, serves clean responses to scanner.
- **Mitigation:** Consistent browser fingerprinting (Pillar 4). Randomize payload order. Don't follow predictable scanning patterns.

### Threat: DNS rebinding
Target resolves to public IP during crawl, rebinds to 127.0.0.1 during active checks.
- **Mitigation:** Pin DNS resolution at scan start. Verify resolved IP before sending payloads. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x) unless target is explicitly internal.

### Explicitly skip
- Sandboxed VMs per scan — overkill, Playwright isolation is sufficient
- Full network isolation — unnecessary for bounty hunting
- Code signing of payloads — unnecessary complexity

---

## Pillar 6: Autonomous Hunting Mode

SecBot runs on a schedule, hunts across multiple programs, generates draft reports.

### Program Registry (`~/.secbot/programs.yaml`)
```yaml
programs:
  - name: "Example Corp"
    platform: hackerone
    scope_file: ./scopes/example-corp.scope
    profile: standard
    schedule: weekly
    auth: ./auth/example-corp.json
  - name: "Acme Inc"
    platform: bugcrowd
    scope_file: ./scopes/acme.scope
    profile: deep
    schedule: daily
```

### Scan Orchestrator
- Runs via cron on Mac Mini (home or office)
- Reads program registry, launches scans for programs due
- Sequential program scanning (don't scan 10 targets simultaneously)
- Respects rate limits between programs
- Results stored at `~/.secbot/results/{program}/{date}.json`

### Report Pipeline
1. Scan completes → `confidence: high` findings auto-formatted for platform
2. `confidence: medium` → escalation queue for human review
3. Baseline diff — only surface NEW findings (already implemented)
4. Draft reports saved to `~/.secbot/drafts/{program}/{date}.md`
5. Human reviews drafts → submits to platform

### Key Constraint
**Never auto-submit.** Always human review before submission. One bad submission damages reputation permanently.

---

## Pillar 7: Self-Learning Loop

SecBot gets smarter with every hunt. No ML, no training — structured memory from experience.

### Data Sources

**Bounty outcome tracking:**
- After submitting, mark report: `accepted`, `duplicate`, `informative`, `not-applicable`
- Build success rates per check type, per tech stack, per WAF
- Example insight: "CORS findings on API-only targets = 90% duplicate — deprioritize"

**False positive memory:**
- Every discarded finding during review: record target type + check + evidence pattern
- Before next scan, check: "have I seen this pattern marked FP before?"
- Builds local FP ruleset specific to your hunting experience

**Tech stack profiles:**
- "React + Express + Cloudflare: XSS rarely works, focus on IDOR and access control"
- "PHP + MySQL + no WAF: SQLi almost always works, prioritize it"
- Empirical data from YOUR scans, beyond AI planner heuristics

**Payload effectiveness:**
- Track which payloads triggered real findings vs which always fail
- Per-WAF tracking: "double-URL encoding bypasses Cloudflare 60%, unicode only 20%"
- Prune ineffective payloads, promote effective ones

### Storage (`~/.secbot/learning/`)
```
outcomes.json       — bounty submission results
false-positives.json — discarded finding patterns
tech-profiles.json   — tech stack → effective checks mapping
payload-stats.json   — payload success rates per WAF
```

### Feedback Integration
- AI planner receives learning data as additional context
- Confidence scoring adjusts based on past accuracy
- Payload ordering prioritizes historically effective payloads
- Check selection weighted by empirical success rates for detected tech stack

---

## Implementation Phases

```
Phase 1: Validate     → Scan real targets, catalog gaps (no code changes)
Phase 2: Harden       → Detection depth + stealth + self-defense
Phase 3: Eliminate FP  → Confidence scoring + auto-verify + two-pass validation
Phase 4: Automate     → Cron hunting + escalation queue + Nara notifications
Phase 5: Learn        → Outcome tracking + FP memory + payload stats + feedback loop
```

Each phase produces a working, testable improvement. Phase 1 informs Phase 2 priorities. Phases can overlap where independent.

## Explicitly Out of Scope
- npm publish, README, onboarding UX
- IP rotation / proxy chains
- CAPTCHA auto-solving services
- Second-order SQLi, HTTP request smuggling
- Sandboxed VMs
- ML model training

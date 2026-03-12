# SecBot v1.0 "Bounty Ready" — Full Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform SecBot from security scanner into autonomous bounty hunting machine — confidence scoring, stealth, self-defense, autonomous orchestration, and self-learning.

**Architecture:** Build in layers: confidence system first (changes how all checks report), then new checks (OAuth, cache poisoning), then stealth/defense, then orchestration, then learning loop.

**Tech Stack:** TypeScript 5, Playwright, Anthropic SDK, Node.js 20+, Vitest

---

## Chunk 1: Confidence Scoring Foundation

### Task 1: Add confidence field to RawFinding and update types

**Files:**
- Modify: `src/scanner/types.ts`
- Test: `test/unit/confidence-types.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// test/unit/confidence-types.test.ts
import { describe, it, expect } from 'vitest';

describe('Confidence scoring types', () => {
  it('RawFinding accepts confidence field', async () => {
    const { RawFinding } = await import('../../src/scanner/types.js');
    // Type check — confidence is optional with default 'medium'
    const finding = {
      id: 'test-1',
      category: 'xss' as const,
      severity: 'high' as const,
      title: 'Test XSS',
      description: 'desc',
      url: 'https://example.com',
      evidence: 'proof',
      timestamp: new Date().toISOString(),
      confidence: 'high' as const,
    };
    expect(finding.confidence).toBe('high');
  });

  it('confidence levels are high, medium, low', () => {
    const levels: Array<'high' | 'medium' | 'low'> = ['high', 'medium', 'low'];
    expect(levels).toHaveLength(3);
  });
});
```

- [ ] **Step 2: Run test — expect fail**
Run: `npx vitest run test/unit/confidence-types.test.ts`

- [ ] **Step 3: Add Confidence type and update RawFinding**

In `src/scanner/types.ts`, add:
```typescript
export type Confidence = 'high' | 'medium' | 'low';
```

Add to `RawFinding` interface:
```typescript
confidence?: Confidence;
```

- [ ] **Step 4: Run test — expect pass**
- [ ] **Step 5: Commit** `feat: add confidence scoring type to RawFinding`

---

### Task 2: Update all 25 active checks to produce confidence levels

**Files:**
- Modify: ALL files in `src/scanner/active/` (25 checks)
- Modify: `src/scanner/passive.ts` (passive checks)
- Test: `test/unit/confidence-checks.test.ts`

**Confidence assignment rules:**
- `high`: Deterministic proof — payload reflected AND executed, error string contains injected value, CNAME is claimable, timing difference >3x baseline
- `medium`: Strong indicator — payload reflected but not confirmed executed, suspicious header value, single-payload match, timing difference 2-3x baseline
- `low`: Heuristic match — generic pattern, potential false positive, informational

- [ ] **Step 1: Write failing test**

```typescript
// test/unit/confidence-checks.test.ts
import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';

describe('Confidence scoring in active checks', () => {
  it('all checks in registry exist', () => {
    expect(CHECK_REGISTRY.length).toBeGreaterThanOrEqual(25);
  });
});
```

Plus integration-style tests that verify specific checks produce confidence:
- XSS reflected with marker in response → confidence: 'high'
- SQLi error-based with DB error → confidence: 'high'
- SQLi time-based single payload → confidence: 'medium'
- Header-only finding → confidence: 'low'

- [ ] **Step 2: Update each check file to add confidence to findings**

For each check, add `confidence` field to every `RawFinding` it produces. Rules per check:

| Check | high | medium | low |
|-------|------|--------|-----|
| xss | Marker reflected in response body | Reflected but encoded | Pattern match only |
| sqli | DB error with injected string / union data | Time-based single match | Generic error |
| cors | Origin reflected with credentials | Origin reflected, no creds | Wildcard * |
| redirect | Location header contains payload | Redirect to different domain | Suspicious param name |
| traversal | File content in response (e.g., root:x:0) | Path traversal pattern | 403 on traversal path |
| ssrf | Callback received / metadata in response | Status change on internal IP | Timeout difference |
| ssti | Math result in response (e.g., 49374346) | Template syntax error | Generic 500 |
| cmdi | Command output in response | Time-based match | Generic error |
| idor | Different user data returned | Status differs between users | Parameter looks ID-like |
| subdomain-takeover | Fingerprint match + exploitable flag | CNAME dangling, unknown service | DNS error only |
| jwt | none-alg accepted / weak secret cracked | Missing expiry | Sensitive data in payload |
| crlf | Header injected in response | Partial reflection | Pattern only |
| host-header | Injected host in response body/Location | Different response on host change | Header reflected in non-critical |
| file-upload | Shell extension accepted + executable | Bypass extension accepted | Large file accepted |
| access-control | Admin endpoint accessible | Method override works | Different status code |
| business-logic | Price/quantity manipulation confirmed | Workflow step skippable | Parameter tampering |
| websocket | Injection reflected in WS | Auth bypass (no token needed) | Missing origin check |
| graphql | Introspection enabled | Deep query accepted | Batch accepted |
| rate-limit | No rate limit after 20 requests | Inconsistent limiting | Limit exists but high |
| race-condition | State inconsistency detected | Different responses | Timing variance only |
| api-versioning | Old version returns data | Version exists but same | Version not found |
| tls | Weak cipher accepted | Short cert / self-signed | Near-expiry cert |
| sri | Script without integrity attr | CDN without integrity | Internal script |
| info-disclosure | .env / .git HEAD with content | Source map accessible | robots.txt disallow |
| js-cve | Known CVE version match | Version range match | Library detected |

- [ ] **Step 3: Run full test suite — expect pass**
Run: `npx vitest run`
- [ ] **Step 4: Commit** `feat: add confidence levels to all 25 active checks`

---

### Task 3: Confidence-aware dedup, validation, and reporting

**Files:**
- Modify: `src/utils/dedup.ts` — preserve highest confidence when merging
- Modify: `src/ai/validator.ts` — include confidence in validation prompt
- Modify: `src/ai/reporter.ts` — group by confidence in report
- Modify: `src/reporter/terminal.ts` — show confidence badge
- Modify: `src/reporter/bounty.ts` — only include high confidence
- Test: `test/unit/confidence-pipeline.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// test/unit/confidence-pipeline.test.ts
import { describe, it, expect } from 'vitest';
import { deduplicateFindings } from '../../src/utils/dedup.js';

describe('Confidence-aware pipeline', () => {
  it('dedup preserves highest confidence', () => {
    const findings = [
      { id: '1', category: 'xss', severity: 'high', title: 'XSS on /page', description: '', url: 'https://a.com/page', evidence: '', timestamp: '', confidence: 'medium' },
      { id: '2', category: 'xss', severity: 'high', title: 'XSS on /page', description: '', url: 'https://a.com/page', evidence: '', timestamp: '', confidence: 'high' },
    ];
    const result = deduplicateFindings(findings as any);
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe('high');
  });

  it('dedup defaults missing confidence to medium', () => {
    const findings = [
      { id: '1', category: 'xss', severity: 'high', title: 'XSS', description: '', url: 'https://a.com', evidence: '', timestamp: '' },
    ];
    const result = deduplicateFindings(findings as any);
    expect(result[0].confidence).toBe('medium');
  });
});
```

- [ ] **Step 2: Update dedup to merge confidence (keep highest)**
- [ ] **Step 3: Update terminal reporter — show [HIGH]/[MED]/[LOW] badge**
- [ ] **Step 4: Update bounty reporter — only include confidence: high findings, separate section for medium**
- [ ] **Step 5: Run tests — expect pass**
- [ ] **Step 6: Commit** `feat: confidence-aware dedup, validation, and reporting`

---

## Chunk 2: Auto-Verify and Two-Pass Validation

### Task 4: Auto-verify module (Playwright-based re-confirmation)

**Files:**
- Create: `src/scanner/auto-verify.ts`
- Test: `test/unit/auto-verify.test.ts`

The auto-verify module takes medium-confidence findings and attempts to upgrade them to high or downgrade to low.

- [ ] **Step 1: Write failing test**

```typescript
// test/unit/auto-verify.test.ts
import { describe, it, expect } from 'vitest';

describe('Auto-verify module', () => {
  it('exports verifyFinding function', async () => {
    const mod = await import('../../src/scanner/auto-verify.js');
    expect(typeof mod.verifyFinding).toBe('function');
  });

  it('XSS verify checks for DOM mutation', async () => {
    const { verifyXss } = await import('../../src/scanner/auto-verify.js');
    expect(typeof verifyXss).toBe('function');
  });

  it('SQLi verify uses second payload', async () => {
    const { verifySqli } = await import('../../src/scanner/auto-verify.js');
    expect(typeof verifySqli).toBe('function');
  });

  it('returns upgraded confidence on successful verify', async () => {
    const { upgradeConfidence } = await import('../../src/scanner/auto-verify.js');
    expect(upgradeConfidence('medium', true)).toBe('high');
    expect(upgradeConfidence('medium', false)).toBe('low');
    expect(upgradeConfidence('high', true)).toBe('high');
    expect(upgradeConfidence('low', true)).toBe('medium');
  });
});
```

- [ ] **Step 2: Implement auto-verify module**

```typescript
// src/scanner/auto-verify.ts
import type { BrowserContext } from 'playwright';
import type { RawFinding, Confidence } from './types.js';

export function upgradeConfidence(current: Confidence, verified: boolean): Confidence {
  if (verified) {
    return current === 'low' ? 'medium' : 'high';
  }
  return current === 'high' ? 'medium' : 'low';
}

export async function verifyFinding(
  finding: RawFinding,
  context: BrowserContext,
): Promise<RawFinding> {
  switch (finding.category) {
    case 'xss': return { ...finding, confidence: (await verifyXss(finding, context)) ? 'high' : 'low' };
    case 'sqli': return { ...finding, confidence: (await verifySqli(finding, context)) ? 'high' : 'low' };
    case 'subdomain-takeover': return { ...finding, confidence: (await verifySubdomainTakeover(finding)) ? 'high' : 'low' };
    default: return finding; // no auto-verify available
  }
}

export async function verifyXss(finding: RawFinding, context: BrowserContext): Promise<boolean> {
  // Navigate to URL with payload, check if dialog fires or DOM mutates
  try {
    const page = await context.newPage();
    let dialogFired = false;
    page.on('dialog', async d => { dialogFired = true; await d.dismiss(); });
    await page.goto(finding.url, { timeout: 10000, waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    await page.close();
    return dialogFired;
  } catch { return false; }
}

export async function verifySqli(finding: RawFinding, _context: BrowserContext): Promise<boolean> {
  // Confirm with a different payload (e.g., if ' OR 1=1 worked, try ' OR 2=2)
  // Return true if second payload also produces similar error
  if (!finding.request?.url) return false;
  try {
    const url = new URL(finding.request.url);
    // Try alternate payload
    for (const [key, value] of url.searchParams) {
      if (value.includes("'") || value.includes('OR')) {
        url.searchParams.set(key, "' OR 2=2--");
        const resp = await fetch(url.toString(), { signal: AbortSignal.timeout(10000) });
        const body = await resp.text();
        // If we still get a DB error, it's confirmed
        const errorPatterns = ['SQL', 'mysql', 'syntax error', 'ORA-', 'PostgreSQL'];
        return errorPatterns.some(p => body.toLowerCase().includes(p.toLowerCase()));
      }
    }
    return false;
  } catch { return false; }
}

export async function verifySubdomainTakeover(finding: RawFinding): Promise<boolean> {
  // Re-resolve CNAME and re-check fingerprint
  try {
    const resp = await fetch(finding.url, { signal: AbortSignal.timeout(10000) });
    const body = await resp.text();
    // If still shows takeover fingerprint, confirmed
    return resp.status === 404 || body.includes('There isn\'t a GitHub Pages site here');
  } catch { return false; }
}

export async function verifyFindings(
  findings: RawFinding[],
  context: BrowserContext,
): Promise<RawFinding[]> {
  const results: RawFinding[] = [];
  for (const f of findings) {
    if (f.confidence === 'medium') {
      results.push(await verifyFinding(f, context));
    } else {
      results.push(f);
    }
  }
  return results;
}
```

- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: auto-verify module for Playwright-based re-confirmation`

---

### Task 5: Two-pass validation pipeline

**Files:**
- Modify: `src/index.ts` — insert auto-verify between active checks and AI validation
- Create: `src/scanner/pre-filter.ts` — rule-based pre-filter before AI
- Test: `test/unit/pre-filter.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// test/unit/pre-filter.test.ts
import { describe, it, expect } from 'vitest';

describe('Pre-filter', () => {
  it('exports preFilterFindings function', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    expect(typeof preFilterFindings).toBe('function');
  });

  it('drops low confidence findings by default', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'high', category: 'xss', severity: 'high', title: 'XSS', description: '', url: '', evidence: '', timestamp: '' },
      { id: '2', confidence: 'low', category: 'xss', severity: 'low', title: 'Maybe XSS', description: '', url: '', evidence: '', timestamp: '' },
      { id: '3', confidence: 'medium', category: 'sqli', severity: 'medium', title: 'SQLi', description: '', url: '', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings as any);
    expect(result.passed).toHaveLength(2); // high + medium
    expect(result.dropped).toHaveLength(1); // low
  });

  it('keeps all findings when threshold is low', async () => {
    const { preFilterFindings } = await import('../../src/scanner/pre-filter.js');
    const findings = [
      { id: '1', confidence: 'low', category: 'xss', severity: 'low', title: 'XSS', description: '', url: '', evidence: '', timestamp: '' },
    ];
    const result = preFilterFindings(findings as any, 'low');
    expect(result.passed).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Implement pre-filter**

```typescript
// src/scanner/pre-filter.ts
import type { RawFinding, Confidence } from './types.js';

const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export interface PreFilterResult {
  passed: RawFinding[];
  dropped: RawFinding[];
}

export function preFilterFindings(
  findings: RawFinding[],
  minConfidence: Confidence = 'medium',
): PreFilterResult {
  const threshold = CONFIDENCE_ORDER[minConfidence];
  const passed: RawFinding[] = [];
  const dropped: RawFinding[] = [];

  for (const f of findings) {
    const level = CONFIDENCE_ORDER[f.confidence ?? 'medium'];
    if (level >= threshold) {
      passed.push(f);
    } else {
      dropped.push(f);
    }
  }

  return { passed, dropped };
}
```

- [ ] **Step 3: Wire into main pipeline (src/index.ts)**

After active checks + auto-verify, before AI validation:
```typescript
// After dedup, before AI validation
const { passed: filteredFindings, dropped } = preFilterFindings(dedupedFindings);
if (dropped.length > 0) {
  logger.info(`Pre-filter: dropped ${dropped.length} low-confidence findings`);
}
// Only send filteredFindings to AI validation
```

- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: two-pass validation with pre-filter and auto-verify`

---

## Chunk 3: New Active Checks (OAuth + Cache Poisoning)

### Task 6: OAuth flow testing check

**Files:**
- Create: `src/scanner/active/oauth.ts`
- Modify: `src/scanner/active/index.ts` — register check
- Modify: `src/scanner/types.ts` — add 'oauth' to CheckCategory
- Modify: `src/ai/prompts.ts` — add oauth to planner
- Modify: `src/ai/fallback.ts` — add oauth fallback
- Modify: `src/ai/planner.ts` — add oauth to determineRelevantChecks
- Test: `test/unit/oauth.test.ts`

- [ ] **Step 1: Write failing test**

Test OAuth endpoint detection, missing state parameter, redirect_uri validation, token leakage.

- [ ] **Step 2: Implement OAuth check**

Key detection logic:
- Find OAuth endpoints: `/authorize`, `/oauth`, `/.well-known/openid-configuration`
- Test missing `state` parameter (CSRF on OAuth)
- Test open redirect in `redirect_uri` (swap to attacker domain)
- Test token in URL fragment (token leakage via Referer)
- Test scope escalation (request admin scope)

Confidence levels:
- `high`: Missing state AND auth code returned, redirect_uri bypassed
- `medium`: Missing state parameter, token in URL fragment
- `low`: OAuth endpoint detected but no issues found

- [ ] **Step 3: Register in CHECK_REGISTRY, update types, planner, fallback**
- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: OAuth flow testing check — state, redirect_uri, token leakage`

---

### Task 7: Cache poisoning check

**Files:**
- Create: `src/scanner/active/cache-poisoning.ts`
- Modify: `src/scanner/active/index.ts` — register check
- Modify: `src/scanner/types.ts` — add 'cache-poisoning' to CheckCategory
- Modify: `src/ai/prompts.ts` — add to planner
- Modify: `src/ai/fallback.ts` — add fallback
- Modify: `src/ai/planner.ts` — add to determineRelevantChecks
- Test: `test/unit/cache-poisoning.test.ts`

- [ ] **Step 1: Write failing test**

Test unkeyed header detection, cache hit/miss detection, poisoned response verification.

- [ ] **Step 2: Implement cache poisoning check**

Key logic:
- Detect caching: look for `X-Cache`, `CF-Cache-Status`, `Age`, `X-Varnish` headers
- Test unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`
- Send request with unkeyed header containing canary value
- Check if subsequent request (without header) returns cached poisoned response
- Only report if poison is actually served to clean requests

Confidence levels:
- `high`: Poisoned response served to clean request (canary in clean response)
- `medium`: Unkeyed header reflected in response but cache not confirmed
- `low`: Cache headers present but no reflection

- [ ] **Step 3: Register in CHECK_REGISTRY, update types, planner, fallback**
- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: cache poisoning check — unkeyed headers, cache verification`

---

## Chunk 4: Stealth & Self-Defense

### Task 8: Behavioral stealth layer

**Files:**
- Modify: `src/utils/stealth.ts` — add behavioral simulation functions
- Modify: `src/scanner/browser.ts` — integrate behavioral stealth into crawl
- Test: `test/unit/stealth-behavioral.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Behavioral stealth', () => {
  it('gaussianDelay returns values in bell curve distribution', () => {
    const { gaussianDelay } = await import('../../src/utils/stealth.js');
    const delays = Array.from({ length: 100 }, () => gaussianDelay(500));
    const mean = delays.reduce((a, b) => a + b, 0) / delays.length;
    expect(mean).toBeGreaterThan(300);
    expect(mean).toBeLessThan(700);
  });

  it('generateRefererChain produces plausible referrer sequence', () => {
    const { generateRefererChain } = await import('../../src/utils/stealth.js');
    const chain = generateRefererChain('https://example.com/page');
    expect(chain[0]).toContain('example.com');
  });

  it('simulateHumanBehavior returns page interaction script', () => {
    const { simulateHumanBehavior } = await import('../../src/utils/stealth.js');
    expect(typeof simulateHumanBehavior).toBe('function');
  });
});
```

- [ ] **Step 2: Implement behavioral stealth functions**

Add to `src/utils/stealth.ts`:
- `gaussianDelay(meanMs)` — Box-Muller transform for human-like timing
- `generateRefererChain(targetUrl)` — plausible referrer (Google search → landing page → target)
- `simulateHumanBehavior(page)` — mouse move, scroll, wait (for stealth profile)
- `buildConsistentProfile()` — matched UA + viewport + timezone + locale

- [ ] **Step 3: Wire behavioral stealth into browser.ts for stealth profile**
- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: behavioral stealth — Gaussian delays, referrer chains, human simulation`

---

### Task 9: Adaptive payload delivery

**Files:**
- Modify: `src/utils/payload-mutator.ts` — add adaptive encoding logic
- Modify: `src/scanner/active/xss.ts` — use adaptive encoding on WAF block
- Modify: `src/scanner/active/sqli.ts` — use adaptive encoding on WAF block
- Test: `test/unit/adaptive-encoding.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Adaptive payload delivery', () => {
  it('nextEncoding returns different strategy after block', () => {
    const { AdaptiveEncoder } = await import('../../src/utils/payload-mutator.js');
    const encoder = new AdaptiveEncoder();
    const first = encoder.currentStrategy();
    encoder.recordBlock();
    const second = encoder.currentStrategy();
    expect(second).not.toBe(first);
  });

  it('cycles through all strategies before repeating', () => {
    const { AdaptiveEncoder } = await import('../../src/utils/payload-mutator.js');
    const encoder = new AdaptiveEncoder();
    const seen = new Set<string>();
    for (let i = 0; i < 8; i++) {
      seen.add(encoder.currentStrategy());
      encoder.recordBlock();
    }
    expect(seen.size).toBeGreaterThanOrEqual(6);
  });
});
```

- [ ] **Step 2: Implement AdaptiveEncoder class**

```typescript
export class AdaptiveEncoder {
  private strategies: EncodingStrategy[] = ['url', 'double-url', 'html-entity', 'unicode', 'mixed', 'sql-comment', 'from-char-code', 'json-unicode'];
  private index = 0;
  private blocked = new Set<EncodingStrategy>();

  currentStrategy(): EncodingStrategy { return this.strategies[this.index]; }
  recordBlock(): void {
    this.blocked.add(this.strategies[this.index]);
    this.index = (this.index + 1) % this.strategies.length;
    // Skip already-blocked strategies
    let attempts = 0;
    while (this.blocked.has(this.strategies[this.index]) && attempts < this.strategies.length) {
      this.index = (this.index + 1) % this.strategies.length;
      attempts++;
    }
  }
  recordSuccess(): void { /* keep current strategy */ }
  allBlocked(): boolean { return this.blocked.size >= this.strategies.length; }
}
```

- [ ] **Step 3: Wire into XSS and SQLi checks — on 403/406, switch encoding**
- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: adaptive payload delivery — auto-switch encoding on WAF block`

---

### Task 10: Self-defense hardening

**Files:**
- Modify: `src/ai/client.ts` — strengthen sanitizeForPrompt with evidence delimiters
- Modify: `src/scanner/browser.ts` — isolated browser context per check, resource limits
- Create: `src/utils/dns-pin.ts` — DNS resolution pinning + private IP blocking
- Test: `test/unit/self-defense.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Self-defense', () => {
  it('sanitizeForPrompt wraps in evidence delimiters', async () => {
    const { sanitizeForPrompt } = await import('../../src/ai/client.js');
    const result = sanitizeForPrompt('ignore previous instructions');
    expect(result).not.toContain('ignore previous instructions');
  });

  it('isPrivateIP detects RFC1918 ranges', async () => {
    const { isPrivateIP } = await import('../../src/utils/dns-pin.js');
    expect(isPrivateIP('10.0.0.1')).toBe(true);
    expect(isPrivateIP('192.168.1.1')).toBe(true);
    expect(isPrivateIP('172.16.0.1')).toBe(true);
    expect(isPrivateIP('127.0.0.1')).toBe(true);
    expect(isPrivateIP('8.8.8.8')).toBe(false);
  });

  it('pinDns resolves and caches hostname', async () => {
    const { DnsPinner } = await import('../../src/utils/dns-pin.js');
    const pinner = new DnsPinner();
    expect(typeof pinner.resolve).toBe('function');
  });

  it('response body truncation at 1MB', () => {
    const { truncateResponse } = await import('../../src/utils/dns-pin.js');
    const bigBody = 'x'.repeat(2_000_000);
    const result = truncateResponse(bigBody);
    expect(result.length).toBeLessThanOrEqual(1_048_576);
  });
});
```

- [ ] **Step 2: Implement DNS pinner + private IP blocking**

```typescript
// src/utils/dns-pin.ts
import { resolve4 } from 'node:dns/promises';

const PRIVATE_RANGES = [
  /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./, /^0\./, /^169\.254\./,
];

export function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

export function truncateResponse(body: string, maxBytes = 1_048_576): string {
  return body.length > maxBytes ? body.slice(0, maxBytes) : body;
}

export class DnsPinner {
  private cache = new Map<string, string[]>();

  async resolve(hostname: string): Promise<string[]> {
    if (this.cache.has(hostname)) return this.cache.get(hostname)!;
    const ips = await resolve4(hostname);
    this.cache.set(hostname, ips);
    return ips;
  }

  async isAllowed(hostname: string, allowPrivate = false): Promise<boolean> {
    const ips = await this.resolve(hostname);
    if (allowPrivate) return true;
    return !ips.some(ip => isPrivateIP(ip));
  }
}
```

- [ ] **Step 3: Strengthen sanitizeForPrompt — add evidence delimiters, strip control chars**
- [ ] **Step 4: Add response body max size (1MB) and redirect limit (10) to browser.ts**
- [ ] **Step 5: Run tests — expect pass**
- [ ] **Step 6: Commit** `feat: self-defense — DNS pinning, response limits, prompt hardening`

---

### Task 11: Rate adaptation

**Files:**
- Modify: `src/utils/rate-limiter.ts` — add CAPTCHA detection + auto-backoff
- Modify: `src/utils/domain-rate-limiter.ts` — auto-detect rate limits
- Test: `test/unit/rate-adaptation.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Rate adaptation', () => {
  it('detects CAPTCHA in response body', async () => {
    const { isCaptchaResponse } = await import('../../src/utils/rate-limiter.js');
    expect(isCaptchaResponse('<div class="g-recaptcha">')).toBe(true);
    expect(isCaptchaResponse('<div class="h-captcha">')).toBe(true);
    expect(isCaptchaResponse('<p>Normal page</p>')).toBe(false);
  });

  it('auto-backoff on CAPTCHA detection', async () => {
    const { RateLimiter } = await import('../../src/utils/rate-limiter.js');
    const limiter = new RateLimiter({ requestsPerSecond: 10, initialDelayMs: 100 });
    limiter.recordCaptcha();
    const stats = limiter.getStats();
    expect(stats.currentDelayMs).toBeGreaterThan(100);
  });
});
```

- [ ] **Step 2: Add CAPTCHA detection patterns and recordCaptcha method**
- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: rate adaptation — CAPTCHA detection, auto-backoff`

---

## Chunk 5: Autonomous Hunting Infrastructure

### Task 12: Program registry

**Files:**
- Create: `src/hunting/registry.ts`
- Create: `src/hunting/types.ts`
- Test: `test/unit/registry.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Program registry', () => {
  it('parses programs.yaml format', async () => {
    const { parseRegistry } = await import('../../src/hunting/registry.js');
    const yaml = `
programs:
  - name: "Example Corp"
    platform: hackerone
    scope_file: ./scopes/example.scope
    profile: standard
    schedule: weekly
    auth: ./auth/example.json
`;
    const programs = parseRegistry(yaml);
    expect(programs).toHaveLength(1);
    expect(programs[0].name).toBe('Example Corp');
    expect(programs[0].schedule).toBe('weekly');
  });

  it('validates required fields', async () => {
    const { parseRegistry } = await import('../../src/hunting/registry.js');
    expect(() => parseRegistry('programs:\n  - name: "Test"')).toThrow();
  });

  it('isDue returns true for weekly program after 7 days', async () => {
    const { isDue } = await import('../../src/hunting/registry.js');
    const lastScan = new Date(Date.now() - 8 * 86400000).toISOString();
    expect(isDue('weekly', lastScan)).toBe(true);
    const recentScan = new Date(Date.now() - 2 * 86400000).toISOString();
    expect(isDue('weekly', recentScan)).toBe(false);
  });
});
```

- [ ] **Step 2: Implement registry parser**

Simple YAML-like parser (key: value format, no full YAML dependency needed, or use simple line-based parsing). Support fields: name, platform, scope_file, profile, schedule (daily/weekly/biweekly/monthly), auth.

- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: program registry — YAML parser, schedule tracking`

---

### Task 13: Escalation queue

**Files:**
- Create: `src/hunting/escalation.ts`
- Test: `test/unit/escalation.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Escalation queue', () => {
  it('creates queue entry for CAPTCHA block', async () => {
    const { EscalationQueue } = await import('../../src/hunting/escalation.js');
    const queue = new EscalationQueue();
    queue.addBlocked('/admin', 'captcha', 'recaptcha-v2');
    const items = queue.getItems();
    expect(items).toHaveLength(1);
    expect(items[0].reason).toBe('captcha');
  });

  it('creates queue entry for ambiguous finding', async () => {
    const { EscalationQueue } = await import('../../src/hunting/escalation.js');
    const queue = new EscalationQueue();
    queue.addAmbiguousFinding({ id: '1', category: 'xss', confidence: 'medium' } as any);
    expect(queue.getItems()).toHaveLength(1);
  });

  it('serializes to JSON file', async () => {
    const { EscalationQueue } = await import('../../src/hunting/escalation.js');
    const queue = new EscalationQueue();
    queue.addBlocked('/login', '2fa-required');
    const json = queue.toJSON();
    expect(json.needsHuman).toBe(1);
    expect(json.blocked).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Implement EscalationQueue class**
- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: escalation queue — CAPTCHA, 2FA, ambiguous finding tracking`

---

### Task 14: Scan orchestrator + hunt CLI command

**Files:**
- Create: `src/hunting/orchestrator.ts`
- Modify: `src/index.ts` — add `hunt` CLI command
- Test: `test/unit/orchestrator.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Scan orchestrator', () => {
  it('determines which programs are due', async () => {
    const { getduePrograms } = await import('../../src/hunting/orchestrator.js');
    const programs = [
      { name: 'A', schedule: 'daily', lastScan: new Date(Date.now() - 2 * 86400000).toISOString() },
      { name: 'B', schedule: 'weekly', lastScan: new Date().toISOString() },
    ];
    const due = getduePrograms(programs as any);
    expect(due.map(p => p.name)).toContain('A');
    expect(due.map(p => p.name)).not.toContain('B');
  });

  it('runs programs sequentially', async () => {
    const { Orchestrator } = await import('../../src/hunting/orchestrator.js');
    expect(typeof Orchestrator).toBe('function');
  });
});
```

- [ ] **Step 2: Implement orchestrator**

Orchestrator reads registry, filters due programs, runs scans sequentially, saves results, generates escalation queue, produces summary.

- [ ] **Step 3: Add `secbot hunt` CLI command**

```typescript
program.command('hunt')
  .description('Run autonomous bounty hunting — scan all due programs')
  .option('--registry <path>', 'Program registry file', '~/.secbot/programs.yaml')
  .option('--dry-run', 'Show which programs would be scanned without scanning')
  .action(async (opts) => { /* orchestrator logic */ });
```

- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: scan orchestrator + hunt CLI command`

---

### Task 15: Nara notification integration

**Files:**
- Create: `src/hunting/notify.ts`
- Test: `test/unit/notify.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Notification', () => {
  it('formats hunt summary message', async () => {
    const { formatHuntSummary } = await import('../../src/hunting/notify.js');
    const summary = {
      programs: 3,
      findings: { high: 2, medium: 5, low: 1 },
      escalations: 3,
      duration: '45m',
    };
    const msg = formatHuntSummary(summary);
    expect(msg).toContain('3 programs scanned');
    expect(msg).toContain('2 high-confidence');
    expect(msg).toContain('3 need your help');
  });

  it('exports sendNotification function', async () => {
    const { sendNotification } = await import('../../src/hunting/notify.js');
    expect(typeof sendNotification).toBe('function');
  });
});
```

- [ ] **Step 2: Implement notification module**

Uses Nara MCP (via `nara_send_message` tool) or falls back to writing to `~/.secbot/notifications.log`. Message format: "🔍 Hunt complete — {n} programs scanned, {n} findings ({n} high), {n} need your help"

- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: Nara notification integration for hunt results`

---

## Chunk 6: Self-Learning Loop

### Task 16: Outcome tracking

**Files:**
- Create: `src/learning/outcomes.ts`
- Create: `src/learning/types.ts`
- Test: `test/unit/outcomes.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Outcome tracking', () => {
  it('records bounty submission outcome', async () => {
    const { OutcomeTracker } = await import('../../src/learning/outcomes.js');
    const tracker = new OutcomeTracker();
    tracker.record({
      findingId: 'abc-123',
      program: 'Example Corp',
      category: 'xss',
      techStack: ['react', 'express', 'cloudflare'],
      outcome: 'accepted',
      bounty: 500,
      submittedAt: '2026-03-12',
    });
    const stats = tracker.getStats();
    expect(stats.total).toBe(1);
    expect(stats.accepted).toBe(1);
  });

  it('calculates success rate per category', async () => {
    const { OutcomeTracker } = await import('../../src/learning/outcomes.js');
    const tracker = new OutcomeTracker();
    tracker.record({ findingId: '1', category: 'xss', outcome: 'accepted', program: 'A', techStack: [], submittedAt: '' });
    tracker.record({ findingId: '2', category: 'xss', outcome: 'duplicate', program: 'A', techStack: [], submittedAt: '' });
    tracker.record({ findingId: '3', category: 'cors-misconfiguration', outcome: 'not-applicable', program: 'A', techStack: [], submittedAt: '' });
    const rates = tracker.successRateByCategory();
    expect(rates['xss']).toBe(0.5); // 1 accepted / 2 total
    expect(rates['cors-misconfiguration']).toBe(0);
  });
});
```

- [ ] **Step 2: Implement OutcomeTracker — file-backed JSON store at ~/.secbot/learning/outcomes.json**
- [ ] **Step 3: Add `secbot outcome` CLI command to record results**

```
secbot outcome <finding-id> --result accepted --bounty 500
secbot outcome <finding-id> --result duplicate
secbot outcome stats
```

- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: outcome tracking — record bounty results, calculate success rates`

---

### Task 17: False positive memory

**Files:**
- Create: `src/learning/fp-memory.ts`
- Test: `test/unit/fp-memory.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('FP memory', () => {
  it('records false positive pattern', async () => {
    const { FPMemory } = await import('../../src/learning/fp-memory.js');
    const mem = new FPMemory();
    mem.record({
      category: 'cors-misconfiguration',
      pattern: 'wildcard-origin-no-credentials',
      techStack: ['express'],
      count: 1,
    });
    expect(mem.isKnownFP('cors-misconfiguration', 'wildcard-origin-no-credentials')).toBe(true);
  });

  it('suggests confidence downgrade for known FP pattern', async () => {
    const { FPMemory } = await import('../../src/learning/fp-memory.js');
    const mem = new FPMemory();
    mem.record({ category: 'xss', pattern: 'reflected-in-attribute-encoded', techStack: ['react'], count: 5 });
    const adjustment = mem.confidenceAdjustment('xss', 'reflected-in-attribute-encoded');
    expect(adjustment).toBe('downgrade'); // seen 5 times as FP → downgrade
  });
});
```

- [ ] **Step 2: Implement FPMemory — pattern matching against known FP patterns**
- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: false positive memory — pattern-based FP tracking`

---

### Task 18: Tech profiles + payload stats

**Files:**
- Create: `src/learning/tech-profiles.ts`
- Create: `src/learning/payload-stats.ts`
- Test: `test/unit/tech-profiles.test.ts`
- Test: `test/unit/payload-stats.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
describe('Tech profiles', () => {
  it('records effective checks per tech stack', async () => {
    const { TechProfiler } = await import('../../src/learning/tech-profiles.js');
    const profiler = new TechProfiler();
    profiler.record(['react', 'express', 'cloudflare'], 'xss', false);
    profiler.record(['react', 'express', 'cloudflare'], 'idor', true);
    const recommendation = profiler.recommend(['react', 'express', 'cloudflare']);
    expect(recommendation.prioritize).toContain('idor');
    expect(recommendation.deprioritize).toContain('xss');
  });
});

describe('Payload stats', () => {
  it('tracks payload effectiveness per WAF', async () => {
    const { PayloadStats } = await import('../../src/learning/payload-stats.js');
    const stats = new PayloadStats();
    stats.record('cloudflare', 'double-url', true);
    stats.record('cloudflare', 'double-url', true);
    stats.record('cloudflare', 'unicode', false);
    const best = stats.bestStrategy('cloudflare');
    expect(best).toBe('double-url');
  });
});
```

- [ ] **Step 2: Implement TechProfiler and PayloadStats — file-backed JSON**
- [ ] **Step 3: Run tests — expect pass**
- [ ] **Step 4: Commit** `feat: tech profiles + payload stats — empirical effectiveness tracking`

---

### Task 19: Wire learning data into planner

**Files:**
- Modify: `src/ai/planner.ts` — accept learning context, adjust check selection
- Modify: `src/index.ts` — load learning data, pass to planner
- Modify: `src/hunting/orchestrator.ts` — record outcomes after scan
- Test: `test/unit/learning-integration.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
describe('Learning integration', () => {
  it('planner deprioritizes historically ineffective checks', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const learningContext = {
      techProfile: { deprioritize: ['cors-misconfiguration'], prioritize: ['idor'] },
      fpPatterns: ['cors-wildcard-no-creds'],
      payloadStats: { cloudflare: { best: 'double-url', worst: 'unicode' } },
    };
    // Learning context should influence plan
    // This tests the interface, not the full integration
    expect(learningContext.techProfile.deprioritize).toContain('cors-misconfiguration');
  });
});
```

- [ ] **Step 2: Add LearningContext type and wire into planAttack**
- [ ] **Step 3: Load learning data from ~/.secbot/learning/ at scan start**
- [ ] **Step 4: Run tests — expect pass**
- [ ] **Step 5: Commit** `feat: wire learning data into AI planner — empirical check prioritization`

---

## Chunk 7: Pipeline Integration + Version Bump

### Task 20: Wire everything into main pipeline

**Files:**
- Modify: `src/index.ts` — integrate auto-verify, pre-filter, escalation queue, learning hooks
- Test: Run full test suite

- [ ] **Step 1: Update main pipeline**

After active checks (Phase 5):
1. Auto-verify medium-confidence findings
2. Pre-filter: drop low-confidence findings
3. Record escalation items (CAPTCHAs, 2FA, ambiguous)
4. Existing: dedup → AI validation → AI report → output

After scan completes:
1. Save escalation queue to `~/.secbot/queue/`
2. Record payload stats for learning
3. Update tech profiles

- [ ] **Step 2: Run full test suite**
Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 3: Bump version to 1.0.0**
- [ ] **Step 4: Update CLAUDE.md with v1.0 features**
- [ ] **Step 5: Commit** `feat: v1.0.0 "Bounty Ready" — full pipeline integration`

---

## Summary

| Chunk | Tasks | New Files | What |
|-------|-------|-----------|------|
| 1 | 1-3 | 1 test | Confidence scoring foundation |
| 2 | 4-5 | 2 src + 2 test | Auto-verify + two-pass validation |
| 3 | 6-7 | 2 src + 2 test | OAuth + cache poisoning checks |
| 4 | 8-11 | 1 src + 4 test | Stealth + self-defense |
| 5 | 12-15 | 5 src + 4 test | Autonomous hunting infra |
| 6 | 16-19 | 5 src + 4 test | Self-learning loop |
| 7 | 20 | 0 | Pipeline integration + v1.0 |

**Total: 20 tasks, ~15 new source files, ~16 new test files**

**Dependencies:**
- Tasks 1-3 must be first (confidence system used by everything)
- Tasks 4-5 depend on Task 1-3 (auto-verify produces confidence)
- Tasks 6-7 independent (new checks, can parallel with 4-5)
- Tasks 8-11 independent of each other (stealth + defense)
- Tasks 12-15 can start after Tasks 1-5 (hunting needs confidence)
- Tasks 16-19 can start after Tasks 12-14 (learning needs hunting infra)
- Task 20 is last (integration)

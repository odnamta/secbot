# SecBot Path A Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform SecBot from a Phase 1 MVP (5.5/10) into a reliable developer security tool (v1.0.0) with 12 check types, tests, deduplication, route discovery, and CI/CD-ready output.

**Architecture:** Foundation-first — fix infrastructure (tests, dedup, SIGINT, dead code) before expanding checks. Each new check follows the existing plugin pattern: file in `src/scanner/active/`, registered in `CHECK_REGISTRY`. Route discovery uses a pluggable `RouteDiscoverer` interface for Path B extensibility.

**Tech Stack:** TypeScript 5, Playwright, Anthropic SDK, Vitest, Express (test server)

---

## Phase 1: Infrastructure & Quality Foundation

### Task 1: Set up test infrastructure

**Files:**
- Create: `test/fixtures/vulnerable-server.ts`
- Create: `test/setup.ts`
- Modify: `package.json` (add express dev dep, vitest config)
- Create: `vitest.config.ts`

**Step 1: Install test dependencies**

Run: `npm install -D express @types/express`

**Step 2: Create vitest config**

Create `vitest.config.ts`:
```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    root: '.',
    include: ['test/**/*.test.ts'],
    globals: true,
    testTimeout: 30000,
  },
});
```

**Step 3: Create test setup with server lifecycle**

Create `test/setup.ts`:
```typescript
import type { Server } from 'node:http';
import { createVulnerableServer } from './fixtures/vulnerable-server.js';

let server: Server;
let baseUrl: string;

export async function startTestServer(): Promise<string> {
  const { server: s, url } = await createVulnerableServer();
  server = s;
  baseUrl = url;
  return url;
}

export async function stopTestServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) server.close(() => resolve());
    else resolve();
  });
}

export function getTestUrl(): string {
  return baseUrl;
}
```

**Step 4: Create vulnerable test server**

Create `test/fixtures/vulnerable-server.ts` — an Express app with intentional vulnerabilities:
- `/` — homepage with links, missing security headers
- `/search?q=` — reflected XSS (no encoding)
- `/login` — form with POST action
- `/api/v1/users/:id` — sequential IDs (IDOR)
- `/api/v1/data?query=` — SQLi error reflection
- `/redirect?url=` — open redirect
- `/files?path=` — directory traversal
- `/fetch?url=` — SSRF endpoint
- `/template?name=` — SSTI (evaluates `{{7*7}}`)
- `/exec?cmd=` — command injection (echoes input)
- `/cors-api` — responds with `Access-Control-Allow-Origin: *` + credentials
- `/safe` — properly secured page (all headers, encoded output)
- All pages intentionally missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- One cookie without HttpOnly, one without Secure

The server should listen on a random available port and return the URL.

**Step 5: Run test to verify server starts**

Create `test/fixtures/vulnerable-server.test.ts`:
```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestServer, stopTestServer, getTestUrl } from '../setup.js';

describe('Vulnerable Test Server', () => {
  beforeAll(async () => { await startTestServer(); });
  afterAll(async () => { await stopTestServer(); });

  it('starts and responds on root', async () => {
    const res = await fetch(getTestUrl());
    expect(res.status).toBe(200);
  });

  it('has missing security headers', async () => {
    const res = await fetch(getTestUrl());
    expect(res.headers.get('content-security-policy')).toBeNull();
    expect(res.headers.get('strict-transport-security')).toBeNull();
  });

  it('reflects XSS in search', async () => {
    const res = await fetch(`${getTestUrl()}/search?q=<script>alert(1)</script>`);
    const body = await res.text();
    expect(body).toContain('<script>alert(1)</script>');
  });

  it('has open redirect', async () => {
    const res = await fetch(`${getTestUrl()}/redirect?url=https://evil.com`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://evil.com');
  });
});
```

Run: `npx vitest run test/fixtures/vulnerable-server.test.ts`
Expected: 4 PASS

**Step 6: Commit**

```bash
git add test/ vitest.config.ts package.json package-lock.json
git commit -m "test: add vulnerable test server and vitest infrastructure"
```

---

### Task 2: Unit tests for pure functions

**Files:**
- Create: `test/unit/scope.test.ts`
- Create: `test/unit/json-parser.test.ts`
- Create: `test/unit/dedup.test.ts` (created in Task 3, test first)

**Step 1: Write scope tests**

Create `test/unit/scope.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { parseScopePatterns, isInScope } from '../../src/utils/scope.js';

describe('parseScopePatterns', () => {
  it('parses include patterns', () => {
    const scope = parseScopePatterns('*.example.com,api.example.com');
    expect(scope.includePatterns).toEqual(['*.example.com', 'api.example.com']);
    expect(scope.excludePatterns).toEqual([]);
  });

  it('parses exclude patterns with - prefix', () => {
    const scope = parseScopePatterns('*.example.com,-admin.example.com');
    expect(scope.includePatterns).toEqual(['*.example.com']);
    expect(scope.excludePatterns).toEqual(['admin.example.com']);
  });

  it('handles empty input', () => {
    const scope = parseScopePatterns('');
    expect(scope.includePatterns).toEqual([]);
    expect(scope.excludePatterns).toEqual([]);
  });
});

describe('isInScope', () => {
  const target = 'https://example.com';

  it('defaults to same-origin when no scope', () => {
    expect(isInScope('https://example.com/page', target)).toBe(true);
    expect(isInScope('https://other.com/page', target)).toBe(false);
  });

  it('matches wildcard patterns', () => {
    const scope = parseScopePatterns('*.example.com');
    expect(isInScope('https://sub.example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://evil.com/page', target, scope)).toBe(false);
  });

  it('respects exclude patterns', () => {
    const scope = parseScopePatterns('*.example.com,-admin.example.com');
    expect(isInScope('https://api.example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://admin.example.com/page', target, scope)).toBe(false);
  });

  it('returns false for invalid URLs', () => {
    expect(isInScope('not-a-url', target)).toBe(false);
  });
});
```

Run: `npx vitest run test/unit/scope.test.ts`
Expected: PASS

**Step 2: Write JSON parser tests**

Create `test/unit/json-parser.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { parseJsonResponse } from '../../src/ai/client.js';

describe('parseJsonResponse', () => {
  it('parses plain JSON', () => {
    expect(parseJsonResponse('{"key": "value"}')).toEqual({ key: 'value' });
  });

  it('parses JSON in markdown code block', () => {
    const input = '```json\n{"key": "value"}\n```';
    expect(parseJsonResponse(input)).toEqual({ key: 'value' });
  });

  it('extracts JSON from surrounding text', () => {
    const input = 'Here is the result: {"key": "value"} Hope this helps!';
    expect(parseJsonResponse(input)).toEqual({ key: 'value' });
  });

  it('handles arrays', () => {
    expect(parseJsonResponse('[1, 2, 3]')).toEqual([1, 2, 3]);
  });

  it('recovers truncated JSON (unclosed bracket)', () => {
    const input = '{"key": "value", "items": [1, 2';
    const result = parseJsonResponse(input);
    expect(result).not.toBeNull();
    expect((result as Record<string, unknown>).key).toBe('value');
  });

  it('returns null for complete garbage', () => {
    expect(parseJsonResponse('not json at all')).toBeNull();
  });
});
```

Run: `npx vitest run test/unit/json-parser.test.ts`
Expected: PASS

**Step 3: Commit**

```bash
git add test/unit/
git commit -m "test: add unit tests for scope matching and JSON parser"
```

---

### Task 3: Pre-deduplication engine

**Files:**
- Create: `src/utils/dedup.ts`
- Create: `test/unit/dedup.test.ts`
- Modify: `src/index.ts` (insert dedup between Phase 5 and Phase 6)
- Modify: `src/scanner/types.ts` (add `affectedUrls` to `RawFinding`)

**Step 1: Write failing dedup test**

Create `test/unit/dedup.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { deduplicateFindings } from '../../src/utils/dedup.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    category: 'security-headers',
    severity: 'medium',
    title: 'Missing HSTS',
    description: 'Strict-Transport-Security header not set',
    url: 'https://example.com',
    evidence: 'Header missing',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('deduplicateFindings', () => {
  it('collapses identical findings across pages into one', () => {
    const findings = [
      makeFinding({ url: 'https://example.com/page1' }),
      makeFinding({ url: 'https://example.com/page2' }),
      makeFinding({ url: 'https://example.com/page3' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].affectedUrls).toEqual([
      'https://example.com/page1',
      'https://example.com/page2',
      'https://example.com/page3',
    ]);
  });

  it('keeps different finding types separate', () => {
    const findings = [
      makeFinding({ title: 'Missing HSTS', url: 'https://example.com/a' }),
      makeFinding({ title: 'Missing CSP', url: 'https://example.com/a' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('keeps different severities separate', () => {
    const findings = [
      makeFinding({ title: 'XSS', severity: 'high', url: 'https://example.com/a' }),
      makeFinding({ title: 'XSS', severity: 'medium', url: 'https://example.com/b' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('returns empty array for empty input', () => {
    expect(deduplicateFindings([])).toEqual([]);
  });
});
```

Run: `npx vitest run test/unit/dedup.test.ts`
Expected: FAIL (module not found)

**Step 2: Implement dedup engine**

Create `src/utils/dedup.ts`:
```typescript
import type { RawFinding } from '../scanner/types.js';

/**
 * Deduplicate raw findings by (category, severity, title).
 * Collapses identical findings across multiple URLs into one finding
 * with an affectedUrls array. Keeps the first finding's details.
 */
export function deduplicateFindings(findings: RawFinding[]): RawFinding[] {
  const groups = new Map<string, RawFinding[]>();

  for (const finding of findings) {
    const key = `${finding.category}|${finding.severity}|${finding.title}`;
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }

  return Array.from(groups.values()).map((group) => {
    const primary = group[0];
    const urls = [...new Set(group.map((f) => f.url))];
    return {
      ...primary,
      affectedUrls: urls,
    };
  });
}
```

**Step 3: Add `affectedUrls` to RawFinding type**

Modify `src/scanner/types.ts` — add optional `affectedUrls` to `RawFinding`:
```typescript
export interface RawFinding {
  // ... existing fields ...
  affectedUrls?: string[];
}
```

**Step 4: Run dedup test**

Run: `npx vitest run test/unit/dedup.test.ts`
Expected: PASS

**Step 5: Wire dedup into pipeline**

Modify `src/index.ts` — add dedup call between Phase 5 (active scan) and Phase 6 (AI validation):
```typescript
import { deduplicateFindings } from './utils/dedup.js';

// After: const allRawFindings = [...passiveFindings, ...activeFindings];
// Add:
log.info(`Raw findings before dedup: ${allRawFindings.length}`);
const dedupedFindings = deduplicateFindings(allRawFindings);
log.info(`After dedup: ${dedupedFindings.length} unique findings`);
```

Then use `dedupedFindings` instead of `allRawFindings` for Phase 6, 7, and 8.

**Step 6: Commit**

```bash
git add src/utils/dedup.ts test/unit/dedup.test.ts src/scanner/types.ts src/index.ts
git commit -m "feat: add pre-dedup engine to reduce AI token cost"
```

---

### Task 4: Infrastructure fixes (SIGINT, version, dead code, logging)

**Files:**
- Modify: `src/index.ts` (SIGINT handler, exit codes, remove `randomUUID`)
- Modify: `src/reporter/html.ts` (dynamic version)
- Modify: `src/utils/logger.ts` (dynamic version in banner)
- Modify: `src/ai/fallback.ts` (remove duplicate `severityOrder`)
- Modify: `src/scanner/types.ts` (remove dead `idor`/`tls` categories — re-add when implemented)
- Modify: all `catch {}` blocks in active scanners (add `logger.debug`)

**Step 1: Add SIGINT handler to `src/index.ts`**

Add at top level, after imports:
```typescript
import { closeBrowser } from './scanner/browser.js';

// Graceful shutdown
let cleanupDone = false;
async function cleanup() {
  if (cleanupDone) return;
  cleanupDone = true;
  log.warn('Interrupted — cleaning up...');
  try { await closeBrowser(); } catch { /* best effort */ }
  process.exit(130);
}
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
```

Note: `closeBrowser` currently requires a `browser` argument. Refactor it to also support being called without args (close whatever browser is open) by storing the browser instance at module level in `browser.ts`.

**Step 2: Add exit codes to `src/index.ts`**

After Phase 8, before `log.info('Scan complete!')`:
```typescript
const hasHighOrCritical = interpretedFindings.some(
  (f) => f.severity === 'high' || f.severity === 'critical'
);
process.exitCode = hasHighOrCritical ? 1 : 0;
```

Wrap the outer catch to use exit code 2:
```typescript
catch (err) {
  log.error(`Scan failed: ${(err as Error).message}`);
  process.exit(2);
}
```

**Step 3: Remove dead code**

- `src/index.ts`: Remove `import { randomUUID } from 'node:crypto';`
- `src/ai/fallback.ts`: Remove the local `severityOrder` function, import from `../utils/shared.js`
- `src/scanner/types.ts`: Remove `'idor' | 'tls'` from `CheckCategory` (will re-add in Task 9/11)

**Step 4: Dynamic version**

In `src/reporter/html.ts` and `src/utils/logger.ts`, replace hardcoded version strings with:
```typescript
import { readFileSync } from 'node:fs';
const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'));
// Use pkg.version
```

Note: `src/index.ts` already does this correctly (line 28).

**Step 5: Add debug logging to silent catch blocks**

In these files, replace `catch { }` or `catch { // Continue }` with `catch (err) { log.debug(\`...: ${(err as Error).message}\`); }`:
- `src/scanner/active/xss.ts`
- `src/scanner/active/sqli.ts`
- `src/scanner/active/redirect.ts`
- `src/scanner/active/traversal.ts`
- `src/scanner/browser.ts`

Import `log` from `../../utils/logger.js` where not already imported.

**Step 6: Refactor `closeBrowser` for SIGINT support**

Modify `src/scanner/browser.ts`:
- Store the active `Browser` instance at module level
- Export `closeBrowser()` that takes optional browser arg, falls back to module-level instance
- This allows SIGINT handler to call `closeBrowser()` without a reference

**Step 7: Commit**

```bash
git add src/
git commit -m "fix: SIGINT handler, exit codes, dead code cleanup, debug logging"
```

---

## Phase 2: Improve Existing Checks

### Task 5: Improve passive checks (dedup + cookie heuristics)

**Files:**
- Modify: `src/scanner/passive.ts`
- Create: `test/unit/passive.test.ts`

**Step 1: Write tests for passive check improvements**

Create `test/unit/passive.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { runPassiveChecks } from '../../src/scanner/passive.js';
import type { CrawledPage, InterceptedResponse } from '../../src/scanner/types.js';

// Test that cookie checks skip analytics/csrf cookies
// Test that header findings are deduplicated across pages
// Test that safe pages produce zero findings
```

Tests should verify:
- Cookies named `_ga`, `_gid`, `locale`, `theme`, `csrf_token` do NOT trigger HttpOnly warnings
- Multiple pages missing the same header produce exactly 1 finding (not N)
- A properly secured page returns 0 findings

**Step 2: Implement cookie heuristics**

In `src/scanner/passive.ts`, add a skip list for cookie HttpOnly checks:
```typescript
const SKIP_HTTPONLY_PATTERNS = [
  /^_ga/i, /^_gid/i, /^_gat/i, /^_fbp/i, /^_gcl/i,  // analytics
  /^csrf/i, /^xsrf/i, /^_csrf/i,                        // CSRF tokens
  /^locale$/i, /^lang$/i, /^theme$/i, /^i18n/i,         // preferences
  /^__utm/i,                                              // UTM tracking
];

function shouldCheckHttpOnly(cookieName: string): boolean {
  return !SKIP_HTTPONLY_PATTERNS.some(p => p.test(cookieName));
}
```

**Step 3: Implement per-scan header dedup**

Instead of creating a finding per-page for each missing header, track which headers have already been reported:
```typescript
const reportedHeaders = new Set<string>();
// In header check loop:
const key = `missing-${headerName}`;
if (reportedHeaders.has(key)) continue;
reportedHeaders.add(key);
// Create finding with affectedUrls listing all pages missing this header
```

**Step 4: Run tests**

Run: `npx vitest run test/unit/passive.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/scanner/passive.ts test/unit/passive.test.ts
git commit -m "fix: reduce passive check noise with cookie heuristics and header dedup"
```

---

### Task 6: Improve XSS check

**Files:**
- Modify: `src/scanner/active/xss.ts`
- Modify: `src/config/payloads/xss.ts`
- Create: `test/unit/xss-payloads.test.ts`
- Create: `test/integration/xss.test.ts`

**Step 1: Fix marker-payload coupling**

In `src/config/payloads/xss.ts`, embed markers directly in payloads instead of relying on array index. Each payload should be an object `{ payload: string, marker: string, type: string }`.

**Step 2: Expand payloads to ~40**

Add to `src/config/payloads/xss.ts`:
- HTML entity encoded variants: `&lt;script&gt;`, `&#x3C;script&#x3E;`
- URL encoded: `%3Cscript%3E`
- Event handlers: `" onfocus="alert(1)" autofocus="`, `' onerror='alert(1)' '`
- Template literals: `` ${alert(1)} ``, `{{constructor.constructor('alert(1)')()}}`
- SVG variants: `<svg/onload=alert(1)>`, `<svg><script>alert(1)</script></svg>`
- IMG variants: `<img src=x onerror=alert(1)>`, `<img/src=x onerror=alert(1)>`
- DOM-centric: payloads targeting `location.hash`, `document.referrer`

**Step 3: Add DOM XSS detection**

In `src/scanner/active/xss.ts`, add a DOM XSS check:
- Inject payload into URL fragment (`#payload`)
- Use `page.evaluate()` to monkey-patch `document.write`, `innerHTML` setter, `eval`
- Navigate to URL with fragment
- Check if monkey-patched sinks were called with the payload

**Step 4: Add basic stored XSS detection**

After injecting a payload via form submission on page A, re-visit other crawled pages to check if the payload appears in their DOM.

**Step 5: Write integration test**

Create `test/integration/xss.test.ts` — run XSS check against the vulnerable test server:
- `/search?q=<payload>` should be detected (reflected XSS)
- `/safe?q=<payload>` should NOT be detected (encoded output)

**Step 6: Run tests**

Run: `npx vitest run test/integration/xss.test.ts`
Expected: PASS

**Step 7: Commit**

```bash
git add src/scanner/active/xss.ts src/config/payloads/xss.ts test/
git commit -m "feat: improve XSS detection with DOM XSS, stored XSS, expanded payloads"
```

---

### Task 7: Improve SQLi check

**Files:**
- Modify: `src/scanner/active/sqli.ts`
- Modify: `src/config/payloads/sqli.ts`
- Create: `test/integration/sqli.test.ts`

**Step 1: Add boolean-based blind detection**

In `src/scanner/active/sqli.ts`, after error-based and time-based checks, add:
- Send `' OR '1'='1` and `' OR '1'='2` to same parameter
- Compare response body length. If `1=1` response is significantly longer (>20% difference), flag as potential boolean-based blind SQLi.

**Step 2: Improve timing detection**

Replace single measurement with median of 3:
```typescript
async function measureResponseTime(url: string, page: Page): Promise<number> {
  const times: number[] = [];
  for (let i = 0; i < 3; i++) {
    const start = Date.now();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
    times.push(Date.now() - start);
  }
  times.sort((a, b) => a - b);
  return times[1]; // median
}
```

**Step 3: Add NoSQL injection payloads**

Add to `src/config/payloads/sqli.ts`:
```typescript
export const NOSQL_PAYLOADS = [
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$regex": ".*"}',
  '[$ne]=1',
  '[$gt]=',
  'true, $where: \'1 == 1\'',
];

export const NOSQL_ERROR_PATTERNS = [
  /MongoError/i,
  /mongo/i,
  /BSON/i,
  /ObjectId/i,
  /mongoose/i,
];
```

**Step 4: Add Union-based detection**

Probe column count with `ORDER BY N` (increment until error), then attempt `UNION SELECT NULL,...`.

**Step 5: Write integration test against vulnerable server**

Run: `npx vitest run test/integration/sqli.test.ts`
Expected: PASS

**Step 6: Commit**

```bash
git add src/scanner/active/sqli.ts src/config/payloads/sqli.ts test/integration/sqli.test.ts
git commit -m "feat: improve SQLi with boolean-blind, NoSQL, union-based, better timing"
```

---

### Task 8: Improve CORS, redirect, traversal checks

**Files:**
- Modify: `src/scanner/active/cors.ts`
- Modify: `src/scanner/active/redirect.ts`
- Modify: `src/scanner/active/traversal.ts`
- Modify: `src/config/payloads/redirect.ts`
- Modify: `src/config/payloads/traversal.ts`
- Modify: `src/scanner/active/index.ts` (expand `redirectUrls` param list)
- Create: `test/integration/cors.test.ts`
- Create: `test/integration/redirect.test.ts`
- Create: `test/integration/traversal.test.ts`

**Step 1: CORS — active `Origin: null` test + API/static distinction**

In `src/scanner/active/cors.ts`:
- Add a test case that sends `Origin: null` header
- When checking CORS, determine if the URL is an API endpoint (`/api/` prefix or JSON content-type) vs static asset. Only flag `Access-Control-Allow-Origin: *` on API endpoints, not static assets.
- Test `Access-Control-Allow-Credentials: true` with reflected origin (most dangerous CORS misconfiguration).

**Step 2: Redirect — expand parameter names**

In `src/scanner/active/index.ts`, expand `buildTargets`:
```typescript
const REDIRECT_PARAMS = /[?&](url|redirect|next|return|goto|dest|callback|redir|forward|ref|out|continue|target|path|link|returnUrl|redirectUrl|returnTo|return_to|redirect_uri|redirect_url)=/i;
```

In `src/config/payloads/redirect.ts`, add header-based redirect payloads.

**Step 3: Traversal — remove API-only filter + path param detection**

In `src/scanner/active/traversal.ts`:
- Remove the early return when `apiEndpoints.length === 0`
- Also target URLs with file-like parameters (param value contains `.`, `/`, or common file extensions)
- Add path segment traversal: try replacing path segments with `../etc/passwd`

In `src/scanner/active/index.ts`, update `buildTargets` to also extract URLs with file-like params for traversal.

**Step 4: Write integration tests for each**

Create integration tests that run each check against the vulnerable test server.

**Step 5: Run all tests**

Run: `npx vitest run test/integration/`
Expected: PASS

**Step 6: Commit**

```bash
git add src/scanner/active/ src/config/payloads/ test/integration/
git commit -m "feat: improve CORS, redirect, traversal checks with broader detection"
```

---

## Phase 3: New Check Types

### Task 9: Add SSRF check

**Files:**
- Create: `src/scanner/active/ssrf.ts`
- Create: `src/config/payloads/ssrf.ts`
- Modify: `src/scanner/active/index.ts` (register check)
- Modify: `src/scanner/types.ts` (add `'ssrf'` to CheckCategory)
- Modify: `src/config/payloads/index.ts` (re-export)
- Create: `test/integration/ssrf.test.ts`

**Step 1: Create SSRF payloads**

Create `src/config/payloads/ssrf.ts`:
```typescript
export const SSRF_PAYLOADS = [
  'http://127.0.0.1',
  'http://localhost',
  'http://[::1]',
  'http://0.0.0.0',
  'http://169.254.169.254/latest/meta-data/',   // AWS metadata
  'http://metadata.google.internal/',            // GCP metadata
  'http://100.100.100.200/latest/meta-data/',    // Alibaba metadata
  'file:///etc/passwd',
  'http://127.0.0.1:22',                        // port scan
  'http://127.0.0.1:3000',                      // internal services
];

export const SSRF_PARAM_PATTERNS = /[?&](url|link|src|image|proxy|callback|fetch|load|uri|href|path|file|resource|target|site|page|data)=/i;

export const SSRF_INDICATORS = [
  /root:.*:0:0/,                  // /etc/passwd content
  /ami-id/i,                      // AWS metadata
  /instance-id/i,                 // Cloud metadata
  /meta-data/i,                   // Generic metadata
  /Connection refused/i,          // Internal port scan evidence
  /No route to host/i,
];
```

**Step 2: Implement SSRF check**

Create `src/scanner/active/ssrf.ts`:
- Scan for URL parameters matching `SSRF_PARAM_PATTERNS`
- Inject SSRF payloads into those parameters
- Check response for `SSRF_INDICATORS`
- Also check timing: internal requests may be faster than external baseline

**Step 3: Register in CHECK_REGISTRY**

Modify `src/scanner/active/index.ts`:
```typescript
import { ssrfCheck } from './ssrf.js';
// Add to CHECK_REGISTRY:
export const CHECK_REGISTRY: ActiveCheck[] = [
  xssCheck, sqliCheck, corsCheck, redirectCheck, traversalCheck, ssrfCheck,
];
```

Add `'ssrf'` to `CheckCategory` in `src/scanner/types.ts`.

**Step 4: Write integration test**

Test against vulnerable server's `/fetch?url=` endpoint.

**Step 5: Run test**

Run: `npx vitest run test/integration/ssrf.test.ts`
Expected: PASS

**Step 6: Commit**

```bash
git add src/scanner/active/ssrf.ts src/config/payloads/ssrf.ts src/scanner/active/index.ts src/scanner/types.ts test/integration/ssrf.test.ts src/config/payloads/index.ts
git commit -m "feat: add SSRF vulnerability check"
```

---

### Task 10: Add SSTI check

**Files:**
- Create: `src/scanner/active/ssti.ts`
- Create: `src/config/payloads/ssti.ts`
- Modify: `src/scanner/active/index.ts` (register)
- Modify: `src/scanner/types.ts` (add `'ssti'` to CheckCategory)
- Create: `test/integration/ssti.test.ts`

**Step 1: Create SSTI payloads**

Create `src/config/payloads/ssti.ts`:
```typescript
export const SSTI_PAYLOADS = [
  { payload: '{{7*7}}', expected: '49', engine: 'Jinja2/Twig' },
  { payload: '${7*7}', expected: '49', engine: 'Freemarker/Velocity' },
  { payload: '<%= 7*7 %>', expected: '49', engine: 'ERB/EJS' },
  { payload: '#{7*7}', expected: '49', engine: 'Pug/Slim' },
  { payload: '{{7*\'7\'}}', expected: '7777777', engine: 'Jinja2 (string mul)' },
  { payload: '${7*7}', expected: '49', engine: 'Java EL' },
  { payload: '@(7*7)', expected: '49', engine: 'Razor' },
];
```

**Step 2: Implement SSTI check**

Create `src/scanner/active/ssti.ts`:
- For each form input and URL parameter, inject SSTI payloads
- Check if the response contains the `expected` value where it wasn't present before injection
- To avoid false positives: also send a control value (e.g., `{{7+7}}` expecting `14`) to confirm template evaluation, not just string matching

**Step 3: Register, test, commit**

Same pattern as Task 9.

```bash
git commit -m "feat: add SSTI vulnerability check"
```

---

### Task 11: Add Command Injection check

**Files:**
- Create: `src/scanner/active/cmdi.ts`
- Create: `src/config/payloads/cmdi.ts`
- Modify: `src/scanner/active/index.ts` (register)
- Modify: `src/scanner/types.ts` (add `'command-injection'` to CheckCategory)
- Create: `test/integration/cmdi.test.ts`

**Step 1: Create payloads**

Create `src/config/payloads/cmdi.ts`:
```typescript
export const CMDI_PAYLOADS_TIMING = [
  { payload: '; sleep 5', delay: 5 },
  { payload: '| sleep 5', delay: 5 },
  { payload: '`sleep 5`', delay: 5 },
  { payload: '$(sleep 5)', delay: 5 },
  { payload: '%0asleep 5', delay: 5 },
  // Windows variants
  { payload: '& timeout /t 5', delay: 5 },
  { payload: '| timeout /t 5', delay: 5 },
];

export const CMDI_PAYLOADS_OUTPUT = [
  { payload: '; echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker' },
  { payload: '| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker' },
  { payload: '`echo secbot-cmdi-marker`', marker: 'secbot-cmdi-marker' },
  { payload: '$(echo secbot-cmdi-marker)', marker: 'secbot-cmdi-marker' },
];
```

**Step 2: Implement command injection check**

Create `src/scanner/active/cmdi.ts`:
- Timing-based: inject sleep payloads, measure response time (median of 3)
- Output-based: inject echo payloads, check for marker in response
- Target: all form inputs and URL parameters (not just specific param names)

**Step 3: Register, test, commit**

```bash
git commit -m "feat: add command injection vulnerability check"
```

---

### Task 12: Add IDOR check

**Files:**
- Create: `src/scanner/active/idor.ts`
- Modify: `src/scanner/active/index.ts` (register)
- Modify: `src/scanner/types.ts` (re-add `'idor'` to CheckCategory)
- Create: `test/integration/idor.test.ts`

**Step 1: Implement IDOR check**

Create `src/scanner/active/idor.ts`:
- Scan crawled URLs for sequential numeric IDs in path segments: `/users/123`, `/api/v1/invoices/456`
- For each detected ID pattern:
  - Request the original URL (baseline) — store status and response length
  - Request with ID+1 and ID-1
  - If the adjacent ID returns the same status (200) and similar response structure, flag as potential IDOR
- Skip this check entirely if no auth storage state is configured (IDOR without auth is meaningless)
- Severity: HIGH (access control bypass)

**Step 2: Register, test, commit**

```bash
git commit -m "feat: add IDOR vulnerability check"
```

---

### Task 13: Add TLS/Crypto check

**Files:**
- Create: `src/scanner/active/tls.ts`
- Modify: `src/scanner/active/index.ts` (register)
- Modify: `src/scanner/types.ts` (re-add `'tls'` to CheckCategory)
- Create: `test/unit/tls.test.ts`

**Step 1: Implement TLS check**

Create `src/scanner/active/tls.ts`:
- Use Node.js `tls.connect()` to connect to the target
- Check:
  - TLS version (flag 1.0 and 1.1 as deprecated)
  - Certificate validity (expiry, self-signed)
  - Certificate chain completeness
  - HSTS preload eligibility (`includeSubDomains`, `max-age >= 31536000`)
- This check does NOT use Playwright — it uses raw TLS socket
- Since it doesn't use `BrowserContext`, it should implement `ActiveCheck` but its `run()` can ignore the context param

**Step 2: Register, test, commit**

```bash
git commit -m "feat: add TLS/crypto security check"
```

---

### Task 14: Add SRI check

**Files:**
- Create: `src/scanner/active/sri.ts`
- Modify: `src/scanner/active/index.ts` (register)
- Modify: `src/scanner/types.ts` (add `'sri'` to CheckCategory)
- Create: `test/integration/sri.test.ts`

**Step 1: Implement SRI check**

Create `src/scanner/active/sri.ts`:
- For each crawled page, check all `<script src="...">` and `<link href="..." rel="stylesheet">` tags
- If the src/href is from a different origin (CDN), check for `integrity` attribute
- Flag external resources without SRI
- Skip same-origin resources (they don't need SRI)
- This check operates on already-crawled page data, so it's more like an enhanced passive check but fits the active check interface

**Step 2: Register, test, commit**

```bash
git commit -m "feat: add Subresource Integrity (SRI) check"
```

---

### Task 15: Add deep security headers check

**Files:**
- Modify: `src/scanner/passive.ts` (add new header checks)
- Modify: `src/scanner/types.ts` (add `'cross-origin-policy'` to CheckCategory if needed)
- Modify: `test/unit/passive.test.ts` (add tests for new headers)

**Step 1: Add modern isolation header checks**

In `src/scanner/passive.ts`, add checks for:
- `Cross-Origin-Opener-Policy` (COOP) — should be `same-origin`
- `Cross-Origin-Embedder-Policy` (COEP) — should be `require-corp`
- `Cross-Origin-Resource-Policy` (CORP) — should be `same-origin` or `same-site`
- `Permissions-Policy` — flag overly permissive values (e.g., allowing `camera`, `microphone`, `geolocation` from `*`)

**Step 2: Test and commit**

```bash
git commit -m "feat: add cross-origin isolation and permissions-policy checks"
```

---

## Phase 4: Crawling & Route Discovery

### Task 16: Implement RouteDiscoverer interface and Next.js extraction

**Files:**
- Create: `src/scanner/discovery/index.ts`
- Create: `src/scanner/discovery/types.ts`
- Create: `src/scanner/discovery/link-crawler.ts`
- Create: `src/scanner/discovery/nextjs-extractor.ts`
- Create: `src/scanner/discovery/url-file-loader.ts`
- Modify: `src/scanner/browser.ts` (integrate discovery)
- Modify: `src/index.ts` (add `--urls` flag)
- Create: `test/unit/discovery.test.ts`

**Step 1: Define RouteDiscoverer interface**

Create `src/scanner/discovery/types.ts`:
```typescript
export interface DiscoveredRoute {
  url: string;
  source: 'crawl' | 'nextjs' | 'sitemap' | 'file' | 'probe';
  confidence: 'high' | 'medium' | 'low';
}

export interface RouteDiscoverer {
  name: string;
  discover(targetUrl: string): Promise<DiscoveredRoute[]>;
}
```

**Step 2: Implement Next.js extractor**

Create `src/scanner/discovery/nextjs-extractor.ts`:
- Fetch `${targetUrl}/sitemap.xml` — parse XML for URLs
- Fetch `${targetUrl}/_next/routes-manifest.json` — parse for routes
- Probe common Next.js paths: `/api/health`, `/api/v1`, `/_next/data/`
- Return discovered routes with source and confidence

**Step 3: Implement URL file loader**

Create `src/scanner/discovery/url-file-loader.ts`:
- Read a text file (one URL per line)
- Return as discovered routes with source `'file'`, confidence `'high'`

**Step 4: Create discovery orchestrator**

Create `src/scanner/discovery/index.ts`:
```typescript
export async function discoverRoutes(
  targetUrl: string,
  urlsFile?: string,
): Promise<DiscoveredRoute[]> {
  const discoverers: RouteDiscoverer[] = [
    new NextJsExtractor(),
  ];
  if (urlsFile) {
    discoverers.push(new UrlFileLoader(urlsFile));
  }

  const allRoutes: DiscoveredRoute[] = [];
  for (const d of discoverers) {
    const routes = await d.discover(targetUrl);
    allRoutes.push(...routes);
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  return allRoutes.filter(r => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });
}
```

**Step 5: Wire into pipeline**

Modify `src/index.ts`:
- Add `--urls <file>` CLI option
- Before Phase 1 crawl, run route discovery
- Pass discovered routes to crawler as additional seed URLs

**Step 6: Test and commit**

```bash
git commit -m "feat: add route discovery with Next.js extraction and --urls flag"
```

---

## Phase 5: Output & Polish

### Task 17: JSON output enhancements + version bump

**Files:**
- Modify: `src/scanner/types.ts` (add fields to `ScanResult` and `ScanSummary`)
- Modify: `src/index.ts` (populate new fields)
- Modify: `src/reporter/json.ts` (include new fields)
- Modify: `package.json` (bump to v1.0.0)
- Create: `test/integration/full-scan.test.ts`

**Step 1: Add fields to ScanResult**

In `src/scanner/types.ts`, add to `ScanResult`:
```typescript
exitCode: number;
scanDuration: number; // ms
checksRun: string[];
```

Add to `ScanSummary`:
```typescript
passedChecks: string[]; // check types that ran but found nothing
```

**Step 2: Populate in pipeline**

In `src/index.ts`, compute `scanDuration`, `checksRun`, `passedChecks`, and `exitCode`. Include in `scanResult`.

**Step 3: Write full integration test**

Create `test/integration/full-scan.test.ts`:
- Run a complete scan against the vulnerable test server with `--no-ai --format json`
- Parse the JSON output
- Assert: exitCode is 1 (findings present), scanDuration > 0, checksRun is non-empty
- Assert: at least 1 XSS finding, at least 1 header finding
- Assert: `/safe` endpoint does not appear in false positives

This is the key integration test that validates the entire pipeline end-to-end.

**Step 4: Version bump**

In `package.json`, change `"version": "0.0.1"` to `"version": "1.0.0"`.

**Step 5: Run full test suite**

Run: `npx vitest run`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add .
git commit -m "feat: v1.0.0 — JSON output enhancements, full integration test, version bump"
```

---

### Task 18: Update AI prompts for new check types

**Files:**
- Modify: `src/ai/prompts.ts` (update planner/validator/reporter prompts)
- Modify: `src/ai/fallback.ts` (update rule-based fallback for new checks)

**Step 1: Update planner prompt**

The planner prompt needs to know about all 12 check types (was 5). Update the system prompt to list all available checks with descriptions so the AI can recommend the right ones.

**Step 2: Update validator prompt**

The validator needs to understand new check categories (SSRF, SSTI, command injection, IDOR, TLS, SRI, cross-origin policy) to properly assess findings.

**Step 3: Update fallback logic**

In `src/ai/fallback.ts`, update `buildDefaultPlan` to include logic for when to recommend new check types:
- SSRF: when URL-accepting parameters are detected
- SSTI: when template engine detected in recon
- Command injection: when non-static API routes exist
- IDOR: when sequential IDs in URLs + auth present
- TLS: always (just needs HTTPS target)
- SRI: when external scripts detected
- Deep headers: always

**Step 4: Commit**

```bash
git add src/ai/prompts.ts src/ai/fallback.ts
git commit -m "feat: update AI prompts and fallback logic for 12 check types"
```

---

### Task 19: Update CLAUDE.md, README.md, and docs

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

**Step 1: Update CLAUDE.md**

- Update version to v1.0.0
- Update architecture diagram to include new phases (route discovery) and all 12 check types
- Update key files section with new files (ssrf.ts, ssti.ts, cmdi.ts, idor.ts, tls.ts, sri.ts, discovery/)
- Update CLI options (add `--urls`)
- Update CheckCategory list

**Step 2: Update README.md**

- Update scan results section
- Add new check types to documentation
- Add `--urls` flag documentation
- Add exit codes documentation
- Update "How It Works" diagram

**Step 3: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: update CLAUDE.md and README.md for v1.0.0"
```

---

## Summary

| Phase | Tasks | What it delivers |
|-------|-------|-----------------|
| 1. Infrastructure | Tasks 1-4 | Tests, dedup, SIGINT, exit codes, dead code cleanup |
| 2. Improve existing | Tasks 5-8 | Better XSS/SQLi/CORS/redirect/traversal/passive checks |
| 3. New checks | Tasks 9-15 | SSRF, SSTI, command injection, IDOR, TLS, SRI, deep headers |
| 4. Crawling | Task 16 | Next.js route extraction, `--urls` flag, RouteDiscoverer interface |
| 5. Polish | Tasks 17-19 | JSON output, AI prompt updates, docs, v1.0.0 bump |

**Total: 19 tasks**

Estimated new/modified files: ~40
Estimated new test files: ~12
Estimated new lines of code: ~3,000-4,000

## Path B Reference

When Path A is complete and validated, the following Path B features can be added as extensions:
- Full SPA crawling → new `RouteDiscoverer` implementation (architecture ready from Task 16)
- WAF evasion → payload expansion in `src/config/payloads/` (structure ready)
- `--proxy` flag → config in `ScanConfig`, pass to Playwright launch options
- Auth flows → extend `ScanConfig.authStorageState` to support multiple auth methods
- Interactive mode → new CLI command `secbot probe <url>` alongside existing `secbot scan`
- Screenshot capture → `page.screenshot()` in active checks when finding confirmed
- Rate limit config → `--rate-limit <n>` flag, enforce in request interceptor

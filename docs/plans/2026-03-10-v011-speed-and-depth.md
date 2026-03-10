# SecBot v0.11 "Speed & Depth" Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing scanner 3-4x faster via parallel checks, and make payload selection intelligent by wiring `PayloadContext` into the 4 key active checks.

**Architecture:** Split `runActiveChecks()` into parallel and sequential groups. Each active check reads `config.payloadContext` to reorder/filter its payload list. Recon module consumes crawler's framework info instead of its own weaker detection.

**Tech Stack:** TypeScript, Vitest, Playwright (existing)

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `src/scanner/active/index.ts` | Split runner into parallel + sequential groups |
| Modify | `src/scanner/active/sqli.ts` | Read `payloadContext.databases` to reorder payloads |
| Modify | `src/scanner/active/ssti.ts` | Read `payloadContext.templateEngines` to reorder payloads |
| Modify | `src/scanner/active/xss.ts` | Read `payloadContext.preferDomXss` to prioritize DOM vs reflected |
| Modify | `src/scanner/active/cmdi.ts` | Read `payloadContext.osHint` to filter Unix/Windows payloads |
| Modify | `src/config/payloads/sqli.ts` | Add `dbType` tag to time-based payloads |
| Modify | `src/config/payloads/cmdi.ts` | Add `os` tag to payloads |
| Modify | `src/scanner/recon.ts` | Consume `CrawledPage.framework` in `detectFramework()` |
| Create | `test/unit/parallel-runner.test.ts` | Tests for parallel check execution |
| Create | `test/unit/payload-context-wiring.test.ts` | Tests for context-aware payload selection |
| Modify | `test/unit/payload-context.test.ts` | Extend with wiring integration assertions |

---

## Task 1: Parallel Active Check Runner

**Files:**
- Modify: `src/scanner/active/index.ts:56-77` (CHECK_REGISTRY) and `:238-250` (sequential loop)
- Create: `test/unit/parallel-runner.test.ts`

### Step 1: Add `parallel` flag to ActiveCheck interface and tag each check

- [ ] **1.1: Add `parallel` property to ActiveCheck**

In `src/scanner/active/index.ts`, add to the `ActiveCheck` interface:

```typescript
export interface ActiveCheck {
  name: string;
  category: CheckCategory;
  /** If true, this check can run concurrently with other parallel checks (read-only, no state mutation) */
  parallel?: boolean;
  run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]>;
}
```

- [ ] **1.2: Tag safe-to-parallelize checks in CHECK_REGISTRY**

No changes to CHECK_REGISTRY array itself — instead, set `parallel: true` in each check's export object. These checks are read-only (no payload injection, no state changes):

| Check | File | Set `parallel: true` |
|-------|------|---------------------|
| `corsCheck` | `cors.ts` | Yes |
| `tlsCheck` | `tls.ts` | Yes |
| `sriCheck` | `sri.ts` | Yes |
| `infoDisclosureCheck` | `info-disclosure.ts` | Yes |
| `jsCveCheck` | `js-cve.ts` | Yes |
| `hostHeaderCheck` | `host-header.ts` | Yes |
| `jwtCheck` | `jwt.ts` | Yes |
| `rateLimitCheck` | `rate-limit.ts` | Yes |
| `graphqlCheck` | `graphql.ts` | Yes |

In each file, add `parallel: true` to the exported check object. Example for `cors.ts`:
```typescript
export const corsCheck: ActiveCheck = {
  name: 'cors',
  category: 'cors-misconfiguration',
  parallel: true,       // <-- add this line
  async run(context, targets, config, requestLogger) {
```

All other checks (xss, sqli, ssrf, ssti, cmdi, crlf, redirect, traversal, idor, race) remain `parallel: undefined` (falsy = sequential).

- [ ] **1.3: Write the failing test for parallel runner**

Create `test/unit/parallel-runner.test.ts`:

```typescript
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('parallel check runner', () => {
  it('separates checks into parallel and sequential groups', async () => {
    // Dynamic import to get the function after mocks are set up
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');

    const parallel = CHECK_REGISTRY.filter((c) => c.parallel);
    const sequential = CHECK_REGISTRY.filter((c) => !c.parallel);

    // At least 7 checks should be parallelizable
    expect(parallel.length).toBeGreaterThanOrEqual(7);
    // At least 5 checks must remain sequential (xss, sqli, ssrf, ssti, cmdi, etc.)
    expect(sequential.length).toBeGreaterThanOrEqual(5);

    // Verify specific checks are in the right group
    expect(parallel.find((c) => c.name === 'cors')).toBeDefined();
    expect(parallel.find((c) => c.name === 'tls')).toBeDefined();
    expect(parallel.find((c) => c.name === 'sri')).toBeDefined();
    expect(parallel.find((c) => c.name === 'jwt')).toBeDefined();

    // These MUST be sequential (they inject payloads)
    expect(sequential.find((c) => c.name === 'xss')).toBeDefined();
    expect(sequential.find((c) => c.name === 'sqli')).toBeDefined();
    expect(sequential.find((c) => c.name === 'ssrf')).toBeDefined();
  });
});
```

- [ ] **1.4: Run test to verify it fails**

Run: `cd /Users/dioatmando/Vibecode/experiments/secbot && npx vitest run test/unit/parallel-runner.test.ts`

Expected: FAIL — `parallel` property doesn't exist yet on any check.

- [ ] **1.5: Implement parallel flag on all 9 checks**

Add `parallel: true` to the check export in each of the 9 files listed in step 1.2.

- [ ] **1.6: Run test to verify it passes**

Run: `npx vitest run test/unit/parallel-runner.test.ts`
Expected: PASS

### Step 2: Split the runner loop into parallel + sequential execution

- [ ] **2.1: Write failing test for parallel execution timing**

Add to `test/unit/parallel-runner.test.ts`:

```typescript
import type { ActiveCheck } from '../../src/scanner/active/index.js';
import { splitChecksByParallelism } from '../../src/scanner/active/index.js';

describe('splitChecksByParallelism', () => {
  it('returns parallel and sequential arrays', () => {
    const checks: ActiveCheck[] = [
      { name: 'a', category: 'tls', parallel: true, run: async () => [] },
      { name: 'b', category: 'xss', run: async () => [] },
      { name: 'c', category: 'sri', parallel: true, run: async () => [] },
    ];
    const { parallel, sequential } = splitChecksByParallelism(checks);
    expect(parallel.map((c) => c.name)).toEqual(['a', 'c']);
    expect(sequential.map((c) => c.name)).toEqual(['b']);
  });

  it('returns empty arrays for empty input', () => {
    const { parallel, sequential } = splitChecksByParallelism([]);
    expect(parallel).toEqual([]);
    expect(sequential).toEqual([]);
  });
});
```

- [ ] **2.2: Run test to verify it fails**

Run: `npx vitest run test/unit/parallel-runner.test.ts`
Expected: FAIL — `splitChecksByParallelism` not exported.

- [ ] **2.3: Implement splitChecksByParallelism and rewrite runActiveChecks**

In `src/scanner/active/index.ts`, add:

```typescript
/** Split checks into parallel (safe to run concurrently) and sequential groups */
export function splitChecksByParallelism(checks: ActiveCheck[]): {
  parallel: ActiveCheck[];
  sequential: ActiveCheck[];
} {
  return {
    parallel: checks.filter((c) => c.parallel),
    sequential: checks.filter((c) => !c.parallel),
  };
}
```

Then rewrite the runner loop in `runActiveChecks()` (replace lines 238-250):

```typescript
  const { parallel, sequential } = splitChecksByParallelism(checksToRun);

  // Phase A: Run parallel checks concurrently (read-only, no state mutation)
  if (parallel.length > 0) {
    log.info(`Running ${parallel.length} checks in parallel: ${parallel.map((c) => c.name).join(', ')}`);
    const parallelResults = await Promise.allSettled(
      parallel.map(async (check) => {
        try {
          return await check.run(context, targets, config, requestLogger);
        } catch (err) {
          log.warn(`Active check "${check.name}" failed: ${(err as Error).message}`);
          return [];
        }
      }),
    );
    for (const result of parallelResults) {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      }
    }
  }

  // Phase B: Run sequential checks one-by-one (inject payloads, may trigger WAF)
  if (sequential.length > 0) {
    log.info(`Running ${sequential.length} checks sequentially: ${sequential.map((c) => c.name).join(', ')}`);
    for (let i = 0; i < sequential.length; i++) {
      const check = sequential[i];
      try {
        if (i > 0) {
          await rateLimiter.acquire();
        }
        const checkFindings = await check.run(context, targets, config, requestLogger);
        findings.push(...checkFindings);
      } catch (err) {
        log.warn(`Active check "${check.name}" failed: ${(err as Error).message}`);
      }
    }
  }
```

- [ ] **2.4: Run tests to verify everything passes**

Run: `npx vitest run test/unit/parallel-runner.test.ts`
Expected: PASS

- [ ] **2.5: Run full test suite to verify no regressions**

Run: `npx vitest run`
Expected: All 1252+ tests pass.

- [ ] **2.6: Commit**

```bash
git add src/scanner/active/index.ts src/scanner/active/cors.ts src/scanner/active/tls.ts \
  src/scanner/active/sri.ts src/scanner/active/info-disclosure.ts src/scanner/active/js-cve.ts \
  src/scanner/active/host-header.ts src/scanner/active/jwt.ts src/scanner/active/rate-limit.ts \
  src/scanner/active/graphql.ts test/unit/parallel-runner.test.ts
git commit -m "feat: parallel active check runner — 9 read-only checks run concurrently"
```

---

## Task 2: Wire PayloadContext into SQLi

**Files:**
- Modify: `src/config/payloads/sqli.ts` — add `dbType` tag to time payloads
- Modify: `src/scanner/active/sqli.ts:34-40` — `selectSqliPayloads()` consults `payloadContext`
- Create: `test/unit/payload-context-wiring.test.ts`

- [ ] **2.1: Tag time-based payloads with dbType**

In `src/config/payloads/sqli.ts`, change `SQLI_TIME_PAYLOADS` to include a `dbType` field:

```typescript
export interface TimedSqliPayload {
  payload: string;
  dbType: 'mysql' | 'mssql' | 'postgres' | 'sqlite' | 'generic';
}

export const SQLI_TIME_PAYLOADS: TimedSqliPayload[] = [
  { payload: "' OR SLEEP(5)--", dbType: 'mysql' },
  { payload: "1 OR SLEEP(5)--", dbType: 'mysql' },
  { payload: "1; WAITFOR DELAY '0:0:5'--", dbType: 'mssql' },
  { payload: "'; SELECT pg_sleep(5)--", dbType: 'postgres' },
  { payload: "1 OR 1=1 AND RANDOMBLOB(500000000)--", dbType: 'sqlite' },
];
```

- [ ] **2.2: Write failing test for context-aware SQLi payload selection**

Create `test/unit/payload-context-wiring.test.ts`:

```typescript
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('SQLi payload context wiring', () => {
  it('prioritizes MySQL payloads when PHP detected', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['mysql']);
    // MySQL payloads should come first
    expect(result[0].dbType).toBe('mysql');
    // All payloads still included (don't drop — just reorder)
    expect(result.length).toBeGreaterThanOrEqual(4);
  });

  it('prioritizes MSSQL payloads when .NET detected', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['mssql']);
    expect(result[0].dbType).toBe('mssql');
  });

  it('keeps original order when no context', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['unknown']);
    expect(result.length).toBeGreaterThanOrEqual(4);
  });
});
```

- [ ] **2.3: Run test to verify it fails**

Run: `npx vitest run test/unit/payload-context-wiring.test.ts`
Expected: FAIL — `prioritizeTimedPayloads` not exported.

- [ ] **2.4: Implement prioritizeTimedPayloads in sqli.ts**

Add to `src/scanner/active/sqli.ts`:

```typescript
import type { TimedSqliPayload } from '../../config/payloads/sqli.js';
import type { DatabaseType } from '../../utils/payload-context.js';

/** Reorder timed SQLi payloads: matching DB types first, then the rest */
export function prioritizeTimedPayloads(databases: DatabaseType[]): TimedSqliPayload[] {
  const dbSet = new Set(databases.filter((d) => d !== 'unknown'));
  if (dbSet.size === 0) return [...SQLI_TIME_PAYLOADS];

  const prioritized = SQLI_TIME_PAYLOADS.filter((p) => dbSet.has(p.dbType as DatabaseType));
  const rest = SQLI_TIME_PAYLOADS.filter((p) => !dbSet.has(p.dbType as DatabaseType));
  log.debug(`SQLi payload context: prioritizing ${prioritized.length} ${[...dbSet].join('/')} payloads`);
  return [...prioritized, ...rest];
}
```

Then in the check's `run()` method, where time-based payloads are used, replace `SQLI_TIME_PAYLOADS` with:

```typescript
const timedPayloads = config.payloadContext
  ? prioritizeTimedPayloads(config.payloadContext.databases)
  : [...SQLI_TIME_PAYLOADS];
```

- [ ] **2.5: Run test to verify it passes**

Run: `npx vitest run test/unit/payload-context-wiring.test.ts`
Expected: PASS

- [ ] **2.6: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass.

- [ ] **2.7: Commit**

```bash
git add src/config/payloads/sqli.ts src/scanner/active/sqli.ts test/unit/payload-context-wiring.test.ts
git commit -m "feat: wire payload context into SQLi — prioritize DB-specific payloads"
```

---

## Task 3: Wire PayloadContext into SSTI

**Files:**
- Modify: `src/scanner/active/ssti.ts` — reorder `SSTI_PAYLOADS` by detected template engine
- Modify: `test/unit/payload-context-wiring.test.ts` — add SSTI tests

- [ ] **3.1: Write failing test**

Add to `test/unit/payload-context-wiring.test.ts`:

```typescript
describe('SSTI payload context wiring', () => {
  it('prioritizes Jinja2 payloads when Django detected', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const result = prioritizeSstiPayloads(['jinja2']);
    expect(result[0].engine).toMatch(/jinja2/i);
  });

  it('prioritizes ERB payloads when Ruby detected', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const result = prioritizeSstiPayloads(['erb']);
    expect(result[0].engine).toMatch(/erb/i);
  });

  it('keeps all payloads when no context', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const { SSTI_PAYLOADS } = await import('../../src/config/payloads/ssti.js');
    const result = prioritizeSstiPayloads(['unknown']);
    expect(result.length).toBe(SSTI_PAYLOADS.length);
  });
});
```

- [ ] **3.2: Run test to verify it fails**

- [ ] **3.3: Implement prioritizeSstiPayloads in ssti.ts**

```typescript
import type { TemplateEngine } from '../../utils/payload-context.js';
import type { SSTIPayload } from '../../config/payloads/ssti.js';

/** Reorder SSTI payloads: matching template engines first */
export function prioritizeSstiPayloads(engines: TemplateEngine[]): SSTIPayload[] {
  const engineSet = new Set(engines.filter((e) => e !== 'unknown'));
  if (engineSet.size === 0) return [...SSTI_PAYLOADS];

  const engineMatchesAny = (p: SSTIPayload) =>
    [...engineSet].some((e) => p.engine.toLowerCase().includes(e));

  const prioritized = SSTI_PAYLOADS.filter(engineMatchesAny);
  const rest = SSTI_PAYLOADS.filter((p) => !engineMatchesAny(p));
  return [...prioritized, ...rest];
}
```

Then in `run()`, replace `SSTI_PAYLOADS` usage with:

```typescript
const payloads = config.payloadContext
  ? prioritizeSstiPayloads(config.payloadContext.templateEngines)
  : SSTI_PAYLOADS;
```

- [ ] **3.4: Run tests, verify pass**

- [ ] **3.5: Commit**

```bash
git add src/scanner/active/ssti.ts test/unit/payload-context-wiring.test.ts
git commit -m "feat: wire payload context into SSTI — prioritize detected template engines"
```

---

## Task 4: Wire PayloadContext into XSS

**Files:**
- Modify: `src/scanner/active/xss.ts` — when `preferDomXss`, run DOM XSS before reflected
- Modify: `test/unit/payload-context-wiring.test.ts` — add XSS test

- [ ] **4.1: Write failing test**

Add to `test/unit/payload-context-wiring.test.ts`:

```typescript
describe('XSS payload context wiring', () => {
  it('exports shouldPrioritizeDomXss function', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    expect(typeof shouldPrioritizeDomXss).toBe('function');
  });

  it('returns true when payloadContext.preferDomXss is true', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    const config = { payloadContext: { preferDomXss: true } } as any;
    expect(shouldPrioritizeDomXss(config)).toBe(true);
  });

  it('returns false when no payloadContext', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    const config = {} as any;
    expect(shouldPrioritizeDomXss(config)).toBe(false);
  });
});
```

- [ ] **4.2: Run test to verify it fails**

- [ ] **4.3: Implement shouldPrioritizeDomXss and reorder check phases**

In `src/scanner/active/xss.ts`, add:

```typescript
/** Check if payload context recommends prioritizing DOM XSS over reflected */
export function shouldPrioritizeDomXss(config: ScanConfig): boolean {
  return config.payloadContext?.preferDomXss === true;
}
```

Then in the check's `run()` method, reorder the phases:

```typescript
if (shouldPrioritizeDomXss(config)) {
  log.info('Payload context: SPA detected — prioritizing DOM XSS');
  // Run DOM XSS first (SPA search, DOM checks)
  // Then reflected/POST
} else {
  // Current order: reflected GET → POST → DOM → SPA search
}
```

The key change is moving DOM XSS and SPA search XSS blocks BEFORE reflected GET/POST when `preferDomXss` is true. This means DOM XSS findings surface faster and the scan can potentially short-circuit.

- [ ] **4.4: Run tests, verify pass**

- [ ] **4.5: Commit**

```bash
git add src/scanner/active/xss.ts test/unit/payload-context-wiring.test.ts
git commit -m "feat: wire payload context into XSS — prioritize DOM XSS for SPAs"
```

---

## Task 5: Wire PayloadContext into CMDi

**Files:**
- Modify: `src/config/payloads/cmdi.ts` — add `os` tag to payloads
- Modify: `src/scanner/active/cmdi.ts` — filter payloads by OS hint
- Modify: `test/unit/payload-context-wiring.test.ts` — add CMDi tests

- [ ] **5.1: Tag CMDi payloads with OS**

In `src/config/payloads/cmdi.ts`:

```typescript
export interface CmdiTimingPayload {
  payload: string;
  delay: number;
  os: 'unix' | 'windows';
}

export interface CmdiOutputPayload {
  payload: string;
  marker: string;
  os: 'unix' | 'windows';
}

export const CMDI_PAYLOADS_TIMING: CmdiTimingPayload[] = [
  { payload: '; sleep 5', delay: 5, os: 'unix' },
  { payload: '| sleep 5', delay: 5, os: 'unix' },
  { payload: '`sleep 5`', delay: 5, os: 'unix' },
  { payload: '$(sleep 5)', delay: 5, os: 'unix' },
  { payload: '%0asleep 5', delay: 5, os: 'unix' },
  { payload: '& timeout /t 5', delay: 5, os: 'windows' },
  { payload: '| timeout /t 5', delay: 5, os: 'windows' },
];

export const CMDI_PAYLOADS_OUTPUT: CmdiOutputPayload[] = [
  { payload: '; echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '`echo secbot-cmdi-marker`', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '$(echo secbot-cmdi-marker)', marker: 'secbot-cmdi-marker', os: 'unix' },
];
```

- [ ] **5.2: Write failing test**

Add to `test/unit/payload-context-wiring.test.ts`:

```typescript
describe('CMDi payload context wiring', () => {
  it('prioritizes unix payloads when OS is unix', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('unix');
    expect(result.timing[0].os).toBe('unix');
    expect(result.output[0].os).toBe('unix');
  });

  it('prioritizes windows payloads when OS is windows', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('windows');
    expect(result.timing[0].os).toBe('windows');
  });

  it('keeps all payloads when OS is unknown', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('unknown');
    const totalPayloads = result.timing.length + result.output.length;
    expect(totalPayloads).toBeGreaterThanOrEqual(7);
  });
});
```

- [ ] **5.3: Run test to verify it fails**

- [ ] **5.4: Implement prioritizeCmdiPayloads**

In `src/scanner/active/cmdi.ts`:

```typescript
import type { CmdiTimingPayload, CmdiOutputPayload } from '../../config/payloads/cmdi.js';

/** Reorder CMDi payloads: matching OS first, then the rest */
export function prioritizeCmdiPayloads(osHint: 'unix' | 'windows' | 'unknown'): {
  timing: CmdiTimingPayload[];
  output: CmdiOutputPayload[];
} {
  if (osHint === 'unknown') {
    return { timing: [...CMDI_PAYLOADS_TIMING], output: [...CMDI_PAYLOADS_OUTPUT] };
  }
  const timingPrioritized = [
    ...CMDI_PAYLOADS_TIMING.filter((p) => p.os === osHint),
    ...CMDI_PAYLOADS_TIMING.filter((p) => p.os !== osHint),
  ];
  const outputPrioritized = [
    ...CMDI_PAYLOADS_OUTPUT.filter((p) => p.os === osHint),
    ...CMDI_PAYLOADS_OUTPUT.filter((p) => p.os !== osHint),
  ];
  return { timing: timingPrioritized, output: outputPrioritized };
}
```

Then in `run()`, replace direct usage with:

```typescript
const { timing, output } = config.payloadContext
  ? prioritizeCmdiPayloads(config.payloadContext.osHint)
  : { timing: CMDI_PAYLOADS_TIMING, output: CMDI_PAYLOADS_OUTPUT };
```

- [ ] **5.5: Run tests, verify pass**

- [ ] **5.6: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass.

- [ ] **5.7: Commit**

```bash
git add src/config/payloads/cmdi.ts src/scanner/active/cmdi.ts test/unit/payload-context-wiring.test.ts
git commit -m "feat: wire payload context into CMDi — OS-aware payload ordering"
```

---

## Task 6: Recon ↔ Framework-Detector Merge

**Files:**
- Modify: `src/scanner/recon.ts:199-283` — `detectFramework()` checks `CrawledPage.framework` first
- Modify: `src/scanner/recon.ts:17-57` — `runRecon()` accepts pages with framework info

- [ ] **6.1: Write failing test**

Add to `test/unit/payload-context-wiring.test.ts`:

```typescript
describe('Recon framework merge', () => {
  it('uses crawled framework when available', async () => {
    const { runRecon } = await import('../../src/scanner/recon.js');
    const pages = [{
      url: 'http://localhost:3000/',
      status: 200,
      headers: {},
      title: 'Test',
      forms: [],
      links: [],
      scripts: [],
      cookies: [],
      framework: { name: 'angular', version: '20.3.17', strategy: 'angular-router' as const },
    }];
    const result = runRecon(pages, []);
    expect(result.framework.name).toBe('Angular');
    expect(result.framework.confidence).toBe('high');
    expect(result.framework.evidence).toContain('Crawl framework detection: angular v20.3.17');
  });
});
```

- [ ] **6.2: Run test to verify it fails**

Expected: FAIL — recon's `detectFramework()` doesn't check `CrawledPage.framework` and returns `{ confidence: 'low' }`.

- [ ] **6.3: Implement framework merge in recon.ts**

In `src/scanner/recon.ts`, modify `detectFramework()` to accept pages and check for crawler-detected framework FIRST:

```typescript
function detectFramework(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
): FrameworkDetection {
  // Priority 1: Use framework detected during crawl (Playwright-based, most accurate)
  const crawledFramework = pages.find((p) => p.framework)?.framework;
  if (crawledFramework) {
    const name = crawledFramework.name.charAt(0).toUpperCase() + crawledFramework.name.slice(1);
    const versionStr = crawledFramework.version ? ` v${crawledFramework.version}` : '';
    return {
      name,
      version: crawledFramework.version,
      confidence: 'high',
      evidence: [`Crawl framework detection: ${crawledFramework.name}${versionStr}`],
    };
  }

  // Priority 2: Existing header/body/script detection (fallback)
  const evidence: string[] = [];
  // ... rest of existing code unchanged
```

- [ ] **6.4: Run test to verify it passes**

- [ ] **6.5: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass.

- [ ] **6.6: Commit**

```bash
git add src/scanner/recon.ts test/unit/payload-context-wiring.test.ts
git commit -m "feat: recon consumes crawl framework info — single source of truth"
```

---

## Task 7: Benchmark + Version Bump + Final Validation

- [ ] **7.1: Run Juice Shop scan and record time**

```bash
cd /Users/dioatmando/Vibecode/experiments/secbot
time npx tsx src/index.ts scan http://localhost:3000 -p deep -f terminal --no-ai -y --verbose 2>&1 | tee /tmp/secbot-v011-benchmark.log
```

Expected: Scan time should be significantly faster than 18min baseline. Target: < 8min.
Look for log lines showing parallel vs sequential execution.

- [ ] **7.2: Verify payload context is logged per check**

In the scan output, confirm log lines like:
- `SQLi payload context: prioritizing 2 mysql payloads`
- `Payload context: SPA detected — prioritizing DOM XSS`
- `Recon: Crawl framework detection: angular v20.3.17`

- [ ] **7.3: Bump version to 0.11.0**

In `package.json`: `"version": "0.11.0"`
In `CLAUDE.md`: Update version, test count, and note parallel runner + payload context wiring.

- [ ] **7.4: Final full test run**

Run: `npx vitest run`
Expected: All tests pass (1270+ expected with new tests).

- [ ] **7.5: Commit version bump**

```bash
git add package.json CLAUDE.md
git commit -m "chore: bump to v0.11.0 — parallel checks, payload context wiring, recon merge"
```

# SecBot Reliability Fixes — Priority Checklist

> 4 of 8 real-target scans hang or fail. These are the root causes and fixes.
> Source: deep code audit of index.ts, browser.ts, fast-engine.ts, discovery/*, active/index.ts, templates/engine.ts

## Root Causes of 4/8 Failure Rate

1. **Crawl hangs on `networkidle`** — sites with WebSocket/SSE never reach idle, wastes 30s/page
2. **Content + param discovery consume the time budget** — 500 paths + 1000 probes = 10-15 min before active checks start
3. **WAF/CDN blocks cause slow timeouts, not fast failures** — WAFs hold connections 5-10s before 403
4. **Global timeout kills process with `process.exit(2)`** — all findings lost, no partial report

## Fix Priority Order

### Fix 1: Phase timeout utility (CRITICAL — enables all other fixes)

```typescript
// src/utils/phase-timeout.ts
export async function withPhaseTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  phaseName: string,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fn(controller.signal);
  } catch (err) {
    if (controller.signal.aborted) {
      throw new Error(`Phase "${phaseName}" timed out after ${timeoutMs / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
```

### Fix 2: Time-budget-aware pipeline in index.ts (CRITICAL)

Replace bare `await` calls with budget-aware wrapping:

```typescript
const scanStartMs = Date.now();
const timeBudgetMs = maxScanTimeMinutes * 60_000;

function remainingMs(): number {
  return Math.max(0, timeBudgetMs - (Date.now() - scanStartMs));
}

function hasTimeFor(phaseMinMs: number): boolean {
  return remainingMs() > phaseMinMs + 60_000; // reserve 60s for reporting
}
```

Wrap each phase:
```typescript
if (hasTimeFor(120_000)) {
  try {
    await withPhaseTimeout(
      () => discoverContent({...}),
      Math.min(remainingMs() * 0.3, 180_000), // max 3 min or 30% remaining
      'content-discovery',
    );
  } catch (err) {
    log.warn(`Content discovery: ${(err as Error).message}`);
  }
}
```

### Fix 3: Global timeout produces partial results instead of killing (CRITICAL)

Replace `process.exit(2)` with:
```typescript
let globalTimeoutFired = false;
const globalAbortController = new AbortController();
const scanTimeout = setTimeout(() => {
  log.error(`Scan exceeded ${maxScanTimeMinutes}min — generating partial report`);
  globalTimeoutFired = true;
  globalAbortController.abort();
}, maxScanTime);
```

Each phase checks: `if (globalTimeoutFired) break;`
Pipeline falls through to reporting with whatever findings exist.

### Fix 4: response.text() timeout in browser.ts (HIGH)

Line 298 — `response.text()` can hang forever on chunked responses:
```typescript
const textPromise = response.text();
const timeoutPromise = new Promise<string>((_, reject) =>
  setTimeout(() => reject(new Error('Response body read timeout')), 10_000),
);
body = await Promise.race([textPromise, timeoutPromise]);
```

### Fix 5: pendingResponses timeout in browser.ts (HIGH)

Line 387 — `Promise.allSettled(pendingResponses)` can wait forever:
```typescript
const pendingTimeout = new Promise<void>((resolve) => setTimeout(resolve, 15_000));
await Promise.race([Promise.allSettled(pendingResponses), pendingTimeout]);
```

### Fix 6: Body size limit in fast-engine.ts (MEDIUM)

Line 103 — `resp.text()` reads entire body into memory, no size limit:
```typescript
const contentLength = parseInt(resp.headers.get('content-length') ?? '0', 10);
if (contentLength > 5_000_000) {
  return { ...result, body: '[body too large]' };
}
const body = await resp.text();
```

### Fix 7: Active check total timeout (HIGH)

No cap on total active check time. 43 checks × 5 min each = 215 min worst case:
```typescript
const TOTAL_ACTIVE_TIMEOUT = { quick: 120_000, standard: 600_000, deep: 1200_000, stealth: 1200_000 };
const activeStart = Date.now();

// In sequential loop:
if (Date.now() - activeStart > totalTimeoutMs) {
  log.warn(`Active checks exceeded budget — skipping remaining`);
  break;
}
```

### Fix 8: Clear dangling timers in active check runner (MEDIUM)

Line 452 — `setTimeout` in `Promise.race` is never cleared:
```typescript
let timer: ReturnType<typeof setTimeout>;
const timeoutPromise = new Promise<never>((_, reject) => {
  timer = setTimeout(() => reject(new Error('timeout')), checkTimeoutMs);
});
try {
  const result = await Promise.race([check.run(...), timeoutPromise]);
  clearTimeout(timer!); // ADD THIS
} catch (err) {
  clearTimeout(timer!); // ADD THIS
}
```

### Fix 9: Template engine batch timeout (MEDIUM)

Templates run sequentially with no total timeout:
```typescript
for (const template of applicable) {
  if (Date.now() - startMs > timeoutMs) {
    log.warn(`Template scan exceeded budget — stopping`);
    break;
  }
  // run template...
}
```

## Quick Wins (implement today)

1. Fix 3 (partial results) — biggest user-facing improvement
2. Fix 7 (active check total timeout) — prevents infinite scan
3. Fix 4 + Fix 5 (browser response timeouts) — prevents crawl hangs
4. Fix 8 (clear timers) — prevents memory leaks

## Suggested Time Budgets Per Phase (standard profile, 30 min total)

| Phase | Budget | Notes |
|-------|--------|-------|
| Crawl | 5 min | Per-page timeout already exists |
| Recon | 2 min | Usually fast |
| Subdomain enum | 2 min | DNS + crt.sh |
| Content discovery | 3 min | 500 paths @ 20 concurrent |
| Param discovery | 3 min | 10 URLs × 100 params |
| JS analysis | 2 min | Download + parse |
| AI Plan | 1 min | Single Claude call |
| Passive scan | 1 min | Header/cookie analysis |
| Template scan | 3 min | 52 built-in + selected YAML |
| Active scan | 5 min | Time-budgeted checks |
| AI validate | 2 min | Batch Claude calls |
| AI report | 1 min | Single Claude call |
| **Total** | **30 min** | **Fits default budget** |

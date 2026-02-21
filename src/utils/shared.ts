import type { BrowserContext } from 'playwright';
import type { Severity } from '../scanner/types.js';

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function severityOrder(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}

export function formatDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

/** Normalize a URL by removing hash and trailing slash */
export function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    let path = u.pathname;
    if (path.length > 1 && path.endsWith('/')) {
      path = path.slice(0, -1);
    }
    u.pathname = path;
    return u.href;
  } catch {
    return url;
  }
}

/**
 * Measure response time using median of 3 requests for reliable timing.
 * Used by time-based blind detection (SQLi, command injection) to reduce
 * false positives from network jitter.
 */
export async function measureResponseTime(
  context: BrowserContext,
  url: string,
  options?: { method?: string; headers?: Record<string, string>; data?: string },
): Promise<number> {
  const times: number[] = [];
  for (let i = 0; i < 3; i++) {
    const page = await context.newPage();
    try {
      const start = Date.now();
      if (options?.method && options.method !== 'GET') {
        await page.request.fetch(url, {
          method: options.method,
          headers: options.headers,
          data: options.data,
        });
      } else {
        await page.request.fetch(url);
      }
      times.push(Date.now() - start);
    } catch {
      // Skip failed measurements
    } finally {
      await page.close();
    }
  }
  if (times.length === 0) return -1;
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)]; // median
}

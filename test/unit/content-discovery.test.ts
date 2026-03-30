import { describe, it, expect } from 'vitest';
import {
  selectPaths,
  isInteresting,
  mergeIntoEndpoints,
  COMMON_PATHS,
} from '../../src/scanner/discovery/content-discovery.js';
import type { FastResponse } from '../../src/scanner/fast-engine.js';
import type { DiscoveredEndpoint } from '../../src/scanner/discovery/content-discovery.js';

function makeResponse(overrides: Partial<FastResponse> = {}): FastResponse {
  return {
    url: 'https://example.com/admin',
    status: 200,
    headers: {},
    body: '',
    redirected: false,
    timeMs: 50,
    ...overrides,
  };
}

// ── COMMON_PATHS ────────────────────────────────────────────────────

describe('COMMON_PATHS', () => {
  it('has all expected generic categories', () => {
    expect(COMMON_PATHS).toHaveProperty('admin');
    expect(COMMON_PATHS).toHaveProperty('api');
    expect(COMMON_PATHS).toHaveProperty('debug');
    expect(COMMON_PATHS).toHaveProperty('config');
    expect(COMMON_PATHS).toHaveProperty('backup');
    expect(COMMON_PATHS).toHaveProperty('sensitive');
  });

  it('has framework-specific categories', () => {
    expect(COMMON_PATHS).toHaveProperty('wordpress');
    expect(COMMON_PATHS).toHaveProperty('rails');
    expect(COMMON_PATHS).toHaveProperty('laravel');
    expect(COMMON_PATHS).toHaveProperty('nextjs');
    expect(COMMON_PATHS).toHaveProperty('django');
    expect(COMMON_PATHS).toHaveProperty('spring');
    expect(COMMON_PATHS).toHaveProperty('dotnet');
  });

  it('each category has at least 5 paths', () => {
    for (const [cat, paths] of Object.entries(COMMON_PATHS)) {
      expect(paths.length, `category "${cat}" should have >= 5 paths`).toBeGreaterThanOrEqual(5);
    }
  });

  it('all paths start with /', () => {
    for (const [cat, paths] of Object.entries(COMMON_PATHS)) {
      for (const p of paths) {
        expect(p, `path in "${cat}"`).toMatch(/^\//);
      }
    }
  });
});

// ── selectPaths ─────────────────────────────────────────────────────

describe('selectPaths', () => {
  it('includes common paths by default (no framework)', () => {
    const paths = selectPaths(undefined, 500);
    expect(paths.length).toBeGreaterThan(0);

    // Should include generic categories
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('admin')).toBe(true);
    expect(categories.has('api')).toBe(true);
    expect(categories.has('debug')).toBe(true);
    expect(categories.has('config')).toBe(true);
    expect(categories.has('backup')).toBe(true);
    expect(categories.has('sensitive')).toBe(true);
  });

  it('does not include framework paths when no framework detected', () => {
    const paths = selectPaths(undefined, 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('wordpress')).toBe(false);
    expect(categories.has('rails')).toBe(false);
    expect(categories.has('nextjs')).toBe(false);
    expect(categories.has('django')).toBe(false);
    expect(categories.has('spring')).toBe(false);
    expect(categories.has('dotnet')).toBe(false);
  });

  it('adds WordPress paths when framework is WordPress', () => {
    const paths = selectPaths('WordPress', 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('wordpress')).toBe(true);

    const wpPaths = paths.filter(p => p.category === 'wordpress');
    expect(wpPaths.length).toBeGreaterThan(0);
    expect(wpPaths.some(p => p.path === '/wp-login.php')).toBe(true);
  });

  it('adds Next.js paths when framework is Next.js', () => {
    const paths = selectPaths('Next.js', 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('nextjs')).toBe(true);
  });

  it('adds Django paths when framework is Django', () => {
    const paths = selectPaths('Django', 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('django')).toBe(true);
  });

  it('adds Spring paths when framework is Spring Boot', () => {
    const paths = selectPaths('Spring Boot', 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('spring')).toBe(true);
  });

  it('adds .NET paths when framework is ASP.NET', () => {
    const paths = selectPaths('ASP.NET', 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('dotnet')).toBe(true);
  });

  it('adds Laravel paths when framework contains "php"', () => {
    const paths = selectPaths('PHP', 500);
    const categories = new Set(paths.map(p => p.category));
    expect(categories.has('laravel')).toBe(true);
  });

  it('deduplicates paths', () => {
    const paths = selectPaths(undefined, 500);
    const pathStrings = paths.map(p => p.path);
    const unique = new Set(pathStrings);
    expect(pathStrings.length).toBe(unique.size);
  });

  it('respects maxPaths limit', () => {
    const paths = selectPaths(undefined, 10);
    expect(paths.length).toBeLessThanOrEqual(10);
  });

  it('maxPaths of 0 returns empty array', () => {
    const paths = selectPaths(undefined, 0);
    expect(paths.length).toBe(0);
  });
});

// ── isInteresting ───────────────────────────────────────────────────

describe('isInteresting', () => {
  it('returns true for 200 on admin paths', () => {
    const resp = makeResponse({ status: 200 });
    expect(isInteresting(resp, 'admin')).toBe(true);
  });

  it('returns true for 200 on debug paths', () => {
    const resp = makeResponse({ status: 200 });
    expect(isInteresting(resp, 'debug')).toBe(true);
  });

  it('returns true for 200 on config paths', () => {
    const resp = makeResponse({ status: 200 });
    expect(isInteresting(resp, 'config')).toBe(true);
  });

  it('returns true for 200 on backup paths', () => {
    const resp = makeResponse({ status: 200 });
    expect(isInteresting(resp, 'backup')).toBe(true);
  });

  it('returns true for 200 on sensitive paths', () => {
    const resp = makeResponse({ status: 200 });
    expect(isInteresting(resp, 'sensitive')).toBe(true);
  });

  it('returns true for 200 on API paths with content', () => {
    const resp = makeResponse({ status: 200, body: 'x'.repeat(200) });
    expect(isInteresting(resp, 'api')).toBe(true);
  });

  it('returns false for 200 on API paths with minimal content', () => {
    const resp = makeResponse({ status: 200, body: '{}' });
    expect(isInteresting(resp, 'api')).toBe(false);
  });

  it('returns true for 403 on admin paths', () => {
    const resp = makeResponse({ status: 403 });
    expect(isInteresting(resp, 'admin')).toBe(true);
  });

  it('returns true for 403 on debug paths', () => {
    const resp = makeResponse({ status: 403 });
    expect(isInteresting(resp, 'debug')).toBe(true);
  });

  it('returns true for 403 on sensitive paths', () => {
    const resp = makeResponse({ status: 403 });
    expect(isInteresting(resp, 'sensitive')).toBe(true);
  });

  it('returns false for 403 on backup paths (common for static assets)', () => {
    const resp = makeResponse({ status: 403 });
    expect(isInteresting(resp, 'backup')).toBe(false);
  });

  it('returns false for 404', () => {
    const resp = makeResponse({ status: 404 });
    expect(isInteresting(resp, 'admin')).toBe(false);
    expect(isInteresting(resp, 'api')).toBe(false);
    expect(isInteresting(resp, 'debug')).toBe(false);
    expect(isInteresting(resp, 'config')).toBe(false);
  });

  it('returns true for 405 on API endpoints', () => {
    const resp = makeResponse({ status: 405 });
    expect(isInteresting(resp, 'api')).toBe(true);
  });

  it('returns false for 405 on non-API paths', () => {
    const resp = makeResponse({ status: 405 });
    expect(isInteresting(resp, 'admin')).toBe(false);
  });

  it('returns true for redirect (301) on admin paths', () => {
    const resp = makeResponse({ status: 301 });
    expect(isInteresting(resp, 'admin')).toBe(true);
  });

  it('returns true for redirect (302) on debug paths', () => {
    const resp = makeResponse({ status: 302 });
    expect(isInteresting(resp, 'debug')).toBe(true);
  });

  it('returns false for redirect on API paths', () => {
    const resp = makeResponse({ status: 302 });
    expect(isInteresting(resp, 'api')).toBe(false);
  });

  it('returns true for 200 on framework-specific paths', () => {
    const resp = makeResponse({ status: 200 });
    expect(isInteresting(resp, 'wordpress')).toBe(true);
    expect(isInteresting(resp, 'rails')).toBe(true);
    expect(isInteresting(resp, 'laravel')).toBe(true);
    expect(isInteresting(resp, 'django')).toBe(true);
    expect(isInteresting(resp, 'spring')).toBe(true);
    expect(isInteresting(resp, 'dotnet')).toBe(true);
  });
});

// ── mergeIntoEndpoints ──────────────────────────────────────────────

describe('mergeIntoEndpoints', () => {
  it('adds new pages from discovered endpoints', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/admin', status: 200, contentType: 'text/html', contentLength: 500, category: 'admin', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, [], []);
    expect(result.newPages).toContain('https://example.com/admin');
  });

  it('adds new API routes from discovered API endpoints', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/api/v1/users', status: 200, contentType: 'application/json', contentLength: 500, category: 'api', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, [], []);
    expect(result.newApiRoutes).toContain('https://example.com/api/v1/users');
  });

  it('does not add pages that already exist', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/admin', status: 200, contentType: 'text/html', contentLength: 500, category: 'admin', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, ['https://example.com/admin'], []);
    expect(result.newPages).toHaveLength(0);
  });

  it('does not add API routes that already exist', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/api/v1', status: 200, contentType: 'application/json', contentLength: 500, category: 'api', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, [], ['https://example.com/api/v1']);
    expect(result.newApiRoutes).toHaveLength(0);
  });

  it('skips non-interesting endpoints', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/robots.txt', status: 200, contentType: 'text/plain', contentLength: 50, category: 'backup', interesting: false },
    ];
    const result = mergeIntoEndpoints(discovered, [], []);
    expect(result.newPages).toHaveLength(0);
    expect(result.newApiRoutes).toHaveLength(0);
  });

  it('classifies API endpoints by category', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/graphql', status: 200, contentType: 'application/json', contentLength: 500, category: 'api', interesting: true },
      { url: 'https://example.com/swagger.json', status: 200, contentType: 'application/json', contentLength: 500, category: 'api', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, [], []);
    expect(result.newApiRoutes).toContain('https://example.com/graphql');
    expect(result.newApiRoutes).toContain('https://example.com/swagger.json');
  });

  it('classifies non-API endpoints as pages', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/admin/dashboard', status: 200, contentType: 'text/html', contentLength: 1000, category: 'admin', interesting: true },
      { url: 'https://example.com/debug', status: 200, contentType: 'text/html', contentLength: 500, category: 'debug', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, [], []);
    expect(result.newPages).toContain('https://example.com/admin/dashboard');
    expect(result.newPages).toContain('https://example.com/debug');
  });

  it('classifies by content-type even if category is not api', () => {
    const discovered: DiscoveredEndpoint[] = [
      { url: 'https://example.com/config.json', status: 200, contentType: 'application/json', contentLength: 500, category: 'config', interesting: true },
    ];
    const result = mergeIntoEndpoints(discovered, [], []);
    expect(result.newApiRoutes).toContain('https://example.com/config.json');
  });
});

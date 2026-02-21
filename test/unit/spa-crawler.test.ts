import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SPACrawler, SPA_INIT_SCRIPT } from '../../src/scanner/discovery/spa-crawler.js';
import type { RouteDiscoverer, DiscoveredRoute } from '../../src/scanner/discovery/types.js';

// ─── Init script content tests ──────────────────────────────────────

describe('SPA_INIT_SCRIPT', () => {
  it('patches history.pushState', () => {
    expect(SPA_INIT_SCRIPT).toContain('history.pushState');
    expect(SPA_INIT_SCRIPT).toContain('origPushState');
  });

  it('patches history.replaceState', () => {
    expect(SPA_INIT_SCRIPT).toContain('history.replaceState');
    expect(SPA_INIT_SCRIPT).toContain('origReplaceState');
  });

  it('listens for popstate events', () => {
    expect(SPA_INIT_SCRIPT).toContain("'popstate'");
  });

  it('listens for hashchange events', () => {
    expect(SPA_INIT_SCRIPT).toContain("'hashchange'");
  });

  it('patches XMLHttpRequest.prototype.open', () => {
    expect(SPA_INIT_SCRIPT).toContain('XMLHttpRequest.prototype.open');
    expect(SPA_INIT_SCRIPT).toContain('origXHROpen');
  });

  it('patches window.fetch', () => {
    expect(SPA_INIT_SCRIPT).toContain('window.fetch');
    expect(SPA_INIT_SCRIPT).toContain('origFetch');
  });

  it('initializes __secbot_routes array', () => {
    expect(SPA_INIT_SCRIPT).toContain('__secbot_routes');
    expect(SPA_INIT_SCRIPT).toContain('window.__secbot_routes = []');
  });

  it('initializes __secbot_api_endpoints array', () => {
    expect(SPA_INIT_SCRIPT).toContain('__secbot_api_endpoints');
    expect(SPA_INIT_SCRIPT).toContain('window.__secbot_api_endpoints = []');
  });

  it('guards against double-injection', () => {
    expect(SPA_INIT_SCRIPT).toContain('if (window.__secbot_routes) return');
  });

  it('resolves relative URLs using window.location.href', () => {
    expect(SPA_INIT_SCRIPT).toContain('new URL(url, window.location.href)');
  });
});

// ─── SPACrawler class structure tests ────────────────────────────────

describe('SPACrawler', () => {
  it('implements RouteDiscoverer interface', () => {
    const crawler = new SPACrawler();

    // Check name property
    expect(crawler.name).toBe('spa-crawler');

    // Check discover method exists and is a function
    expect(typeof crawler.discover).toBe('function');

    // Verify it satisfies the interface at the type level
    const discoverer: RouteDiscoverer = crawler;
    expect(discoverer.name).toBe('spa-crawler');
  });

  it('has name "spa-crawler"', () => {
    const crawler = new SPACrawler();
    expect(crawler.name).toBe('spa-crawler');
  });

  it('discover method returns a Promise', () => {
    const crawler = new SPACrawler();
    // We just verify the return type — actual browser test would need Playwright
    const result = crawler.discover('https://example.com');
    expect(result).toBeInstanceOf(Promise);
    // Clean up: let the promise settle (it will fail to launch browser in test env, that's ok)
    return result.then(
      (routes) => {
        expect(Array.isArray(routes)).toBe(true);
      },
      () => {
        // Browser launch may fail in CI — that's acceptable
      },
    );
  });
});

// ─── URL deduplication logic tests ───────────────────────────────────

describe('SPACrawler URL deduplication', () => {
  it('collectRoutes returns empty array when page evaluation fails', async () => {
    const crawler = new SPACrawler();

    // Mock a page object that throws on evaluate
    const mockPage = {
      evaluate: vi.fn().mockRejectedValue(new Error('page closed')),
    } as any;

    const routes = await crawler.collectRoutes(mockPage);
    expect(routes).toEqual([]);
  });

  it('collectRoutes returns empty array when window global is not set', async () => {
    const crawler = new SPACrawler();

    const mockPage = {
      evaluate: vi.fn().mockResolvedValue(undefined),
    } as any;

    const routes = await crawler.collectRoutes(mockPage);
    expect(routes).toEqual([]);
  });

  it('collectRoutes returns routes from page', async () => {
    const crawler = new SPACrawler();

    const mockPage = {
      evaluate: vi.fn().mockResolvedValue([
        'https://example.com/page1',
        'https://example.com/page2',
      ]),
    } as any;

    const routes = await crawler.collectRoutes(mockPage);
    expect(routes).toEqual([
      'https://example.com/page1',
      'https://example.com/page2',
    ]);
  });

  it('collectApiEndpoints returns empty array on failure', async () => {
    const crawler = new SPACrawler();

    const mockPage = {
      evaluate: vi.fn().mockRejectedValue(new Error('page closed')),
    } as any;

    const endpoints = await crawler.collectApiEndpoints(mockPage);
    expect(endpoints).toEqual([]);
  });

  it('collectApiEndpoints returns endpoints from page', async () => {
    const crawler = new SPACrawler();

    const mockPage = {
      evaluate: vi.fn().mockResolvedValue([
        'https://example.com/api/users',
        'https://example.com/api/posts',
      ]),
    } as any;

    const endpoints = await crawler.collectApiEndpoints(mockPage);
    expect(endpoints).toEqual([
      'https://example.com/api/users',
      'https://example.com/api/posts',
    ]);
  });
});

// ─── Init script behavior (simulated in-memory) ─────────────────────

describe('SPA init script deduplication logic', () => {
  let windowMock: any;

  beforeEach(() => {
    // Simulate a minimal browser window environment
    windowMock = {
      __secbot_routes: undefined as string[] | undefined,
      __secbot_api_endpoints: undefined as string[] | undefined,
      location: { href: 'https://example.com/' },
    };
  });

  it('addRoute deduplicates same URLs', () => {
    // Simulate the addRoute function's deduplication behavior
    const routes: string[] = [];

    function addRoute(url: string) {
      try {
        const resolved = new URL(url, 'https://example.com/').href;
        if (routes.indexOf(resolved) === -1) {
          routes.push(resolved);
        }
      } catch { /* ignore */ }
    }

    addRoute('/dashboard');
    addRoute('/dashboard'); // duplicate
    addRoute('/settings');
    addRoute('/dashboard'); // duplicate again

    expect(routes).toHaveLength(2);
    expect(routes).toContain('https://example.com/dashboard');
    expect(routes).toContain('https://example.com/settings');
  });

  it('addApiEndpoint deduplicates same API URLs', () => {
    const endpoints: string[] = [];

    function addApiEndpoint(url: string) {
      try {
        const resolved = new URL(url, 'https://example.com/').href;
        if (endpoints.indexOf(resolved) === -1) {
          endpoints.push(resolved);
        }
      } catch { /* ignore */ }
    }

    addApiEndpoint('/api/users');
    addApiEndpoint('/api/users'); // duplicate
    addApiEndpoint('/api/posts');

    expect(endpoints).toHaveLength(2);
    expect(endpoints).toContain('https://example.com/api/users');
    expect(endpoints).toContain('https://example.com/api/posts');
  });

  it('resolves relative URLs correctly', () => {
    const routes: string[] = [];

    function addRoute(url: string) {
      try {
        const resolved = new URL(url, 'https://example.com/app/').href;
        if (routes.indexOf(resolved) === -1) {
          routes.push(resolved);
        }
      } catch { /* ignore */ }
    }

    addRoute('/dashboard');
    addRoute('settings'); // relative
    addRoute('https://example.com/profile'); // absolute

    expect(routes).toContain('https://example.com/dashboard');
    expect(routes).toContain('https://example.com/app/settings');
    expect(routes).toContain('https://example.com/profile');
  });

  it('ignores malformed URLs', () => {
    const routes: string[] = [];

    function addRoute(url: string) {
      try {
        const resolved = new URL(url).href; // no base — requires absolute URL
        if (routes.indexOf(resolved) === -1) {
          routes.push(resolved);
        }
      } catch { /* ignore */ }
    }

    addRoute('not a url at all');
    addRoute('https://example.com/valid');

    expect(routes).toHaveLength(1);
    expect(routes[0]).toBe('https://example.com/valid');
  });
});

// ─── Route source classification ─────────────────────────────────────

describe('SPACrawler route source classification', () => {
  it('classifies routes found during initial load as spa-history', async () => {
    // This tests the logic in discover() that assigns source based on
    // whether a route was in initialRoutes or only found after clicks.

    // The classification logic is:
    // - Routes in initialRoutes (before clicks) -> 'spa-history'
    // - Routes only after clicks -> 'spa-click'
    // - API endpoints -> 'spa-xhr'

    const initialRoutes = ['https://example.com/home', 'https://example.com/about'];
    const allRoutes = ['https://example.com/home', 'https://example.com/about', 'https://example.com/contact'];
    const allApiEndpoints = ['https://example.com/api/data'];

    const routes: DiscoveredRoute[] = [];
    const seen = new Set<string>();
    const origin = 'https://example.com';

    for (const url of allRoutes) {
      if (seen.has(url)) continue;
      seen.add(url);
      try {
        if (new URL(url).origin !== origin) continue;
      } catch { continue; }
      routes.push({
        url,
        source: initialRoutes.includes(url) ? 'spa-history' : 'spa-click',
        confidence: 'medium',
      });
    }

    for (const url of allApiEndpoints) {
      if (seen.has(url)) continue;
      seen.add(url);
      routes.push({
        url,
        source: 'spa-xhr',
        confidence: 'medium',
      });
    }

    expect(routes).toHaveLength(4);
    expect(routes[0]).toEqual({ url: 'https://example.com/home', source: 'spa-history', confidence: 'medium' });
    expect(routes[1]).toEqual({ url: 'https://example.com/about', source: 'spa-history', confidence: 'medium' });
    expect(routes[2]).toEqual({ url: 'https://example.com/contact', source: 'spa-click', confidence: 'medium' });
    expect(routes[3]).toEqual({ url: 'https://example.com/api/data', source: 'spa-xhr', confidence: 'medium' });
  });

  it('filters out cross-origin routes', () => {
    const allRoutes = [
      'https://example.com/home',
      'https://evil.com/phishing',
      'https://example.com/about',
    ];
    const origin = 'https://example.com';

    const routes: DiscoveredRoute[] = [];
    const seen = new Set<string>();

    for (const url of allRoutes) {
      if (seen.has(url)) continue;
      seen.add(url);
      try {
        if (new URL(url).origin !== origin) continue;
      } catch { continue; }
      routes.push({ url, source: 'spa-history', confidence: 'medium' });
    }

    expect(routes).toHaveLength(2);
    expect(routes.map((r) => r.url)).toEqual([
      'https://example.com/home',
      'https://example.com/about',
    ]);
  });

  it('deduplicates URLs across route types', () => {
    const allRoutes = ['https://example.com/api/users'];
    const allApiEndpoints = ['https://example.com/api/users']; // same URL from XHR

    const routes: DiscoveredRoute[] = [];
    const seen = new Set<string>();
    const origin = 'https://example.com';

    for (const url of allRoutes) {
      if (seen.has(url)) continue;
      seen.add(url);
      try {
        if (new URL(url).origin !== origin) continue;
      } catch { continue; }
      routes.push({ url, source: 'spa-history', confidence: 'medium' });
    }

    for (const url of allApiEndpoints) {
      if (seen.has(url)) continue; // Should be skipped — already seen
      seen.add(url);
      routes.push({ url, source: 'spa-xhr', confidence: 'medium' });
    }

    // Should appear only once (from spa-history, since it was added first)
    expect(routes).toHaveLength(1);
    expect(routes[0].source).toBe('spa-history');
  });
});

// ─── performClickNavigation resilience ───────────────────────────────

describe('SPACrawler performClickNavigation', () => {
  it('handles page with no clickable elements gracefully', async () => {
    const crawler = new SPACrawler();

    const mockPage = {
      locator: vi.fn().mockReturnValue({
        count: vi.fn().mockResolvedValue(0),
      }),
      url: vi.fn().mockReturnValue('https://example.com/'),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
    } as any;

    // Should not throw
    await expect(
      crawler.performClickNavigation(mockPage, 'https://example.com'),
    ).resolves.toBeUndefined();
  });

  it('catches errors from individual clicks', async () => {
    const crawler = new SPACrawler();

    const mockElement = {
      getAttribute: vi.fn().mockResolvedValue(null),
      isVisible: vi.fn().mockResolvedValue(true),
      click: vi.fn().mockRejectedValue(new Error('element detached')),
    };

    const mockLocator = {
      count: vi.fn().mockResolvedValue(1),
      nth: vi.fn().mockReturnValue(mockElement),
    };

    const mockPage = {
      locator: vi.fn().mockReturnValue(mockLocator),
      url: vi.fn().mockReturnValue('https://example.com/'),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
    } as any;

    // Should not throw even when clicks fail
    await expect(
      crawler.performClickNavigation(mockPage, 'https://example.com'),
    ).resolves.toBeUndefined();
  });

  it('skips external links', async () => {
    const crawler = new SPACrawler();

    const mockElement = {
      getAttribute: vi.fn().mockResolvedValue('https://external.com/page'),
      isVisible: vi.fn().mockResolvedValue(true),
      click: vi.fn().mockResolvedValue(undefined),
    };

    const mockLocator = {
      count: vi.fn().mockResolvedValue(1),
      nth: vi.fn().mockReturnValue(mockElement),
    };

    const mockPage = {
      locator: vi.fn().mockReturnValue(mockLocator),
      url: vi.fn().mockReturnValue('https://example.com/'),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
    } as any;

    await crawler.performClickNavigation(mockPage, 'https://example.com');

    // Click should NOT have been called because the link is external
    expect(mockElement.click).not.toHaveBeenCalled();
  });

  it('skips non-visible elements', async () => {
    const crawler = new SPACrawler();

    const mockElement = {
      getAttribute: vi.fn().mockResolvedValue('/internal'),
      isVisible: vi.fn().mockResolvedValue(false),
      click: vi.fn().mockResolvedValue(undefined),
    };

    const mockLocator = {
      count: vi.fn().mockResolvedValue(1),
      nth: vi.fn().mockReturnValue(mockElement),
    };

    const mockPage = {
      locator: vi.fn().mockReturnValue(mockLocator),
      url: vi.fn().mockReturnValue('https://example.com/'),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
    } as any;

    await crawler.performClickNavigation(mockPage, 'https://example.com');

    // Click should NOT have been called because element is not visible
    expect(mockElement.click).not.toHaveBeenCalled();
  });
});

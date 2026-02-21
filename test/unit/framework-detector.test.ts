import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  detectFramework,
  getFrameworkHints,
  waitForHydration,
  type FrameworkInfo,
} from '../../src/scanner/discovery/framework-detector.js';

// ─── Helpers: mock Playwright Page ──────────────────────────────────

function createMockPage(evaluateResult: unknown = null) {
  const page = {
    evaluate: vi.fn().mockResolvedValue(evaluateResult),
    waitForFunction: vi.fn().mockResolvedValue(undefined),
    waitForTimeout: vi.fn().mockResolvedValue(undefined),
  };
  return page as unknown as import('playwright').Page;
}

// ─── detectFramework ────────────────────────────────────────────────

describe('detectFramework', () => {
  it('detects Next.js', async () => {
    const page = createMockPage({
      name: 'nextjs',
      version: undefined,
      router: 'nextjs',
      evidence: ['__NEXT_DATA__ global found'],
    });

    const result = await detectFramework(page);

    expect(result).not.toBeNull();
    expect(result!.name).toBe('nextjs');
    expect(result!.router).toBe('nextjs');
    expect(result!.evidence).toContain('__NEXT_DATA__ global found');
  });

  it('detects React', async () => {
    const page = createMockPage({
      name: 'react',
      router: 'react-router',
      evidence: ['_reactRootContainer found', 'React Router link markers found'],
    });

    const result = await detectFramework(page);

    expect(result).not.toBeNull();
    expect(result!.name).toBe('react');
    expect(result!.router).toBe('react-router');
  });

  it('detects Vue', async () => {
    const page = createMockPage({
      name: 'vue',
      version: '3.4.0',
      router: 'vue-router',
      evidence: ['Vue global detected', 'Vue Router link markers found'],
    });

    const result = await detectFramework(page);

    expect(result).not.toBeNull();
    expect(result!.name).toBe('vue');
    expect(result!.version).toBe('3.4.0');
    expect(result!.router).toBe('vue-router');
  });

  it('detects Angular with version', async () => {
    const page = createMockPage({
      name: 'angular',
      version: '17.0.0',
      router: 'angular-router',
      evidence: ['ng-version attribute: 17.0.0'],
    });

    const result = await detectFramework(page);

    expect(result).not.toBeNull();
    expect(result!.name).toBe('angular');
    expect(result!.version).toBe('17.0.0');
    expect(result!.router).toBe('angular-router');
  });

  it('detects Svelte', async () => {
    const page = createMockPage({
      name: 'svelte',
      router: 'svelte-kit',
      evidence: ['Svelte markers found', 'SvelteKit router markers found'],
    });

    const result = await detectFramework(page);

    expect(result).not.toBeNull();
    expect(result!.name).toBe('svelte');
    expect(result!.router).toBe('svelte-kit');
  });

  it('detects Nuxt', async () => {
    const page = createMockPage({
      name: 'nuxt',
      router: 'vue-router',
      evidence: ['__NUXT__ detected'],
    });

    const result = await detectFramework(page);

    expect(result).not.toBeNull();
    expect(result!.name).toBe('nuxt');
    expect(result!.router).toBe('vue-router');
  });

  it('returns null for unknown framework', async () => {
    const page = createMockPage(null);

    const result = await detectFramework(page);

    expect(result).toBeNull();
  });

  it('returns null and does not throw on page.evaluate error', async () => {
    const page = createMockPage();
    (page.evaluate as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Execution context destroyed'));

    const result = await detectFramework(page);

    expect(result).toBeNull();
  });
});

// ─── getFrameworkHints ──────────────────────────────────────────────

describe('getFrameworkHints', () => {
  it('returns generic hints when framework is null', () => {
    const hints = getFrameworkHints(null);

    expect(hints.linkSelectors).toEqual(['a[href]']);
    expect(hints.waitForHydration).toBe(false);
    expect(hints.routeAttributes).toEqual([]);
  });

  it('returns React hints with router selectors', () => {
    const framework: FrameworkInfo = {
      name: 'react',
      router: 'react-router',
      evidence: [],
    };

    const hints = getFrameworkHints(framework);

    expect(hints.waitForHydration).toBe(true);
    expect(hints.linkSelectors).toContain('a[data-discover]');
    expect(hints.linkSelectors).toContain('a[href]');
    expect(hints.routeAttributes).toContain('data-discover');
  });

  it('returns minimal Next.js hints (handled by NextJsExtractor)', () => {
    const framework: FrameworkInfo = {
      name: 'nextjs',
      router: 'nextjs',
      evidence: [],
    };

    const hints = getFrameworkHints(framework);

    expect(hints.waitForHydration).toBe(true);
    expect(hints.linkSelectors).toEqual(['a[href]']);
    expect(hints.routeAttributes).toEqual([]);
  });

  it('returns Vue hints with router-link selectors', () => {
    const framework: FrameworkInfo = {
      name: 'vue',
      router: 'vue-router',
      evidence: [],
    };

    const hints = getFrameworkHints(framework);

    expect(hints.waitForHydration).toBe(true);
    expect(hints.linkSelectors).toContain('a.router-link-active');
    expect(hints.linkSelectors).toContain('[class*="router-link"]');
    expect(hints.routeAttributes).toContain('to');
  });

  it('returns Nuxt hints (same as Vue)', () => {
    const framework: FrameworkInfo = {
      name: 'nuxt',
      router: 'vue-router',
      evidence: [],
    };

    const hints = getFrameworkHints(framework);

    expect(hints.waitForHydration).toBe(true);
    expect(hints.linkSelectors).toContain('a.router-link-active');
  });

  it('returns Angular hints with routerLink selectors', () => {
    const framework: FrameworkInfo = {
      name: 'angular',
      version: '17.0.0',
      router: 'angular-router',
      evidence: [],
    };

    const hints = getFrameworkHints(framework);

    expect(hints.waitForHydration).toBe(true);
    expect(hints.linkSelectors).toContain('a[routerLink]');
    expect(hints.linkSelectors).toContain('[ng-reflect-router-link]');
    expect(hints.routeAttributes).toContain('routerLink');
  });

  it('returns Svelte hints with SvelteKit selectors', () => {
    const framework: FrameworkInfo = {
      name: 'svelte',
      router: 'svelte-kit',
      evidence: [],
    };

    const hints = getFrameworkHints(framework);

    expect(hints.waitForHydration).toBe(true);
    expect(hints.linkSelectors).toContain('a[data-sveltekit-preload-data]');
  });
});

// ─── waitForHydration ───────────────────────────────────────────────

describe('waitForHydration', () => {
  it('uses generic wait when framework is null', async () => {
    const page = createMockPage();

    await waitForHydration(page, null);

    expect(page.waitForFunction).toHaveBeenCalledTimes(1);
    expect(page.waitForTimeout).toHaveBeenCalledWith(500); // idle grace
  });

  it('waits for Next.js hydration markers', async () => {
    const page = createMockPage();
    const framework: FrameworkInfo = {
      name: 'nextjs',
      router: 'nextjs',
      evidence: [],
    };

    await waitForHydration(page, framework);

    expect(page.waitForFunction).toHaveBeenCalledTimes(1);
    // Check that it was called with a function and timeout option
    const call = (page.waitForFunction as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[1]).toEqual({ timeout: 5000 });
  });

  it('waits for React hydration markers', async () => {
    const page = createMockPage();
    const framework: FrameworkInfo = {
      name: 'react',
      router: 'unknown',
      evidence: [],
    };

    await waitForHydration(page, framework);

    expect(page.waitForFunction).toHaveBeenCalledTimes(1);
    const call = (page.waitForFunction as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[1]).toEqual({ timeout: 5000 });
  });

  it('waits for Vue hydration markers', async () => {
    const page = createMockPage();
    const framework: FrameworkInfo = {
      name: 'vue',
      router: 'vue-router',
      evidence: [],
    };

    await waitForHydration(page, framework);

    expect(page.waitForFunction).toHaveBeenCalledTimes(1);
  });

  it('waits for Angular hydration markers', async () => {
    const page = createMockPage();
    const framework: FrameworkInfo = {
      name: 'angular',
      router: 'angular-router',
      evidence: [],
    };

    await waitForHydration(page, framework);

    expect(page.waitForFunction).toHaveBeenCalledTimes(1);
  });

  it('waits for Svelte hydration markers', async () => {
    const page = createMockPage();
    const framework: FrameworkInfo = {
      name: 'svelte',
      router: 'svelte-kit',
      evidence: [],
    };

    await waitForHydration(page, framework);

    expect(page.waitForFunction).toHaveBeenCalledTimes(1);
  });

  it('does not throw when hydration wait times out', async () => {
    const page = createMockPage();
    (page.waitForFunction as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('Timeout 5000ms exceeded'),
    );

    const framework: FrameworkInfo = {
      name: 'react',
      router: 'unknown',
      evidence: [],
    };

    // Should not throw — timeout is expected and handled
    await expect(waitForHydration(page, framework)).resolves.toBeUndefined();
  });

  it('adds idle grace period after framework condition is met', async () => {
    const page = createMockPage();
    const framework: FrameworkInfo = {
      name: 'angular',
      router: 'angular-router',
      evidence: [],
    };

    await waitForHydration(page, framework);

    // Should call waitForTimeout with the idle grace period (500ms)
    expect(page.waitForTimeout).toHaveBeenCalledWith(500);
  });
});

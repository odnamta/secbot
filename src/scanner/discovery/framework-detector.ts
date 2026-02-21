import type { Page } from 'playwright';
import { log } from '../../utils/logger.js';

// ─── Types ──────────────────────────────────────────────────────────

export type SpaFramework = 'react' | 'nextjs' | 'vue' | 'nuxt' | 'angular' | 'svelte';
export type RouterType = 'react-router' | 'nextjs' | 'vue-router' | 'angular-router' | 'svelte-kit' | 'unknown';

export interface FrameworkInfo {
  name: SpaFramework;
  version?: string;
  router: RouterType;
  evidence: string[];
}

export interface CrawlHints {
  /** CSS selectors for link-like elements the framework renders */
  linkSelectors: string[];
  /** Whether to wait for client-side hydration before extracting links */
  waitForHydration: boolean;
  /** Additional attributes that may contain route URLs */
  routeAttributes: string[];
}

// ─── Framework Detection (B.1.4) ───────────────────────────────────

/**
 * Detect the SPA framework used on the current page by evaluating
 * framework-specific global markers in the browser context.
 */
export async function detectFramework(page: Page): Promise<FrameworkInfo | null> {
  try {
    const result = await page.evaluate(() => {
      const w = window as Record<string, unknown>;
      const doc = document;
      const evidence: string[] = [];

      // ── Next.js (check before generic React — Next.js IS React) ──
      if (w.__NEXT_DATA__ || doc.querySelector('#__next')) {
        evidence.push('__NEXT_DATA__' in w ? '__NEXT_DATA__ global found' : '#__next element found');
        let version: string | undefined;
        try {
          const nd = w.__NEXT_DATA__ as { nextExport?: boolean; buildId?: string } | undefined;
          if (nd?.buildId) evidence.push(`buildId: ${nd.buildId}`);
        } catch { /* ignore */ }
        // Check for version in script tags
        const scripts = Array.from(doc.querySelectorAll('script[src*="/_next/"]'));
        if (scripts.length > 0) evidence.push(`${scripts.length} Next.js script bundles`);
        return { name: 'nextjs' as const, version, router: 'nextjs' as const, evidence };
      }

      // ── Nuxt (check before generic Vue — Nuxt IS Vue) ──
      if (w.__NUXT__ || w.__NUXT_ASYNC_DATA__ || doc.querySelector('#__nuxt')) {
        evidence.push('__NUXT__ detected');
        return { name: 'nuxt' as const, router: 'vue-router' as const, evidence };
      }

      // ── React (generic) ──
      if (w.__REACT_DEVTOOLS_GLOBAL_HOOK__ || w._reactRootContainer) {
        evidence.push(
          '_reactRootContainer' in w ? '_reactRootContainer found' : '__REACT_DEVTOOLS_GLOBAL_HOOK__ found',
        );
        // Check for data-reactroot attribute
        const reactRoot = doc.querySelector('[data-reactroot]');
        if (reactRoot) evidence.push('data-reactroot attribute found');

        // Try to detect router type
        let router: 'react-router' | 'unknown' = 'unknown';
        // React Router v6+ uses data-discover attribute on links
        if (doc.querySelector('a[data-discover]') || doc.querySelector('[data-reactrouter]')) {
          router = 'react-router';
          evidence.push('React Router link markers found');
        }
        return { name: 'react' as const, router, evidence };
      }

      // ── Vue (generic) ──
      if (w.__VUE__ || w.__vue_app__ || w.__VUE_APP__) {
        evidence.push('Vue global detected');
        let router: 'vue-router' | 'unknown' = 'unknown';
        // Check for router-link components (rendered as <a> with class router-link-*)
        if (doc.querySelector('.router-link-active') || doc.querySelector('[class*="router-link"]') || doc.querySelector('router-link')) {
          router = 'vue-router';
          evidence.push('Vue Router link markers found');
        }
        let version: string | undefined;
        if (typeof w.__VUE__ === 'string') version = w.__VUE__ as string;
        return { name: 'vue' as const, version, router, evidence };
      }

      // ── Angular ──
      const ngVersionEl = doc.querySelector('[ng-version]');
      if (ngVersionEl) {
        const version = ngVersionEl.getAttribute('ng-version') ?? undefined;
        evidence.push(`ng-version attribute: ${version ?? 'present'}`);
        return { name: 'angular' as const, version, router: 'angular-router' as const, evidence };
      }
      // Fallback: check for Angular's getAllAngularRootElements
      if (typeof (w as Record<string, unknown>).getAllAngularRootElements === 'function') {
        evidence.push('getAllAngularRootElements() available');
        return { name: 'angular' as const, router: 'angular-router' as const, evidence };
      }

      // ── Svelte ──
      if (w.__svelte_meta || doc.querySelector('[class^="svelte-"]') || doc.querySelector('[data-svelte-h]')) {
        evidence.push('Svelte markers found');
        let router: 'svelte-kit' | 'unknown' = 'unknown';
        // SvelteKit uses data-sveltekit-* attributes
        if (doc.querySelector('[data-sveltekit-preload-data]') || doc.querySelector('[data-sveltekit-reload]')) {
          router = 'svelte-kit';
          evidence.push('SvelteKit router markers found');
        }
        return { name: 'svelte' as const, router, evidence };
      }

      return null;
    });

    if (result) {
      log.info(`Framework detected: ${result.name}${result.version ? ` v${result.version}` : ''} (${result.router})`);
      return result;
    }

    log.debug('No SPA framework detected');
    return null;
  } catch (err) {
    log.debug(`Framework detection failed: ${(err as Error).message}`);
    return null;
  }
}

// ─── Framework-Specific Crawling Hints (B.1.4) ────────────────────

/**
 * Return crawl hints tailored to the detected framework.
 * These help the SPA crawler find links that plain <a href> extraction would miss.
 */
export function getFrameworkHints(framework: FrameworkInfo | null): CrawlHints {
  if (!framework) {
    return { linkSelectors: ['a[href]'], waitForHydration: false, routeAttributes: [] };
  }

  switch (framework.name) {
    case 'react':
      return {
        linkSelectors: [
          'a[href]',
          'a[data-discover]',      // React Router v6+
          'a[data-testid]',        // common pattern
          '[role="link"]',
        ],
        waitForHydration: true,
        routeAttributes: ['data-discover', 'data-testid'],
      };

    case 'nextjs':
      // Next.js is already well-handled by NextJsExtractor — minimal extra hints
      return {
        linkSelectors: ['a[href]'],
        waitForHydration: true,
        routeAttributes: [],
      };

    case 'vue':
    case 'nuxt':
      return {
        linkSelectors: [
          'a[href]',
          'a.router-link-active',
          'a.router-link-exact-active',
          '[class*="router-link"]',
        ],
        waitForHydration: true,
        routeAttributes: ['to'],  // <router-link :to="...">
      };

    case 'angular':
      return {
        linkSelectors: [
          'a[href]',
          'a[routerLink]',
          'a[routerlink]',         // case-insensitive fallback
          '[ng-reflect-router-link]',
        ],
        waitForHydration: true,
        routeAttributes: ['routerLink', 'routerlink', 'ng-reflect-router-link'],
      };

    case 'svelte':
      return {
        linkSelectors: [
          'a[href]',
          'a[data-sveltekit-preload-data]',
          'a[data-sveltekit-reload]',
        ],
        waitForHydration: true,
        routeAttributes: ['data-sveltekit-preload-data'],
      };

    default:
      return { linkSelectors: ['a[href]'], waitForHydration: false, routeAttributes: [] };
  }
}

// ─── Wait for Hydration (B.1.6) ───────────────────────────────────

const HYDRATION_TIMEOUT = 5000; // 5 seconds max
const IDLE_GRACE = 500;         // extra idle time after condition is met

/**
 * Wait for the SPA to fully hydrate before extracting content.
 * Uses framework-specific checks to detect hydration completion.
 * Always times out after 5 seconds.
 */
export async function waitForHydration(
  page: Page,
  framework: FrameworkInfo | null,
): Promise<void> {
  const startTime = Date.now();

  try {
    if (!framework) {
      // Generic: wait for document.readyState + idle period
      await page.waitForFunction(
        () => document.readyState === 'complete',
        { timeout: HYDRATION_TIMEOUT },
      );
      await page.waitForTimeout(IDLE_GRACE);
      log.debug(`Generic hydration wait: ${Date.now() - startTime}ms`);
      return;
    }

    switch (framework.name) {
      case 'nextjs':
        // Wait for __NEXT_DATA__ and #__next to have children (content rendered)
        await page.waitForFunction(
          () => {
            const w = window as Record<string, unknown>;
            const nextRoot = document.querySelector('#__next');
            return (w.__NEXT_DATA__ || nextRoot) && nextRoot && nextRoot.children.length > 0;
          },
          { timeout: HYDRATION_TIMEOUT },
        );
        break;

      case 'react':
        // Wait for React root to have rendered children
        await page.waitForFunction(
          () => {
            const root =
              document.querySelector('#root') ??
              document.querySelector('#app') ??
              document.querySelector('[data-reactroot]');
            return root && root.children.length > 0;
          },
          { timeout: HYDRATION_TIMEOUT },
        );
        break;

      case 'vue':
      case 'nuxt':
        // Wait for Vue app to be mounted
        await page.waitForFunction(
          () => {
            const w = window as Record<string, unknown>;
            // Vue 3: __vue_app__ on root element
            const appEl = document.querySelector('#app') ?? document.querySelector('#__nuxt');
            if (appEl && (appEl as unknown as Record<string, unknown>).__vue_app__) return true;
            // Fallback: global __VUE__ set
            return !!w.__vue_app__ || !!w.__VUE__;
          },
          { timeout: HYDRATION_TIMEOUT },
        );
        break;

      case 'angular':
        // Wait for ng-version attribute to appear (set after bootstrap)
        await page.waitForFunction(
          () => !!document.querySelector('[ng-version]'),
          { timeout: HYDRATION_TIMEOUT },
        );
        break;

      case 'svelte':
        // Wait for Svelte-rendered elements (class^="svelte-")
        await page.waitForFunction(
          () => {
            return document.querySelector('[class^="svelte-"]') !== null
              || document.querySelector('[data-svelte-h]') !== null;
          },
          { timeout: HYDRATION_TIMEOUT },
        );
        break;

      default:
        // Unknown framework — generic wait
        await page.waitForFunction(
          () => document.readyState === 'complete',
          { timeout: HYDRATION_TIMEOUT },
        );
    }

    // Always add a short idle grace period after framework condition is met
    const elapsed = Date.now() - startTime;
    const remainingForGrace = Math.min(IDLE_GRACE, HYDRATION_TIMEOUT - elapsed);
    if (remainingForGrace > 0) {
      await page.waitForTimeout(remainingForGrace);
    }

    log.debug(`${framework.name} hydration wait: ${Date.now() - startTime}ms`);
  } catch (err) {
    // Timeout is expected — just log and continue
    const elapsed = Date.now() - startTime;
    log.debug(`Hydration wait timed out after ${elapsed}ms: ${(err as Error).message}`);
  }
}

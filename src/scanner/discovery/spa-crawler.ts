import { chromium, type Browser, type Page } from 'playwright';
import { log } from '../../utils/logger.js';
import type { DiscoveredRoute, RouteDiscoverer } from './types.js';

/**
 * JavaScript init script injected into every page context via addInitScript().
 *
 * Monkey-patches:
 * - history.pushState / history.replaceState (B.1.1)
 * - popstate / hashchange events (B.1.1)
 * - XMLHttpRequest.prototype.open (B.1.3)
 * - window.fetch (B.1.3)
 *
 * Collected data is stored on window globals that the crawler reads back.
 */
export const SPA_INIT_SCRIPT = `
(function() {
  // Guard against double-injection
  if (window.__secbot_routes) return;

  window.__secbot_routes = [];
  window.__secbot_api_endpoints = [];

  function addRoute(url) {
    try {
      var resolved = new URL(url, window.location.href).href;
      if (window.__secbot_routes.indexOf(resolved) === -1) {
        window.__secbot_routes.push(resolved);
      }
    } catch(e) { /* ignore malformed URLs */ }
  }

  function addApiEndpoint(url) {
    try {
      var resolved = new URL(url, window.location.href).href;
      if (window.__secbot_api_endpoints.indexOf(resolved) === -1) {
        window.__secbot_api_endpoints.push(resolved);
      }
    } catch(e) { /* ignore malformed URLs */ }
  }

  // --- B.1.1: History API interception ---
  var origPushState = history.pushState;
  history.pushState = function() {
    var result = origPushState.apply(this, arguments);
    var url = arguments[2];
    if (url) addRoute(url);
    return result;
  };

  var origReplaceState = history.replaceState;
  history.replaceState = function() {
    var result = origReplaceState.apply(this, arguments);
    var url = arguments[2];
    if (url) addRoute(url);
    return result;
  };

  window.addEventListener('popstate', function() {
    addRoute(window.location.href);
  });

  window.addEventListener('hashchange', function(e) {
    addRoute(e.newURL || window.location.href);
  });

  // --- B.1.3: XHR interception ---
  var origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    addApiEndpoint(url);
    return origXHROpen.apply(this, arguments);
  };

  // --- B.1.3: fetch interception ---
  var origFetch = window.fetch;
  window.fetch = function(input) {
    if (typeof input === 'string') {
      addApiEndpoint(input);
    } else if (input && input.url) {
      addApiEndpoint(input.url);
    }
    return origFetch.apply(this, arguments);
  };
})();
`;

/** Maximum number of elements to click during click-through navigation */
const MAX_CLICK_ELEMENTS = 50;

/** Timeout for waiting after each click (ms) */
const CLICK_SETTLE_TIMEOUT = 2000;

/** Overall timeout for the entire SPA crawl (ms) */
const SPA_CRAWL_TIMEOUT = 30000;

export class SPACrawler implements RouteDiscoverer {
  name = 'spa-crawler';

  async discover(targetUrl: string): Promise<DiscoveredRoute[]> {
    let browser: Browser | null = null;

    try {
      browser = await chromium.launch({ headless: true });
      const context = await browser.newContext({
        ignoreHTTPSErrors: true,
      });

      const page = await context.newPage();

      // Inject init script before any page JS runs
      await page.addInitScript(SPA_INIT_SCRIPT);

      // Navigate to target
      try {
        await page.goto(targetUrl, {
          waitUntil: 'networkidle',
          timeout: SPA_CRAWL_TIMEOUT,
        });
      } catch (err) {
        log.debug(`SPA crawler: navigation failed for ${targetUrl}: ${(err as Error).message}`);
        return [];
      }

      // Collect initial routes from page load (frameworks may push routes during init)
      const initialRoutes = await this.collectRoutes(page);
      const initialApiEndpoints = await this.collectApiEndpoints(page);

      // B.1.2: Click-through navigation
      await this.performClickNavigation(page, targetUrl);

      // Collect all routes after click-through
      const allRoutes = await this.collectRoutes(page);
      const allApiEndpoints = await this.collectApiEndpoints(page);

      await page.close();
      await context.close();

      // Build discovered routes
      const routes: DiscoveredRoute[] = [];
      const seen = new Set<string>();

      const origin = new URL(targetUrl).origin;

      // Routes from history interception
      for (const url of allRoutes) {
        if (seen.has(url)) continue;
        seen.add(url);

        // Only include same-origin routes
        try {
          if (new URL(url).origin !== origin) continue;
        } catch {
          continue;
        }

        routes.push({
          url,
          source: initialRoutes.includes(url) ? 'spa-history' : 'spa-click',
          confidence: 'medium',
        });
      }

      // API endpoints from XHR/fetch interception
      for (const url of allApiEndpoints) {
        if (seen.has(url)) continue;
        seen.add(url);

        routes.push({
          url,
          source: 'spa-xhr',
          confidence: 'medium',
        });
      }

      if (routes.length > 0) {
        log.info(`SPA crawler: discovered ${routes.length} routes (${allRoutes.length} navigation, ${allApiEndpoints.length} API)`);
      }

      return routes;
    } catch (err) {
      log.debug(`SPA crawler failed: ${(err as Error).message}`);
      return [];
    } finally {
      if (browser) {
        try {
          await browser.close();
        } catch {
          // ignore cleanup errors
        }
      }
    }
  }

  /**
   * B.1.2: Click-through navigation.
   * Finds clickable elements and clicks each one, capturing route changes.
   */
  async performClickNavigation(page: Page, targetUrl: string): Promise<void> {
    const origin = new URL(targetUrl).origin;

    try {
      // Gather all clickable elements
      const clickableSelectors = 'a[href], button, [role="button"], [onclick]';
      const elementCount = await page.locator(clickableSelectors).count();
      const maxElements = Math.min(elementCount, MAX_CLICK_ELEMENTS);

      log.debug(`SPA crawler: found ${elementCount} clickable elements, will try ${maxElements}`);

      for (let i = 0; i < maxElements; i++) {
        try {
          // Re-query each time since DOM may change after clicks
          const elements = page.locator(clickableSelectors);
          const count = await elements.count();
          if (i >= count) break;

          const element = elements.nth(i);

          // Skip elements that would navigate away from the SPA
          const href = await element.getAttribute('href').catch(() => null);
          if (href) {
            try {
              const resolvedUrl = new URL(href, page.url());
              // Skip external links
              if (resolvedUrl.origin !== origin) continue;
              // Skip non-http links (mailto:, tel:, javascript:, etc.)
              if (!resolvedUrl.protocol.startsWith('http')) continue;
            } catch {
              // Skip malformed hrefs
              continue;
            }
          }

          // Skip if element is not visible or not in viewport
          const isVisible = await element.isVisible().catch(() => false);
          if (!isVisible) continue;

          // Store current URL to detect navigation
          const urlBefore = page.url();

          // Click with timeout and catch errors
          await element.click({ timeout: CLICK_SETTLE_TIMEOUT, noWaitAfter: true }).catch(() => {
            // Element may have been removed, overlapped, etc.
          });

          // Brief wait for any route changes to propagate
          await page.waitForTimeout(300);

          // If a full navigation happened (not SPA route change), go back
          try {
            const currentUrl = page.url();
            const currentOrigin = new URL(currentUrl).origin;
            if (currentOrigin !== origin) {
              await page.goBack({ waitUntil: 'networkidle', timeout: 5000 }).catch(() => {});
            }
          } catch {
            // ignore navigation check errors
          }
        } catch {
          // Individual click failed — continue with next element
          continue;
        }
      }

      // Final wait for any pending route changes
      await page.waitForTimeout(500);
    } catch (err) {
      log.debug(`SPA crawler: click navigation error: ${(err as Error).message}`);
    }
  }

  /** Read collected routes from the injected window global */
  async collectRoutes(page: Page): Promise<string[]> {
    try {
      const routes = await page.evaluate(() => {
        return (window as any).__secbot_routes || [];
      });
      return Array.isArray(routes) ? routes : [];
    } catch {
      return [];
    }
  }

  /** Read collected API endpoints from the injected window global */
  async collectApiEndpoints(page: Page): Promise<string[]> {
    try {
      const endpoints = await page.evaluate(() => {
        return (window as any).__secbot_api_endpoints || [];
      });
      return Array.isArray(endpoints) ? endpoints : [];
    } catch {
      return [];
    }
  }
}

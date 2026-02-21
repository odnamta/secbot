import { log } from '../../utils/logger.js';
import type { DiscoveredRoute, RouteDiscoverer } from './types.js';

/** Common web app paths to probe for existence */
const COMMON_PATHS = [
  '/api/health',
  '/api/v1',
  '/login',
  '/signup',
  '/register',
  '/dashboard',
  '/settings',
  '/profile',
  '/admin',
  '/admin/login',
  '/graphql',
  '/api/graphql',
  '/.well-known/security.txt',
];

export class NextJsExtractor implements RouteDiscoverer {
  name = 'nextjs';

  async discover(targetUrl: string): Promise<DiscoveredRoute[]> {
    const routes: DiscoveredRoute[] = [];

    // 1. Try sitemap.xml
    const sitemapRoutes = await this.fetchSitemap(targetUrl);
    routes.push(...sitemapRoutes);

    // 2. Try Next.js build manifests
    const manifestRoutes = await this.fetchManifest(targetUrl);
    routes.push(...manifestRoutes);

    // 3. Probe common paths
    const probeRoutes = await this.probeCommonPaths(targetUrl);
    routes.push(...probeRoutes);

    return routes;
  }

  async fetchSitemap(targetUrl: string): Promise<DiscoveredRoute[]> {
    const routes: DiscoveredRoute[] = [];
    const origin = new URL(targetUrl).origin;
    const sitemapUrl = `${origin}/sitemap.xml`;

    try {
      const response = await fetch(sitemapUrl, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        log.debug(`No sitemap.xml at ${sitemapUrl} (${response.status})`);
        return routes;
      }

      const text = await response.text();

      // Extract <loc> URLs from XML
      const locRegex = /<loc>\s*(.*?)\s*<\/loc>/gi;
      let match: RegExpExecArray | null;
      while ((match = locRegex.exec(text)) !== null) {
        const url = match[1].trim();
        if (url) {
          routes.push({
            url,
            source: 'sitemap',
            confidence: 'high',
          });
        }
      }

      if (routes.length > 0) {
        log.info(`sitemap.xml: found ${routes.length} URLs`);
      }
    } catch (err) {
      log.debug(`Failed to fetch sitemap: ${(err as Error).message}`);
    }

    return routes;
  }

  async fetchManifest(targetUrl: string): Promise<DiscoveredRoute[]> {
    const routes: DiscoveredRoute[] = [];
    const origin = new URL(targetUrl).origin;

    // Try Next.js-specific manifest paths
    const manifestPaths = [
      '/_next/routes-manifest.json',
      '/build-manifest.json',
      '/_next/build-manifest.json',
    ];

    for (const path of manifestPaths) {
      try {
        const response = await fetch(`${origin}${path}`, {
          signal: AbortSignal.timeout(5000),
        });

        if (!response.ok) continue;

        const contentType = response.headers.get('content-type') ?? '';
        if (!contentType.includes('json')) continue;

        const manifest = await response.json();

        // routes-manifest.json has staticRoutes, dynamicRoutes
        if (manifest.staticRoutes && Array.isArray(manifest.staticRoutes)) {
          for (const route of manifest.staticRoutes) {
            const routePage = route.page ?? route.path ?? route;
            if (typeof routePage === 'string') {
              routes.push({
                url: `${origin}${routePage}`,
                source: 'nextjs',
                confidence: 'medium',
              });
            }
          }
        }

        if (manifest.dynamicRoutes && Array.isArray(manifest.dynamicRoutes)) {
          for (const route of manifest.dynamicRoutes) {
            const routePage = route.page ?? route.path ?? route;
            if (typeof routePage === 'string') {
              routes.push({
                url: `${origin}${routePage}`,
                source: 'nextjs',
                confidence: 'medium',
              });
            }
          }
        }

        // build-manifest.json has pages as keys
        if (manifest.pages && typeof manifest.pages === 'object') {
          for (const pagePath of Object.keys(manifest.pages)) {
            if (pagePath.startsWith('/_')) continue; // skip internal pages
            routes.push({
              url: `${origin}${pagePath}`,
              source: 'nextjs',
              confidence: 'medium',
            });
          }
        }

        if (routes.length > 0) {
          log.info(`Next.js manifest (${path}): found ${routes.length} routes`);
          break; // Found a manifest, no need to try others
        }
      } catch (err) {
        log.debug(`Failed to fetch manifest ${path}: ${(err as Error).message}`);
      }
    }

    return routes;
  }

  async probeCommonPaths(targetUrl: string): Promise<DiscoveredRoute[]> {
    const routes: DiscoveredRoute[] = [];
    const origin = new URL(targetUrl).origin;

    const probeResults = await Promise.allSettled(
      COMMON_PATHS.map(async (path) => {
        try {
          const response = await fetch(`${origin}${path}`, {
            method: 'HEAD',
            redirect: 'manual',
            signal: AbortSignal.timeout(3000),
          });

          // Consider 200, 301, 302, 307, 308, 401, 403 as "existing" paths
          // 404 and 5xx are not
          if (response.status < 400 || response.status === 401 || response.status === 403) {
            return {
              url: `${origin}${path}`,
              source: 'probe' as const,
              confidence: 'low' as const,
            };
          }
          return null;
        } catch {
          return null;
        }
      }),
    );

    for (const result of probeResults) {
      if (result.status === 'fulfilled' && result.value) {
        routes.push(result.value);
      }
    }

    if (routes.length > 0) {
      log.debug(`Path probing: found ${routes.length} accessible paths`);
    }

    return routes;
  }
}

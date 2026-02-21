import type { DiscoveredRoute } from './types.js';
import { NextJsExtractor } from './nextjs-extractor.js';
import { UrlFileLoader } from './url-file-loader.js';
import { log } from '../../utils/logger.js';

export async function discoverRoutes(
  targetUrl: string,
  urlsFile?: string,
): Promise<DiscoveredRoute[]> {
  const discoverers = [new NextJsExtractor()];
  if (urlsFile) {
    discoverers.push(new UrlFileLoader(urlsFile));
  }

  const allRoutes: DiscoveredRoute[] = [];
  for (const d of discoverers) {
    try {
      const routes = await d.discover(targetUrl);
      allRoutes.push(...routes);
      if (routes.length > 0) {
        log.info(`${d.name}: discovered ${routes.length} routes`);
      }
    } catch (err) {
      log.debug(`${d.name} discovery failed: ${(err as Error).message}`);
    }
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  return allRoutes.filter((r) => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });
}

export type { DiscoveredRoute, RouteDiscoverer } from './types.js';

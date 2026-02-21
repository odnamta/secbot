import { readFileSync } from 'node:fs';
import { log } from '../../utils/logger.js';
import type { DiscoveredRoute, RouteDiscoverer } from './types.js';

export class UrlFileLoader implements RouteDiscoverer {
  name = 'file';

  constructor(private filePath: string) {}

  async discover(_targetUrl: string): Promise<DiscoveredRoute[]> {
    try {
      const content = readFileSync(this.filePath, 'utf-8');
      const routes = content
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')) // skip empty lines and comments
        .map((url) => ({
          url,
          source: 'file' as const,
          confidence: 'high' as const,
        }));

      if (routes.length > 0) {
        log.info(`URL file: loaded ${routes.length} URLs from ${this.filePath}`);
      }

      return routes;
    } catch (err) {
      log.warn(`Failed to read URL file ${this.filePath}: ${(err as Error).message}`);
      return [];
    }
  }
}

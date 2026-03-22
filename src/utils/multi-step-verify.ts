import type { BrowserContext } from 'playwright';
import { log } from './logger.js';

export interface InjectedMarker {
  marker: string;
  payload: string;
  injectionUrl: string;
  injectionField: string;
  injectionMethod: 'POST' | 'PUT' | 'PATCH';
}

export interface PersistenceHit {
  marker: string;
  foundOnUrl: string;
  injectionUrl: string;
  injectionField: string;
  context: 'html-body' | 'attribute' | 'script' | 'unknown';
}

/**
 * Determine the rendering context of a marker within an HTML document.
 * Looks at the 100 characters preceding the marker to infer whether it
 * appears inside a `<script>` block, an HTML attribute value, or plain
 * body content.
 */
export function detectContext(html: string, marker: string): PersistenceHit['context'] {
  const markerPos = html.indexOf(marker);
  if (markerPos === -1) return 'unknown';

  // Check surrounding context (100 chars before marker)
  const before = html.slice(Math.max(0, markerPos - 100), markerPos);

  if (/<script[^>]*>/.test(before) && !/<\/script>/.test(before)) return 'script';
  if (/\w+\s*=\s*["'][^"']*$/.test(before)) return 'attribute';
  return 'html-body';
}

/**
 * Check if previously injected markers persist on other pages.
 * Used for stored XSS and second-order SQLi detection.
 *
 * Visits each URL in `urlsToCheck` and scans the page content for any of
 * the provided markers. Hits where the marker is found on the same page it
 * was injected are skipped (those are reflected, not stored).
 *
 * @param context - Playwright browser context (carries cookies/auth state)
 * @param markers - Markers that were injected during active scanning
 * @param urlsToCheck - Pages to visit looking for persisted markers
 * @param timeout - Per-page navigation timeout (default 10 000 ms)
 * @returns Array of persistence hits
 */
export async function checkPersistence(
  context: BrowserContext,
  markers: InjectedMarker[],
  urlsToCheck: string[],
  timeout: number = 10000,
): Promise<PersistenceHit[]> {
  const hits: PersistenceHit[] = [];
  if (markers.length === 0 || urlsToCheck.length === 0) return hits;

  // Limit to prevent excessive requests
  const maxUrls = Math.min(urlsToCheck.length, 10);

  for (const url of urlsToCheck.slice(0, maxUrls)) {
    const page = await context.newPage();
    try {
      await page.goto(url, { timeout, waitUntil: 'domcontentloaded' });
      const content = await page.content();

      for (const marker of markers) {
        if (!content.includes(marker.marker)) continue;

        // Skip if the marker is on the same page it was injected
        if (url === marker.injectionUrl) continue;

        const ctx = detectContext(content, marker.marker);

        hits.push({
          marker: marker.marker,
          foundOnUrl: url,
          injectionUrl: marker.injectionUrl,
          injectionField: marker.injectionField,
          context: ctx,
        });

        log.info(
          `Persistence detected: marker "${marker.marker}" from ${marker.injectionUrl} found on ${url} in ${ctx} context`,
        );
      }
    } catch (err) {
      log.debug(`Multi-step check on ${url}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }
  }

  return hits;
}

import { randomUUID } from 'node:crypto';
import type { RawFinding } from '../types.js';
import { log } from '../../utils/logger.js';
import type { ActiveCheck } from './index.js';

/**
 * Subresource Integrity (SRI) check.
 *
 * For each page in scan targets, opens the page in the browser context and
 * inspects all <script src="..."> and <link href="..." rel="stylesheet">
 * elements. External resources (different origin) without an `integrity`
 * attribute are flagged as missing SRI.
 *
 * Same-origin resources are skipped since the server controls them.
 * Findings are grouped per page to avoid excessive noise.
 */
export const sriCheck: ActiveCheck = {
  name: 'sri',
  category: 'sri',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];
    const targetOrigin = new URL(config.targetUrl).origin;

    log.info(`SRI check: scanning ${targets.pages.length} page(s) for missing subresource integrity...`);

    for (const pageUrl of targets.pages) {
      const page = await context.newPage();
      try {
        const response = await page.goto(pageUrl, {
          waitUntil: 'domcontentloaded',
          timeout: config.timeout,
        });

        requestLogger?.log({
          timestamp: new Date().toISOString(),
          method: 'GET',
          url: pageUrl,
          responseStatus: response?.status() ?? 0,
          phase: 'active-sri',
        });

        // Query all external scripts and stylesheets without integrity
        const missingIntegrity = await page.evaluate((origin: string) => {
          const results: { tag: string; url: string }[] = [];

          // Check <script src="..."> elements
          const scripts = document.querySelectorAll('script[src]');
          for (const el of scripts) {
            const src = el.getAttribute('src');
            if (!src) continue;
            try {
              const resolved = new URL(src, window.location.href);
              if (resolved.origin !== origin && !el.hasAttribute('integrity')) {
                results.push({ tag: 'script', url: resolved.href });
              }
            } catch {
              // Skip invalid URLs
            }
          }

          // Check <link rel="stylesheet" href="..."> elements
          const links = document.querySelectorAll('link[rel="stylesheet"][href]');
          for (const el of links) {
            const href = el.getAttribute('href');
            if (!href) continue;
            try {
              const resolved = new URL(href, window.location.href);
              if (resolved.origin !== origin && !el.hasAttribute('integrity')) {
                results.push({ tag: 'link', url: resolved.href });
              }
            } catch {
              // Skip invalid URLs
            }
          }

          return results;
        }, targetOrigin);

        if (missingIntegrity.length > 0) {
          const resourceList = missingIntegrity
            .map((r) => `<${r.tag}> ${r.url}`)
            .join('\n');

          findings.push({
            id: randomUUID(),
            category: 'sri',
            severity: 'medium',
            title: 'Missing Subresource Integrity (SRI)',
            description:
              `Found ${missingIntegrity.length} external resource(s) without integrity attributes on ${pageUrl}. ` +
              'Without SRI, if the CDN or external host is compromised, an attacker can inject malicious code that the browser will execute without verification. ' +
              'Add integrity="sha384-..." and crossorigin="anonymous" attributes to all external script and stylesheet tags.',
            url: pageUrl,
            evidence: `External resources without SRI:\n${resourceList}`,
            timestamp: new Date().toISOString(),
            affectedUrls: missingIntegrity.map((r) => r.url),
          });
        }
      } catch (err) {
        log.debug(`SRI check: failed to scan ${pageUrl}: ${(err as Error).message}`);
      } finally {
        await page.close();
      }
    }

    log.info(`SRI check: ${findings.length} finding(s)`);
    return findings;
  },
};

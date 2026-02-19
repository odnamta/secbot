import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { REDIRECT_PAYLOADS } from '../../config/payloads/redirect.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';

export const redirectCheck: ActiveCheck = {
  name: 'redirect',
  category: 'open-redirect',
  async run(context, targets, config, requestLogger) {
    if (targets.redirectUrls.length === 0) return [];

    log.info(`Testing ${targets.redirectUrls.length} URLs for open redirect...`);
    return testOpenRedirect(context, targets.redirectUrls, config, requestLogger);
  },
};

async function testOpenRedirect(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const originalUrl of urls) {
    const parsedUrl = new URL(originalUrl);
    const redirectParams = Array.from(parsedUrl.searchParams.keys()).filter((k) =>
      /^(url|redirect|next|return|goto|dest|continue|rurl|target)$/i.test(k),
    );

    for (const param of redirectParams) {
      for (const payload of REDIRECT_PAYLOADS.slice(0, 2)) {
        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, payload);

        const page = await context.newPage();
        try {
          await page.goto(testUrl.href, {
            timeout: config.timeout,
            waitUntil: 'domcontentloaded',
          });

          requestLogger?.log({
            timestamp: new Date().toISOString(),
            method: 'GET',
            url: testUrl.href,
            phase: 'active-redirect',
          });

          const finalUrl = page.url();
          if (finalUrl.includes('evil.example.com')) {
            findings.push({
              id: randomUUID(),
              category: 'open-redirect',
              severity: 'medium',
              title: `Open Redirect via "${param}" Parameter`,
              description: `The parameter "${param}" allows redirecting users to arbitrary external domains.`,
              url: originalUrl,
              evidence: `Payload: ${payload}\nRedirected to: ${finalUrl}`,
              request: { method: 'GET', url: testUrl.href },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch {
          // Continue
        } finally {
          await page.close();
        }

        await delay(config.requestDelay);
      }
    }
  }

  return findings;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

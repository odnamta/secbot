import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import type {
  ScanConfig,
  CrawledPage,
  FormInfo,
  InputInfo,
  CookieInfo,
  InterceptedResponse,
} from './types.js';
import { log } from '../utils/logger.js';

export interface CrawlResult {
  pages: CrawledPage[];
  responses: InterceptedResponse[];
  browser: Browser;
  context: BrowserContext;
}

export async function crawl(config: ScanConfig): Promise<CrawlResult> {
  const browser = await chromium.launch({ headless: true });
  const contextOptions: Parameters<Browser['newContext']>[0] = {
    userAgent: 'SecBot/0.0.1 (Security Scanner)',
    ignoreHTTPSErrors: true,
  };

  if (config.authStorageState) {
    contextOptions.storageState = config.authStorageState;
  }

  const context = await browser.newContext(contextOptions);
  const responses: InterceptedResponse[] = [];
  const visited = new Set<string>();
  const toVisit: string[] = [config.targetUrl];
  const pages: CrawledPage[] = [];

  // Check robots.txt if configured
  let disallowedPaths: string[] = [];
  if (config.respectRobots) {
    disallowedPaths = await fetchRobotsTxt(config.targetUrl, context);
  }

  while (toVisit.length > 0 && visited.size < config.maxPages) {
    const url = toVisit.shift()!;
    const normalized = normalizeUrl(url);

    if (visited.has(normalized)) continue;
    if (!isSameOrigin(normalized, config.targetUrl)) continue;
    if (isDisallowed(normalized, disallowedPaths, config.targetUrl)) {
      log.debug(`Skipping (robots.txt): ${normalized}`);
      continue;
    }

    visited.add(normalized);
    log.info(`Crawling [${visited.size}/${config.maxPages}]: ${normalized}`);

    try {
      const pageResult = await crawlPage(context, normalized, config, responses);
      pages.push(pageResult);

      // Add discovered links to queue
      for (const link of pageResult.links) {
        const normalizedLink = normalizeUrl(link);
        if (!visited.has(normalizedLink) && isSameOrigin(normalizedLink, config.targetUrl)) {
          toVisit.push(normalizedLink);
        }
      }

      // Rate limiting
      await delay(config.requestDelay);
    } catch (err) {
      log.warn(`Failed to crawl ${normalized}: ${(err as Error).message}`);
    }
  }

  log.info(`Crawl complete: ${pages.length} pages scanned`);
  return { pages, responses, browser, context };
}

/** Close the browser when scanning is complete */
export async function closeBrowser(browser: Browser): Promise<void> {
  try {
    await browser.close();
  } catch {
    // Browser may already be closed
  }
}

async function crawlPage(
  context: BrowserContext,
  url: string,
  config: ScanConfig,
  responses: InterceptedResponse[],
): Promise<CrawledPage> {
  const page = await context.newPage();

  // Intercept all responses
  page.on('response', async (response) => {
    try {
      const headers: Record<string, string> = {};
      const allHeaders = await response.allHeaders();
      for (const [k, v] of Object.entries(allHeaders)) {
        headers[k.toLowerCase()] = v;
      }

      let body: string | undefined;
      const contentType = headers['content-type'] ?? '';
      if (
        contentType.includes('text/html') ||
        contentType.includes('application/json') ||
        contentType.includes('text/plain')
      ) {
        try {
          body = await response.text();
          if (body.length > 10000) {
            body = body.slice(0, 10000) + '... [truncated]';
          }
        } catch {
          // Some responses can't be read
        }
      }

      responses.push({
        url: response.url(),
        status: response.status(),
        headers,
        body,
      });
    } catch {
      // Ignore response reading errors
    }
  });

  try {
    await page.goto(url, {
      waitUntil: 'networkidle',
      timeout: config.timeout,
    });

    // Use final URL after redirects (e.g., / → /login)
    const finalUrl = page.url();

    // Extract page info
    const title = await page.title();
    const links = await extractLinks(page, finalUrl);
    const forms = await extractForms(page, finalUrl);
    const scripts = await extractScripts(page);
    const cookies = await extractCookies(context, finalUrl);

    // Get response headers for the final page (not the redirect)
    const pageResponse =
      responses.find((r) => normalizeUrl(r.url) === normalizeUrl(finalUrl) && r.status >= 200 && r.status < 300) ??
      responses.find((r) => normalizeUrl(r.url) === normalizeUrl(url));
    const headers = pageResponse?.headers ?? {};

    return {
      url: finalUrl,
      status: pageResponse?.status ?? 200,
      headers,
      title,
      forms,
      links,
      scripts,
      cookies,
    };
  } finally {
    await page.close();
  }
}

async function extractLinks(page: Page, baseUrl: string): Promise<string[]> {
  const hrefs = await page.$$eval('a[href]', (anchors) =>
    anchors.map((a) => a.getAttribute('href')).filter(Boolean) as string[],
  );

  return hrefs
    .map((href) => {
      try {
        return new URL(href, baseUrl).href;
      } catch {
        return null;
      }
    })
    .filter((url): url is string => url !== null);
}

async function extractForms(page: Page, pageUrl: string): Promise<FormInfo[]> {
  return page.$$eval(
    'form',
    (forms, pUrl) =>
      forms.map((form) => {
        const inputs = Array.from(form.querySelectorAll('input, textarea, select')).map(
          (input) => ({
            name: input.getAttribute('name') ?? '',
            type: input.getAttribute('type') ?? 'text',
            value: (input as HTMLInputElement).value ?? '',
          }),
        );

        return {
          action: form.getAttribute('action') ?? pUrl,
          method: (form.getAttribute('method') ?? 'GET').toUpperCase(),
          inputs,
          pageUrl: pUrl,
        };
      }),
    pageUrl,
  );
}

async function extractScripts(page: Page): Promise<string[]> {
  return page.$$eval('script[src]', (scripts) =>
    scripts.map((s) => s.getAttribute('src')).filter(Boolean) as string[],
  );
}

async function extractCookies(context: BrowserContext, url: string): Promise<CookieInfo[]> {
  const cookies = await context.cookies(url);
  return cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: c.sameSite,
  }));
}

async function fetchRobotsTxt(targetUrl: string, context: BrowserContext): Promise<string[]> {
  const page = await context.newPage();
  const disallowed: string[] = [];

  try {
    const origin = new URL(targetUrl).origin;
    const response = await page.goto(`${origin}/robots.txt`, { timeout: 5000 });
    if (response && response.status() === 200) {
      const text = await response.text();
      const lines = text.split('\n');
      let isRelevantAgent = false;

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.toLowerCase().startsWith('user-agent:')) {
          const agent = trimmed.slice(11).trim();
          isRelevantAgent = agent === '*' || agent.toLowerCase().includes('secbot');
        } else if (isRelevantAgent && trimmed.toLowerCase().startsWith('disallow:')) {
          const path = trimmed.slice(9).trim();
          if (path) disallowed.push(path);
        }
      }

      if (disallowed.length > 0) {
        log.info(`robots.txt: ${disallowed.length} disallowed paths found`);
      }
    }
  } catch {
    log.debug('No robots.txt found or failed to fetch');
  } finally {
    await page.close();
  }

  return disallowed;
}

function isDisallowed(url: string, disallowedPaths: string[], targetUrl: string): boolean {
  if (disallowedPaths.length === 0) return false;
  const origin = new URL(targetUrl).origin;
  const path = url.replace(origin, '');
  return disallowedPaths.some((d) => path.startsWith(d));
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    // Remove trailing slash for consistency
    let path = u.pathname;
    if (path.length > 1 && path.endsWith('/')) {
      path = path.slice(0, -1);
    }
    u.pathname = path;
    return u.href;
  } catch {
    return url;
  }
}

function isSameOrigin(url: string, target: string): boolean {
  try {
    return new URL(url).origin === new URL(target).origin;
  } catch {
    return false;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

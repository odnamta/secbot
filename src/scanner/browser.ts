import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import { readFileSync, existsSync } from 'node:fs';
import type {
  ScanConfig,
  CrawledPage,
  FormInfo,
  InputInfo,
  CookieInfo,
  InterceptedResponse,
} from './types.js';
import { log } from '../utils/logger.js';
import { normalizeUrl, delay } from '../utils/shared.js';
import { getRandomUserAgent, jitteredDelay } from '../utils/stealth.js';
import {
  MiddlewarePipeline,
  createCustomHeaderMiddleware,
  createResponseLoggerMiddleware,
  createWafBlockDetector,
} from './middleware.js';
import { detectFramework, waitForHydration, getFrameworkHints } from './discovery/framework-detector.js';

export interface CrawlResult {
  pages: CrawledPage[];
  responses: InterceptedResponse[];
  browser: Browser;
  context: BrowserContext;
  middleware: MiddlewarePipeline;
}

/** Realistic Chrome UA to avoid WAF blocks. SecBot identifier only sent in non-stealth mode. */
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

/** Module-level reference for SIGINT cleanup */
let activeBrowser: Browser | null = null;

export async function crawl(
  config: ScanConfig,
  additionalUrls: string[] = [],
  middleware?: MiddlewarePipeline,
): Promise<CrawlResult> {
  const isStealth = config.profile === 'stealth';
  const launchOptions: Parameters<typeof chromium.launch>[0] = { headless: true };
  if (config.proxy) {
    launchOptions.proxy = { server: config.proxy };
    log.info(`Using proxy: ${config.proxy}`);
  }
  const browser = await chromium.launch(launchOptions);
  activeBrowser = browser;

  const mwPipeline = middleware ?? new MiddlewarePipeline();

  // ─── Populate middleware pipeline (only when we created a fresh one) ───
  if (!middleware) {
    // Always add WAF block detector — useful for all scans
    const { middleware: wafMiddleware } = createWafBlockDetector();
    mwPipeline.addResponseMiddleware(wafMiddleware);

    // Add response logger when request logging is enabled
    if (config.logRequests) {
      mwPipeline.addResponseMiddleware(createResponseLoggerMiddleware());
    }

    // If auth storage state contains a CSRF token cookie, add it as a custom header
    if (config.authStorageState && existsSync(config.authStorageState)) {
      try {
        const storageState = JSON.parse(readFileSync(config.authStorageState, 'utf-8'));
        const csrfCookie = (storageState.cookies ?? []).find(
          (c: { name: string }) =>
            /^(csrf|xsrf|_csrf|_token)/i.test(c.name),
        );
        if (csrfCookie) {
          mwPipeline.addRequestMiddleware(
            createCustomHeaderMiddleware({ 'X-CSRF-Token': csrfCookie.value }),
          );
          log.debug(`Middleware: added CSRF header from cookie "${csrfCookie.name}"`);
        }
      } catch {
        // Storage state already validated below — ignore parse errors here
      }
    }

    log.debug(`Middleware pipeline: ${mwPipeline.requestCount} request, ${mwPipeline.responseCount} response`);
  }

  const contextOptions: Parameters<Browser['newContext']>[0] = {
    userAgent: isStealth
      ? getRandomUserAgent()
      : (config.userAgent ?? DEFAULT_USER_AGENT),
    ignoreHTTPSErrors: true,
    ...(config.extraHeaders ? { extraHTTPHeaders: config.extraHeaders } : {}),
  };

  if (config.authStorageState) {
    if (!existsSync(config.authStorageState)) {
      throw new Error(`Auth storage state file not found: ${config.authStorageState}`);
    }
    try {
      JSON.parse(readFileSync(config.authStorageState, 'utf-8'));
      contextOptions.storageState = config.authStorageState;
    } catch {
      throw new Error(`Auth storage state file is not valid JSON: ${config.authStorageState}`);
    }
  }

  const context = await browser.newContext(contextOptions);
  const responses: InterceptedResponse[] = [];
  const visited = new Set<string>();
  const toVisit: string[] = [config.targetUrl, ...additionalUrls];
  const pages: CrawledPage[] = [];

  // Check robots.txt if configured
  let disallowedPaths: string[] = [];
  if (config.respectRobots) {
    disallowedPaths = await fetchRobotsTxt(config.targetUrl, context);
  }

  const concurrency = Math.min(config.concurrency, 5); // Cap at 5 to be safe

  while (toVisit.length > 0 && visited.size < config.maxPages) {
    // Collect a batch of URLs to crawl concurrently
    const batch: string[] = [];
    while (batch.length < concurrency && toVisit.length > 0 && (visited.size + batch.length) < config.maxPages) {
      const url = toVisit.shift()!;
      const normalized = normalizeUrl(url);

      if (visited.has(normalized)) continue;
      if (!isSameOrigin(normalized, config.targetUrl)) continue;
      if (isDisallowed(normalized, disallowedPaths, config.targetUrl)) {
        log.debug(`Skipping (robots.txt): ${normalized}`);
        continue;
      }

      visited.add(normalized);
      batch.push(normalized);
    }

    if (batch.length === 0) break;

    // Crawl batch concurrently
    const results = await Promise.allSettled(
      batch.map(async (normalized) => {
        log.info(`Crawling [${visited.size}/${config.maxPages}]: ${normalized}`);
        return crawlPage(context, normalized, config, responses, mwPipeline);
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const pageResult = result.value;
        pages.push(pageResult);

        // If the page redirected, mark the final URL as visited too.
        // This prevents re-crawling the same page (which would hit the
        // browser cache and lose security headers).
        const normalizedFinal = normalizeUrl(pageResult.url);
        if (!visited.has(normalizedFinal)) {
          visited.add(normalizedFinal);
        }

        // Add discovered links to queue
        for (const link of pageResult.links) {
          const normalizedLink = normalizeUrl(link);
          if (!visited.has(normalizedLink) && isSameOrigin(normalizedLink, config.targetUrl)) {
            toVisit.push(normalizedLink);
          }
        }
      } else {
        log.warn(`Failed to crawl: ${result.reason?.message ?? 'unknown error'}`);
      }
    }

    // Rate limiting between batches — stealth mode uses randomized jitter
    if (isStealth) {
      await jitteredDelay(config.requestDelay);
    } else {
      await delay(config.requestDelay);
    }
  }

  log.info(`Crawl complete: ${pages.length} pages scanned`);
  return { pages, responses, browser, context, middleware: mwPipeline };
}

/** Close all pages, contexts, and the browser when scanning is complete */
export async function closeBrowser(browser?: Browser): Promise<void> {
  const target = browser ?? activeBrowser;
  if (!target) return;
  try {
    for (const ctx of target.contexts()) {
      for (const page of ctx.pages()) {
        try { await page.close(); } catch (err) { log.debug(`Page close: ${(err as Error).message}`); }
      }
      try { await ctx.close(); } catch (err) { log.debug(`Context close: ${(err as Error).message}`); }
    }
    await target.close();
  } catch (err) {
    log.debug(`Browser cleanup warning: ${(err as Error).message}`);
  }
  activeBrowser = null;
}

async function crawlPage(
  context: BrowserContext,
  url: string,
  config: ScanConfig,
  responses: InterceptedResponse[],
  mwPipeline: MiddlewarePipeline,
): Promise<CrawledPage> {
  const page = await context.newPage();

  // Stealth: rotate User-Agent per page to reduce fingerprinting
  if (config.profile === 'stealth') {
    await page.setExtraHTTPHeaders({ 'User-Agent': getRandomUserAgent() });
  }

  // Wire request middleware via page.route() — intercept all HTTP(S) traffic
  if (mwPipeline.requestCount > 0) {
    await page.route('**/*', async (route) => {
      const request = route.request();
      const original = {
        url: request.url(),
        method: request.method(),
        headers: { ...request.headers() },
        body: request.postData() ?? undefined,
      };
      const processed = mwPipeline.processRequest(original);
      await route.continue({
        url: processed.url,
        method: processed.method,
        headers: processed.headers,
        postData: processed.body,
      });
    });
  }

  // Track pending response captures so we can await them before reading
  const pendingResponses: Promise<void>[] = [];

  // Intercept all responses
  page.on('response', (response) => {
    const capture = (async () => {
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
          } catch (err) {
            log.debug(`Response body read: ${(err as Error).message}`);
          }
        }

        const intercepted = {
          url: response.url(),
          status: response.status(),
          headers,
          body,
        };

        // Run response middleware (observation only)
        mwPipeline.processResponse(intercepted);

        responses.push(intercepted);
      } catch (err) {
        log.debug(`Response capture: ${(err as Error).message}`);
      }
    })();
    pendingResponses.push(capture);
  });

  try {
    // Try networkidle first (waits for all requests to finish).
    // If it times out (common on marketing-heavy sites with persistent trackers),
    // fall back to domcontentloaded which only waits for HTML parsing.
    let gotoResponse;
    try {
      gotoResponse = await page.goto(url, {
        waitUntil: 'networkidle',
        timeout: config.timeout,
      });
    } catch (err) {
      const msg = (err as Error).message ?? '';
      if (msg.includes('Timeout') || msg.includes('timeout')) {
        log.info(`networkidle timeout for ${url}, retrying with domcontentloaded`);
        gotoResponse = await page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: config.timeout,
        });
      } else {
        throw err;
      }
    }

    // Capture document headers IMMEDIATELY from the goto response,
    // BEFORE awaiting the response handlers. The handlers call response.text()
    // which can interfere with reading headers from the same HTTP response.
    let headers: Record<string, string> = {};
    let status = 200;
    if (gotoResponse) {
      const allHeaders = await gotoResponse.allHeaders();
      for (const [k, v] of Object.entries(allHeaders)) {
        headers[k.toLowerCase()] = v;
      }
      status = gotoResponse.status();
    }

    // Use final URL after redirects (e.g., / → /login)
    const finalUrl = page.url();

    // When Chromium follows a redirect, the goto response can return
    // incomplete headers (only CDN-level headers, missing security headers).
    // Detect this by checking for content-type — a real HTML response always
    // has it. When missing, make a fresh HTTP request via Playwright's API
    // request context which bypasses the browser cache entirely.
    if (!headers['content-type'] && status >= 200 && status < 400) {
      log.debug(`Incomplete headers for ${finalUrl}, fetching fresh`);
      try {
        const freshResp = await page.request.head(finalUrl);
        const freshHeaders = freshResp.headers();
        if (Object.keys(freshHeaders).length > Object.keys(headers).length) {
          headers = {};
          for (const [k, v] of Object.entries(freshHeaders)) {
            headers[k.toLowerCase()] = v;
          }
          status = freshResp.status();
        }
      } catch {
        log.debug(`Failed to fetch fresh headers for ${finalUrl}`);
      }
    }

    // Now wait for response handlers to finish (populates shared responses[])
    await Promise.allSettled(pendingResponses);

    // Detect SPA framework and wait for hydration before extracting content.
    // This ensures client-rendered links are visible in the DOM.
    const framework = await detectFramework(page);
    if (framework) {
      await waitForHydration(page, framework);
    }
    const hints = getFrameworkHints(framework);

    // Extract page info
    const title = await page.title();
    const links = await extractLinks(page, finalUrl, hints.linkSelectors);
    const forms = await extractForms(page, finalUrl);
    const scripts = await extractScripts(page);
    const cookies = await extractCookies(context, finalUrl);

    // Extract API-like URLs from inline scripts (SPAs embed API endpoints in JS)
    const jsApiUrls = await extractJsApiUrls(page, finalUrl);
    if (jsApiUrls.length > 0) {
      links.push(...jsApiUrls);
      log.debug(`Extracted ${jsApiUrls.length} API-like URLs from inline scripts`);
    }

    // Extract API endpoints from external JS bundles (SPAs hide endpoints in compiled JS)
    const externalJsUrls = await extractExternalJsEndpoints(page, finalUrl);
    if (externalJsUrls.length > 0) {
      // Deduplicate against already-found links
      const existingSet = new Set(links);
      const newUrls = externalJsUrls.filter(u => !existingSet.has(u));
      links.push(...newUrls);
      log.info(`JS bundle analysis: ${externalJsUrls.length} API endpoints found (${newUrls.length} new)`);
    }

    return {
      url: finalUrl,
      status,
      headers,
      title,
      forms,
      links,
      scripts,
      cookies,
      framework: framework ?? undefined,
    };
  } finally {
    await page.close();
  }
}

async function extractLinks(page: Page, baseUrl: string, linkSelectors: string[] = ['a[href]']): Promise<string[]> {
  // Deduplicate selectors while preserving order
  const uniqueSelectors = [...new Set(linkSelectors)];
  const combinedSelector = uniqueSelectors.join(', ');

  const hrefs = await page.$$eval(combinedSelector, (elements) => {
    const urls: string[] = [];
    for (const el of elements) {
      // Primary: href attribute (works for <a>, <area>, <link>)
      const href = el.getAttribute('href');
      if (href) {
        urls.push(href);
        continue;
      }
      // Fallback for framework-specific elements: check common route attributes
      for (const attr of ['to', 'routerLink', 'routerlink', 'ng-reflect-router-link', 'data-href']) {
        const val = el.getAttribute(attr);
        if (val) {
          urls.push(val);
          break;
        }
      }
    }
    return urls;
  });

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

        // Resolve action URL relative to page URL (form.getAttribute returns raw value
        // which may be relative, causing "Invalid URL" in fetch())
        const rawAction = form.getAttribute('action') ?? pUrl;
        let resolvedAction: string;
        try {
          resolvedAction = new URL(rawAction, pUrl).href;
        } catch {
          resolvedAction = pUrl;
        }

        return {
          action: resolvedAction,
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

/** Regex patterns for finding API endpoints in JavaScript source code */
const JS_API_PATTERNS = [
  // Relative API paths: "/api/users", "/rest/v2/data", "/graphql"
  /["'`](\/(?:api|graphql|v[0-9]+|rest|rpc|_api|__api)\/[^"'`\s}{]{2,120})["'`]/g,
  // Absolute API URLs
  /["'`](https?:\/\/[^"'`\s]{10,200}\/(?:api|graphql|v[0-9]+|rest|rpc)\/[^"'`\s}{]{2,120})["'`]/g,
  // fetch() calls: fetch("/path") or fetch("https://...")
  /fetch\s*\(\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
  // axios calls: axios.get("/path"), axios.post("/path"), axios("/path")
  /axios(?:\.[a-z]+)?\s*\(\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
  // XMLHttpRequest.open: xhr.open("GET", "/path")
  /\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
  // URL construction: new URL("/api/...", base) or baseURL + "/api/..."
  /(?:baseURL|baseUrl|BASE_URL|apiUrl|API_URL|apiBase)\s*[+:=]\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
  // Route definitions: path: "/api/users", url: "/rest/data"
  /(?:path|url|endpoint|route|href)\s*:\s*["'`](\/(?:api|rest|v[0-9]+|graphql)[^"'`\s}{]{1,120})["'`]/g,
];

/** Extract API-like URLs from inline <script> content and data attributes */
async function extractJsApiUrls(page: Page, baseUrl: string): Promise<string[]> {
  try {
    const rawUrls = await page.evaluate(() => {
      const urls: string[] = [];
      // Scan inline scripts for URL-like patterns
      const scripts = document.querySelectorAll('script:not([src])');
      const urlRegex = /["'`](\/(?:api|graphql|v[0-9]+|rest|rpc|_api|__api)\/[^"'`\s}{]{2,120})["'`]/g;
      const fullUrlRegex = /["'`](https?:\/\/[^"'`\s]{10,200}\/(?:api|graphql|v[0-9]+|rest|rpc)\/[^"'`\s}{]{2,120})["'`]/g;
      const fetchRegex = /fetch\s*\(\s*["'`](\/[^"'`\s]{2,200})["'`]/g;
      const axiosRegex = /axios(?:\.[a-z]+)?\s*\(\s*["'`](\/[^"'`\s]{2,200})["'`]/g;
      const xhrRegex = /\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`](\/[^"'`\s]{2,200})["'`]/g;
      for (const script of scripts) {
        const text = script.textContent ?? '';
        if (text.length > 500000) continue; // Skip very large inline scripts
        for (const re of [urlRegex, fullUrlRegex, fetchRegex, axiosRegex, xhrRegex]) {
          re.lastIndex = 0;
          let match;
          while ((match = re.exec(text)) !== null) {
            urls.push(match[1]);
          }
        }
      }
      // Also check data attributes that commonly contain API URLs
      const dataEls = document.querySelectorAll('[data-api-url], [data-endpoint], [data-url]');
      for (const el of dataEls) {
        for (const attr of ['data-api-url', 'data-endpoint', 'data-url']) {
          const val = el.getAttribute(attr);
          if (val) urls.push(val);
        }
      }
      return urls;
    });
    // Resolve relative URLs and deduplicate
    const resolved = new Set<string>();
    for (const raw of rawUrls) {
      try {
        resolved.add(new URL(raw, baseUrl).href);
      } catch { /* skip invalid */ }
    }
    return [...resolved];
  } catch {
    return [];
  }
}

/** Max JS files to scan for endpoint extraction (avoid slowdown) */
const MAX_JS_FILES_TO_SCAN = 20;
/** Max size per JS file to scan (bytes) */
const MAX_JS_FILE_SIZE = 1_000_000;

/**
 * Extract API endpoints from external JavaScript files loaded by the page.
 * Uses page.evaluate + fetch to read JS bundles from the browser cache,
 * then scans content for API URL patterns, fetch/axios/XHR calls.
 */
async function extractExternalJsEndpoints(page: Page, baseUrl: string): Promise<string[]> {
  try {
    const origin = new URL(baseUrl).origin;

    const rawUrls = await page.evaluate(async ({ origin: pageOrigin, maxFiles, maxSize }) => {
      const urls: string[] = [];
      // Get all external script sources
      const scriptEls = document.querySelectorAll('script[src]');
      const srcUrls: string[] = [];
      for (const el of scriptEls) {
        const src = el.getAttribute('src');
        if (!src) continue;
        try {
          const resolved = new URL(src, pageOrigin).href;
          // Only scan same-origin and common CDN JS files
          if (resolved.startsWith(pageOrigin) || resolved.includes('.js')) {
            srcUrls.push(resolved);
          }
        } catch { /* skip invalid */ }
      }

      // Limit to maxFiles most relevant files
      const toScan = srcUrls.slice(0, maxFiles);

      // Define patterns to scan for (in-browser regex)
      const patterns = [
        /["'`](\/(?:api|graphql|v[0-9]+|rest|rpc|_api|__api)\/[^"'`\s}{]{2,120})["'`]/g,
        /["'`](https?:\/\/[^"'`\s]{10,200}\/(?:api|graphql|v[0-9]+|rest|rpc)\/[^"'`\s}{]{2,120})["'`]/g,
        /fetch\s*\(\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
        /axios(?:\.[a-z]+)?\s*\(\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
        /\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
        /(?:baseURL|baseUrl|BASE_URL|apiUrl|API_URL|apiBase)\s*[+:=]\s*["'`](\/[^"'`\s]{2,200})["'`]/g,
        /(?:path|url|endpoint|route|href)\s*:\s*["'`](\/(?:api|rest|v[0-9]+|graphql)[^"'`\s}{]{1,120})["'`]/g,
      ];

      // Fetch and scan each JS file
      for (const jsUrl of toScan) {
        try {
          const resp = await fetch(jsUrl, { cache: 'force-cache' });
          if (!resp.ok) continue;
          const contentLength = parseInt(resp.headers.get('content-length') ?? '0', 10);
          if (contentLength > maxSize) continue;

          const text = await resp.text();
          if (text.length > maxSize) continue;

          for (const re of patterns) {
            re.lastIndex = 0;
            let match;
            while ((match = re.exec(text)) !== null) {
              urls.push(match[1]);
            }
          }
        } catch { /* skip failed fetches */ }
      }

      return urls;
    }, { origin, maxFiles: MAX_JS_FILES_TO_SCAN, maxSize: MAX_JS_FILE_SIZE });

    // Resolve relative URLs, deduplicate, filter out static assets
    const resolved = new Set<string>();
    const staticRe = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp)(\?|$)/i;
    for (const raw of rawUrls) {
      try {
        const full = new URL(raw, baseUrl).href;
        if (!staticRe.test(full)) {
          resolved.add(full);
        }
      } catch { /* skip invalid */ }
    }
    return [...resolved];
  } catch {
    return [];
  }
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

function isSameOrigin(url: string, target: string): boolean {
  try {
    return new URL(url).origin === new URL(target).origin;
  } catch {
    return false;
  }
}

import { randomUUID } from 'node:crypto';
import type { BrowserContext, Page } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/** Timeout for WebSocket operations (ms) */
const WS_TIMEOUT = 5000;

/** XSS payload for message injection test */
const XSS_PAYLOAD = '<img src=x onerror=alert(1)>';

/** Patterns to find WebSocket URLs in script source */
const WS_URL_PATTERNS = [
  /new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
  /(?:ws|wss):\/\/[^\s'"`<>)\]},;]+/g,
  /socket\.io[^'"`]*['"`]([^'"`]+)['"`]/g,
  /\.connect\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
];

/** Patterns that indicate WebSocket usage in scripts */
const WS_INDICATOR_PATTERNS = [
  /new\s+WebSocket\b/,
  /\bws:\/\//,
  /\bwss:\/\//,
  /\bsocket\.io\b/i,
  /\.connect\s*\(/,
];

/**
 * Extract WebSocket URLs from script content using regex patterns.
 * Exported for testing.
 */
export function extractWsUrlsFromScript(scriptContent: string, pageOrigin: string): string[] {
  const urls = new Set<string>();

  for (const pattern of WS_URL_PATTERNS) {
    // Reset lastIndex since we reuse regex objects
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(scriptContent)) !== null) {
      // Use captured group if present, otherwise use full match
      const raw = match[1] || match[0];
      const normalized = normalizeWsUrl(raw, pageOrigin);
      if (normalized) {
        urls.add(normalized);
      }
    }
  }

  return [...urls];
}

/**
 * Normalize a WebSocket URL: resolve relative URLs to absolute,
 * ensure ws:// or wss:// scheme.
 * Exported for testing.
 */
export function normalizeWsUrl(raw: string, pageOrigin: string): string | null {
  try {
    let url = raw.trim();

    // Skip empty or template literal strings
    if (!url || url.includes('${') || url.includes('`')) return null;

    // If it starts with ws:// or wss://, it's already absolute
    if (/^wss?:\/\//.test(url)) {
      // Validate it's a real URL
      new URL(url.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:'));
      return url;
    }

    // If it starts with / it's relative to the page origin
    if (url.startsWith('/')) {
      const origin = new URL(pageOrigin);
      const scheme = origin.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${scheme}//${origin.host}${url}`;
    }

    // If it looks like a hostname (no scheme), prepend wss://
    if (/^[\w.-]+:\d+/.test(url) || /^[\w.-]+\//.test(url)) {
      return `wss://${url}`;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Discover WebSocket URLs from crawled pages by inspecting script content.
 */
export async function discoverWebSocketUrls(
  pages: string[],
  context: BrowserContext,
): Promise<string[]> {
  const allUrls = new Set<string>();

  for (const pageUrl of pages.slice(0, 10)) {
    const page = await context.newPage();
    try {
      await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });

      const origin = new URL(pageUrl).origin;

      // Extract WebSocket URLs from inline and external scripts
      const scriptContents = await page.evaluate(() => {
        const scripts = document.querySelectorAll('script');
        const contents: string[] = [];
        for (const script of scripts) {
          if (script.textContent) {
            contents.push(script.textContent);
          }
          if (script.src) {
            contents.push(script.src);
          }
        }
        return contents;
      });

      for (const content of scriptContents) {
        const urls = extractWsUrlsFromScript(content, origin);
        for (const url of urls) {
          allUrls.add(url);
        }
      }

      // Check for socket.io polling endpoints
      const currentUrl = page.url();
      if (currentUrl.includes('/socket.io') || currentUrl.includes('EIO=')) {
        const wsUrl = normalizeWsUrl('/socket.io/', origin);
        if (wsUrl) allUrls.add(wsUrl);
      }
    } catch (err) {
      log.debug(`WebSocket discovery on ${pageUrl}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }
  }

  return [...allUrls];
}

/**
 * Test WebSocket endpoint for auth bypass — connect without cookies/tokens.
 */
async function testAuthBypass(
  context: BrowserContext,
  wsUrl: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  // Create a fresh context without any auth state
  const browser = context.browser();
  if (!browser) return null;

  const freshContext = await browser.newContext();
  const page = await freshContext.newPage();

  try {
    const result = await page.evaluate(
      async ({ url, timeout }) => {
        return new Promise<{ connected: boolean; receivedData: boolean; error?: string }>(
          (resolve) => {
            const ws = new WebSocket(url);
            let receivedData = false;

            const timer = setTimeout(() => {
              ws.close();
              resolve({ connected: false, receivedData: false, error: 'timeout' });
            }, timeout);

            ws.onopen = () => {
              // Connection succeeded without auth
              // Wait briefly for any data
              setTimeout(() => {
                clearTimeout(timer);
                ws.close();
                resolve({ connected: true, receivedData });
              }, 1000);
            };

            ws.onmessage = () => {
              receivedData = true;
            };

            ws.onerror = () => {
              clearTimeout(timer);
              resolve({ connected: false, receivedData: false, error: 'connection refused' });
            };

            ws.onclose = (event) => {
              clearTimeout(timer);
              // Close code 1000 = normal, 1001 = going away — might indicate auth failure
              // Close code 1008 = policy violation — likely auth rejection
              if (event.code === 1008 || event.code === 4001 || event.code === 4003) {
                resolve({ connected: false, receivedData: false, error: `rejected (${event.code})` });
              }
            };
          },
        );
      },
      { url: wsUrl, timeout: WS_TIMEOUT },
    );

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'WS',
      url: wsUrl,
      responseStatus: result.connected ? 101 : 0,
      phase: 'active-websocket-auth-bypass',
    });

    if (result.connected && result.receivedData) {
      return {
        id: randomUUID(),
        category: 'websocket',
        severity: 'high',
        title: 'WebSocket Endpoint Missing Authentication',
        description: `The WebSocket endpoint at ${wsUrl} accepted a connection without any authentication cookies or tokens, and sent data to the unauthenticated client. An attacker can connect and receive potentially sensitive real-time data without logging in.`,
        url: wsUrl,
        evidence: `Connected to ${wsUrl} without auth — received data from server. No cookies or tokens were sent.`,
        request: { method: 'WS', url: wsUrl },
        response: { status: 101, bodySnippet: 'WebSocket connected + data received' },
        timestamp: new Date().toISOString(),
      };
    }
  } catch (err) {
    log.debug(`WebSocket auth bypass test: ${(err as Error).message}`);
  } finally {
    await page.close();
    await freshContext.close();
  }

  return null;
}

/**
 * Test WebSocket endpoint for origin validation — connect with evil origin.
 */
async function testOriginValidation(
  context: BrowserContext,
  wsUrl: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  // Use page.evaluate with a modified approach — create a page on evil origin isn't possible,
  // so we use page.evaluate to test via JavaScript WebSocket API
  const page = await context.newPage();

  try {
    // Navigate to about:blank first, then try connecting
    // The browser will send the current page's origin as the Origin header
    await page.goto('about:blank');

    const result = await page.evaluate(
      async ({ url, timeout }) => {
        return new Promise<{ connected: boolean; error?: string }>((resolve) => {
          try {
            const ws = new WebSocket(url);

            const timer = setTimeout(() => {
              ws.close();
              resolve({ connected: false, error: 'timeout' });
            }, timeout);

            ws.onopen = () => {
              clearTimeout(timer);
              ws.close();
              // Connected from about:blank origin (null origin) — missing origin validation
              resolve({ connected: true });
            };

            ws.onerror = () => {
              clearTimeout(timer);
              resolve({ connected: false, error: 'connection refused' });
            };

            ws.onclose = (event) => {
              clearTimeout(timer);
              if (!event.wasClean || event.code === 1008 || event.code === 403) {
                resolve({ connected: false, error: `rejected (${event.code})` });
              }
            };
          } catch (e) {
            resolve({ connected: false, error: String(e) });
          }
        });
      },
      { url: wsUrl, timeout: WS_TIMEOUT },
    );

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'WS',
      url: wsUrl,
      responseStatus: result.connected ? 101 : 0,
      phase: 'active-websocket-origin-validation',
    });

    if (result.connected) {
      return {
        id: randomUUID(),
        category: 'websocket',
        severity: 'medium',
        title: 'WebSocket Missing Origin Validation',
        description: `The WebSocket endpoint at ${wsUrl} accepted a connection from a null/foreign origin (about:blank). Without origin validation, any website can open a WebSocket connection to this endpoint via a victim's browser, enabling cross-site WebSocket hijacking (CSWSH).`,
        url: wsUrl,
        evidence: `Connected to ${wsUrl} from about:blank (null origin) — server did not reject the cross-origin connection.`,
        request: { method: 'WS', url: wsUrl, headers: { Origin: 'null' } },
        response: { status: 101, bodySnippet: 'WebSocket accepted from null origin' },
        timestamp: new Date().toISOString(),
      };
    }
  } catch (err) {
    log.debug(`WebSocket origin validation test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return null;
}

/**
 * Test WebSocket for message injection — send XSS payload and check if echoed unsanitized.
 */
async function testMessageInjection(
  context: BrowserContext,
  wsUrl: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const page = await context.newPage();

  try {
    const result = await page.evaluate(
      async ({ url, payload, timeout }) => {
        return new Promise<{ connected: boolean; echoed: boolean; response?: string; error?: string }>(
          (resolve) => {
            try {
              const ws = new WebSocket(url);
              let echoed = false;
              let responseText = '';

              const timer = setTimeout(() => {
                ws.close();
                resolve({ connected: ws.readyState === WebSocket.OPEN, echoed, response: responseText });
              }, timeout);

              ws.onopen = () => {
                ws.send(payload);
              };

              ws.onmessage = (event) => {
                responseText = String(event.data);
                // Check if the server echoed back the payload without sanitization
                if (responseText.includes(payload)) {
                  echoed = true;
                  clearTimeout(timer);
                  ws.close();
                  resolve({ connected: true, echoed: true, response: responseText });
                }
              };

              ws.onerror = () => {
                clearTimeout(timer);
                resolve({ connected: false, echoed: false, error: 'connection refused' });
              };

              ws.onclose = () => {
                clearTimeout(timer);
                resolve({ connected: ws.readyState !== WebSocket.CONNECTING, echoed, response: responseText });
              };
            } catch (e) {
              resolve({ connected: false, echoed: false, error: String(e) });
            }
          },
        );
      },
      { url: wsUrl, payload: XSS_PAYLOAD, timeout: WS_TIMEOUT },
    );

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'WS',
      url: wsUrl,
      responseStatus: result.connected ? 101 : 0,
      phase: 'active-websocket-injection',
    });

    if (result.echoed) {
      return {
        id: randomUUID(),
        category: 'websocket',
        severity: 'medium',
        title: 'WebSocket Message Echoed Without Sanitization',
        description: `The WebSocket endpoint at ${wsUrl} echoed an XSS payload back without sanitization. If the client renders WebSocket messages as HTML, this enables cross-site scripting via WebSocket messages.`,
        url: wsUrl,
        evidence: `Sent: ${XSS_PAYLOAD}\nReceived: ${(result.response || '').slice(0, 200)}\nPayload was echoed back unsanitized.`,
        request: { method: 'WS', url: wsUrl, body: XSS_PAYLOAD },
        response: { status: 101, bodySnippet: (result.response || '').slice(0, 200) },
        timestamp: new Date().toISOString(),
      };
    }
  } catch (err) {
    log.debug(`WebSocket injection test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return null;
}

/**
 * Extract WebSocket URLs from crawled page URLs (e.g. socket.io polling endpoints).
 * These appear in the crawled URL list directly.
 */
export function extractWsUrlsFromCrawledPages(pages: string[]): string[] {
  const urls = new Set<string>();
  for (const pageUrl of pages) {
    try {
      const parsed = new URL(pageUrl);
      // socket.io polling endpoints indicate a WebSocket endpoint at the same path
      if (parsed.pathname.includes('/socket.io') || parsed.searchParams.has('EIO')) {
        const scheme = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
        // Build the WebSocket URL from the socket.io polling endpoint
        urls.add(`${scheme}//${parsed.host}/socket.io/`);
      }
    } catch {
      // skip invalid URLs
    }
  }
  return [...urls];
}

/**
 * WebSocket security check.
 *
 * Tests WebSocket endpoints for:
 * 1. Missing authentication (auth bypass)
 * 2. Missing origin validation (CSWSH)
 * 3. Message injection (unsanitized echo)
 *
 * OWASP: A01:2021 - Broken Access Control, A03:2021 - Injection
 */
export const websocketCheck: ActiveCheck = {
  name: 'websocket',
  category: 'websocket',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Discover WebSocket endpoints from crawled pages (script inspection)
    const scriptUrls = await discoverWebSocketUrls(targets.pages, context);
    // Also extract from crawled URL list (socket.io polling endpoints)
    const crawledUrls = extractWsUrlsFromCrawledPages(targets.pages);
    const wsUrls = [...new Set([...scriptUrls, ...crawledUrls])];

    if (wsUrls.length === 0) {
      log.info('WebSocket check: no endpoints found');
      return findings;
    }

    log.info(`Testing ${wsUrls.length} WebSocket endpoint(s)...`);

    for (const wsUrl of wsUrls) {
      // Test 1: Auth bypass
      const authFinding = await testAuthBypass(context, wsUrl, config, requestLogger);
      if (authFinding) findings.push(authFinding);

      await delay(config.requestDelay);

      // Test 2: Origin validation
      const originFinding = await testOriginValidation(context, wsUrl, config, requestLogger);
      if (originFinding) findings.push(originFinding);

      await delay(config.requestDelay);

      // Test 3: Message injection
      const injectionFinding = await testMessageInjection(context, wsUrl, config, requestLogger);
      if (injectionFinding) findings.push(injectionFinding);

      await delay(config.requestDelay);
    }

    log.info(`WebSocket check: ${findings.length} finding(s)`);
    return findings;
  },
};

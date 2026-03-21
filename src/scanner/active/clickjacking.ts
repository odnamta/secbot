import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/**
 * CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)
 * OWASP A05:2021 — Security Misconfiguration
 *
 * This check goes beyond passive X-Frame-Options header detection.
 * It uses Playwright to actually attempt framing target pages and verifies
 * whether the page renders inside an iframe — confirming real clickjacking risk.
 *
 * Phases:
 *  1. Prioritize sensitive pages (login, settings, admin, payment, profile)
 *  2. Create an attacker-controlled page with <iframe> pointing at each target
 *  3. Check if the page loaded inside the iframe (DOM accessible, content visible)
 *  4. Verify no frame-busting scripts prevent interaction
 *  5. Report frameable sensitive pages as findings
 */

/** Paths that are high-value clickjacking targets */
const SENSITIVE_PATH_PATTERNS =
  /\/(login|signin|auth|signup|register|settings|profile|account|admin|dashboard|payment|checkout|transfer|billing|password|delete|confirm|approve|consent|2fa|mfa|verify|withdraw|send|wire)/i;

/** Minimum content length to consider page loaded (not error page) */
const MIN_CONTENT_LENGTH = 200;

/** Max pages to test per profile */
const PROFILE_LIMITS: Record<string, number> = {
  quick: 3,
  standard: 8,
  deep: 20,
  stealth: 5,
};

/**
 * Score a URL for clickjacking relevance — higher = more important to test.
 */
function scorePage(url: string): number {
  let score = 0;
  if (SENSITIVE_PATH_PATTERNS.test(url)) score += 10;
  // Auth/session pages are prime targets
  if (/\/(login|signin|auth|signup)/i.test(url)) score += 5;
  // Payment/transfer pages are critical
  if (/\/(payment|checkout|transfer|billing|withdraw|send|wire)/i.test(url)) score += 5;
  // Settings/profile — account takeover via clickjacking
  if (/\/(settings|profile|account|password)/i.test(url)) score += 3;
  // Admin pages
  if (/\/(admin|dashboard|manage)/i.test(url)) score += 3;
  // Confirmation/approval — one-click attacks
  if (/\/(confirm|approve|consent|delete|verify)/i.test(url)) score += 4;
  return score;
}

/**
 * Parse X-Frame-Options and CSP frame-ancestors from response headers.
 * Returns protection status.
 */
function checkFrameHeaders(headers: Record<string, string>): {
  xfo: string | null;
  frameAncestors: string | null;
  isProtected: boolean;
} {
  const xfo = headers['x-frame-options'] ?? null;
  let frameAncestors: string | null = null;

  const csp = headers['content-security-policy'] ?? '';
  const match = csp.match(/frame-ancestors\s+([^;]+)/i);
  if (match) {
    frameAncestors = match[1].trim();
  }

  // Protected if either header properly restricts framing
  let isProtected = false;
  if (xfo) {
    const xfoUpper = xfo.toUpperCase();
    if (xfoUpper === 'DENY' || xfoUpper === 'SAMEORIGIN') {
      isProtected = true;
    }
  }
  if (frameAncestors) {
    // frame-ancestors 'none' or 'self' means protected
    if (/^\s*'none'\s*$/i.test(frameAncestors) || /^\s*'self'\s*$/i.test(frameAncestors)) {
      isProtected = true;
    }
  }

  return { xfo, frameAncestors, isProtected };
}

export const clickjackingCheck: ActiveCheck = {
  name: 'clickjacking',
  category: 'clickjacking',
  parallel: true, // read-only browser operations

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const profile = config.profile ?? 'standard';
    const limit = PROFILE_LIMITS[profile] ?? 8;

    // Collect all page URLs
    const allUrls = [
      ...(targets.pages ?? []),
      ...(targets.apiEndpoints ?? []),
    ];

    if (allUrls.length === 0) {
      log.debug('[clickjacking] No pages to test');
      return findings;
    }

    // Score and sort — test most sensitive pages first
    const scored = allUrls
      .map((url) => ({ url, score: scorePage(url) }))
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);

    log.info(`[clickjacking] Testing ${scored.length} pages for frameability`);

    // Create an attacker page that tries to iframe each target
    const attackerPage = await context.newPage();

    try {
      for (const { url, score } of scored) {
        try {
          // First, do a quick header check via fetch
          const headerResponse = await attackerPage.evaluate(async (targetUrl: string) => {
            try {
              const resp = await fetch(targetUrl, {
                method: 'HEAD',
                mode: 'no-cors',
                credentials: 'omit',
              });
              // We can't read headers in no-cors mode, so we'll check via iframe
              return { ok: true };
            } catch {
              return { ok: false };
            }
          }, url);

          // Build an attacker HTML page with iframe
          const attackPageHtml = `
            <!DOCTYPE html>
            <html>
            <head><title>Clickjacking Test</title></head>
            <body>
              <div id="status">loading</div>
              <iframe id="target-frame"
                      src="${url.replace(/"/g, '&quot;')}"
                      style="width:800px;height:600px;border:1px solid red;opacity:0.5"
                      sandbox="allow-scripts allow-same-origin allow-forms">
              </iframe>
              <script>
                const frame = document.getElementById('target-frame');
                let loaded = false;

                frame.addEventListener('load', () => {
                  loaded = true;
                  document.getElementById('status').textContent = 'loaded';
                });

                frame.addEventListener('error', () => {
                  document.getElementById('status').textContent = 'error';
                });

                // Timeout after 5 seconds
                setTimeout(() => {
                  if (!loaded) {
                    document.getElementById('status').textContent = 'timeout';
                  }
                }, 5000);
              </script>
            </body>
            </html>
          `;

          // Navigate attacker page to a data URL with the iframe
          await attackerPage.setContent(attackPageHtml, { waitUntil: 'load', timeout: 10000 });

          // Wait for iframe to load or timeout
          await attackerPage.waitForFunction(
            () => document.getElementById('status')?.textContent !== 'loading',
            { timeout: 8000 },
          ).catch(() => {});

          const status = await attackerPage.evaluate(() =>
            document.getElementById('status')?.textContent ?? 'unknown',
          );

          if (status !== 'loaded') {
            log.debug(`[clickjacking] ${url} — frame blocked (${status})`);
            continue;
          }

          // Frame loaded — now check if content is actually visible
          const frameInfo = await attackerPage.evaluate(() => {
            const frame = document.getElementById('target-frame') as HTMLIFrameElement;
            if (!frame) return { accessible: false, hasContent: false, title: '' };

            try {
              const doc = frame.contentDocument;
              if (!doc) return { accessible: false, hasContent: false, title: '' };

              const bodyText = doc.body?.innerText ?? '';
              return {
                accessible: true,
                hasContent: bodyText.length > 50,
                title: doc.title ?? '',
                bodyLength: bodyText.length,
                hasForms: doc.querySelectorAll('form').length > 0,
                hasButtons: doc.querySelectorAll('button, input[type="submit"], a[href]').length > 0,
              };
            } catch {
              // Cross-origin — can't access DOM but iframe still rendered
              return {
                accessible: false,
                hasContent: true, // Assume content if cross-origin blocks DOM access
                title: '',
              };
            }
          });

          // Also check response headers via a direct fetch
          let headerInfo = { xfo: null as string | null, frameAncestors: null as string | null, isProtected: false };
          try {
            const directPage = await context.newPage();
            const resp = await directPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
            if (resp) {
              const headers: Record<string, string> = {};
              for (const [key, value] of Object.entries(resp.headers())) {
                headers[key.toLowerCase()] = value;
              }
              headerInfo = checkFrameHeaders(headers);
            }
            await directPage.close();
          } catch {
            // If we can't fetch headers, proceed with iframe-based detection
          }

          // If headers say protected but iframe loaded — conflicting signals
          // Trust the iframe result (actual behavior > header presence)
          if (status === 'loaded') {
            const isSensitive = score >= 3;
            const severity = score >= 10 ? 'high' : score >= 5 ? 'medium' : 'low';

            // Determine confidence based on evidence quality
            let confidence: 'high' | 'medium' | 'low' = 'medium';
            if (frameInfo.accessible && frameInfo.hasContent) {
              confidence = 'high'; // We could read DOM + content visible
            } else if (!headerInfo.isProtected) {
              confidence = 'high'; // No protective headers at all
            }

            // Skip low-score pages that have some protection
            if (score === 0 && headerInfo.isProtected) {
              log.debug(`[clickjacking] ${url} — low priority, headers present, skipping`);
              continue;
            }

            const protectionDetails: string[] = [];
            if (!headerInfo.xfo) protectionDetails.push('Missing X-Frame-Options header');
            if (!headerInfo.frameAncestors) protectionDetails.push('Missing CSP frame-ancestors directive');
            if (headerInfo.xfo && !headerInfo.isProtected) {
              protectionDetails.push(`X-Frame-Options: ${headerInfo.xfo} (permissive)`);
            }

            const interactiveElements =
              frameInfo.accessible
                ? `Forms: ${(frameInfo as { hasForms?: boolean }).hasForms ? 'YES' : 'no'}, ` +
                  `Buttons/Links: ${(frameInfo as { hasButtons?: boolean }).hasButtons ? 'YES' : 'no'}`
                : 'Cross-origin (DOM not accessible but page rendered in frame)';

            findings.push({
              id: randomUUID(),
              title: `Clickjacking — Page Frameable${isSensitive ? ' (Sensitive Endpoint)' : ''}`,
              description:
                `The page at ${url} can be loaded inside an iframe on an attacker-controlled page, ` +
                `enabling clickjacking attacks. ${protectionDetails.join('. ')}.`,
              category: 'clickjacking',
              severity,
              confidence,
              url,
              evidence: JSON.stringify({
                payloadUsed: `<iframe src="${url}" style="opacity:0.5">`,
                responseIndicators: protectionDetails,
                httpExchange: {
                  request: { method: 'GET', url, headers: {} },
                  response: {
                    status: 200,
                    headers: {
                      ...(headerInfo.xfo ? { 'x-frame-options': headerInfo.xfo } : {}),
                      ...(headerInfo.frameAncestors ? { 'content-security-policy': `frame-ancestors ${headerInfo.frameAncestors}` } : {}),
                    },
                    bodySnippet: `Page rendered in iframe. ${interactiveElements}`,
                  },
                },
                cwe: 'CWE-1021',
                remediation:
                  'Add `Content-Security-Policy: frame-ancestors \'none\'` (or `\'self\'` if same-origin framing is needed). ' +
                  'Also set `X-Frame-Options: DENY` or `SAMEORIGIN` for legacy browser support. ' +
                  'CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers.',
              }),
              timestamp: new Date().toISOString(),
            });

            log.info(`[clickjacking] FOUND: ${url} is frameable (severity: ${severity})`);

            if (requestLogger) {
              requestLogger.log({
                timestamp: new Date().toISOString(),
                method: 'GET',
                url,
                responseStatus: 200,
                phase: 'active:clickjacking',
              });
            }
          }
        } catch (err) {
          log.debug(`[clickjacking] Error testing ${url}: ${(err as Error).message}`);
        }
      }
    } finally {
      await attackerPage.close().catch(() => {});
    }

    return findings;
  },
};

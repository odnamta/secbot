import { chromium, type BrowserContext, type Page } from 'playwright';
import { randomUUID } from 'node:crypto';
import type { CrawledPage, FormInfo, RawFinding, ScanConfig } from './types.js';
import {
  XSS_PAYLOADS,
  XSS_MARKERS,
  SQLI_PAYLOADS,
  SQL_ERROR_PATTERNS,
  REDIRECT_PAYLOADS,
  TRAVERSAL_PAYLOADS,
  TRAVERSAL_SUCCESS_PATTERNS,
} from '../config/payloads.js';
import { log } from '../utils/logger.js';

export async function runActiveChecks(
  pages: CrawledPage[],
  config: ScanConfig,
): Promise<RawFinding[]> {
  if (config.profile === 'quick') {
    log.info('Quick profile — skipping active checks');
    return [];
  }

  const findings: RawFinding[] = [];
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: 'SecBot/0.0.1 (Security Scanner)',
    ignoreHTTPSErrors: true,
    ...(config.authStorageState ? { storageState: config.authStorageState } : {}),
  });

  try {
    // XSS on forms
    const allForms = pages.flatMap((p) => p.forms);
    if (allForms.length > 0) {
      log.info(`Testing ${allForms.length} forms for XSS...`);
      findings.push(...(await testXssOnForms(context, allForms, config)));
    }

    // XSS on URL parameters
    const urlsWithParams = pages
      .map((p) => p.url)
      .filter((u) => u.includes('?'));
    if (urlsWithParams.length > 0) {
      log.info(`Testing ${urlsWithParams.length} URLs for reflected XSS...`);
      findings.push(...(await testXssOnUrls(context, urlsWithParams, config)));
    }

    // SQLi on forms
    if (allForms.length > 0) {
      log.info(`Testing ${allForms.length} forms for SQL injection...`);
      findings.push(...(await testSqliOnForms(context, allForms, config)));
    }

    // CORS misconfiguration
    log.info('Testing CORS configuration...');
    const origins = [...new Set(pages.map((p) => new URL(p.url).origin))];
    findings.push(...(await testCorsMisconfiguration(context, origins, pages)));

    // Open redirect
    const redirectUrls = pages
      .flatMap((p) => p.links)
      .filter((l) => /[?&](url|redirect|next|return|goto|dest)=/i.test(l));
    if (redirectUrls.length > 0) {
      log.info(`Testing ${redirectUrls.length} URLs for open redirect...`);
      findings.push(...(await testOpenRedirect(context, redirectUrls, config)));
    }

    // Directory traversal on API-like endpoints
    if (config.profile === 'deep') {
      const apiEndpoints = pages
        .map((p) => p.url)
        .filter((u) => /\/api\//i.test(u));
      if (apiEndpoints.length > 0) {
        log.info(`Testing ${apiEndpoints.length} API endpoints for directory traversal...`);
        findings.push(...(await testDirectoryTraversal(context, apiEndpoints, config)));
      }
    }
  } finally {
    await browser.close();
  }

  log.info(`Active scan: ${findings.length} raw findings`);
  return findings;
}

async function testXssOnForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  // Use a subset of payloads for standard profile
  const payloads = config.profile === 'deep' ? XSS_PAYLOADS : XSS_PAYLOADS.slice(0, 5);

  for (const form of forms) {
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const payload of payloads) {
      const page = await context.newPage();
      try {
        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        // Fill inputs with payload
        for (const input of textInputs) {
          try {
            await page.fill(`[name="${input.name}"]`, payload);
          } catch {
            // Input may not be fillable
          }
        }

        // Submit form
        let responseBody = '';
        page.on('response', async (response) => {
          try {
            const ct = response.headers()['content-type'] ?? '';
            if (ct.includes('text/html')) {
              responseBody = await response.text();
            }
          } catch {
            // Ignore
          }
        });

        try {
          const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
          if (await submitBtn.count() > 0) {
            await submitBtn.click({ timeout: 5000 });
          } else {
            await page.locator('form').first().evaluate((f) => (f as HTMLFormElement).submit());
          }
          await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        } catch {
          // Form submission may fail
        }

        // Check if payload is reflected unescaped
        const content = responseBody || (await page.content());
        const markerIndex = XSS_PAYLOADS.indexOf(payload);
        const marker = markerIndex >= 0 ? XSS_MARKERS[markerIndex] : null;

        const isReflected =
          content.includes(payload) ||
          (marker && content.includes(marker));

        if (isReflected) {
          findings.push({
            id: randomUUID(),
            category: 'xss',
            severity: 'high',
            title: `Reflected XSS in Form Input "${textInputs[0].name}"`,
            description: `The form input "${textInputs[0].name}" reflects XSS payload without proper encoding.`,
            url: form.pageUrl,
            evidence: `Payload: ${payload}\nReflected in response body`,
            request: {
              method: form.method,
              url: form.action,
              body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
            },
            timestamp: new Date().toISOString(),
          });
          break; // One finding per form
        }
      } catch {
        // Continue to next payload
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

async function testXssOnUrls(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = config.profile === 'deep' ? XSS_PAYLOADS : XSS_PAYLOADS.slice(0, 3);

  for (const originalUrl of urls) {
    const parsedUrl = new URL(originalUrl);
    const params = Array.from(parsedUrl.searchParams.keys());

    for (const param of params) {
      for (const payload of payloads) {
        const testUrl = new URL(originalUrl);
        testUrl.searchParams.set(param, payload);

        const page = await context.newPage();
        try {
          await page.goto(testUrl.href, { timeout: config.timeout, waitUntil: 'domcontentloaded' });
          const content = await page.content();

          if (content.includes(payload)) {
            findings.push({
              id: randomUUID(),
              category: 'xss',
              severity: 'high',
              title: `Reflected XSS in URL Parameter "${param}"`,
              description: `The URL parameter "${param}" reflects XSS payload without proper encoding.`,
              url: originalUrl,
              evidence: `Payload: ${payload}\nTest URL: ${testUrl.href}`,
              request: { method: 'GET', url: testUrl.href },
              timestamp: new Date().toISOString(),
            });
            break; // One finding per param
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

async function testSqliOnForms(
  context: BrowserContext,
  forms: FormInfo[],
  config: ScanConfig,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const payloads = config.profile === 'deep' ? SQLI_PAYLOADS : SQLI_PAYLOADS.slice(0, 4);

  for (const form of forms) {
    const textInputs = form.inputs.filter(
      (i) => ['text', 'search', 'email', 'url', 'tel', 'number', ''].includes(i.type) && i.name,
    );
    if (textInputs.length === 0) continue;

    for (const payload of payloads) {
      const page = await context.newPage();
      let responseBody = '';

      page.on('response', async (response) => {
        try {
          const ct = response.headers()['content-type'] ?? '';
          if (ct.includes('text/html') || ct.includes('application/json')) {
            responseBody = await response.text();
          }
        } catch {
          // Ignore
        }
      });

      try {
        await page.goto(form.pageUrl, { timeout: config.timeout, waitUntil: 'domcontentloaded' });

        for (const input of textInputs) {
          try {
            await page.fill(`[name="${input.name}"]`, payload);
          } catch {
            // Continue
          }
        }

        try {
          const submitBtn = page.locator('form button[type="submit"], form input[type="submit"]').first();
          if (await submitBtn.count() > 0) {
            await submitBtn.click({ timeout: 5000 });
          } else {
            await page.locator('form').first().evaluate((f) => (f as HTMLFormElement).submit());
          }
          await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        } catch {
          // Form submission may fail
        }

        const content = responseBody || (await page.content());

        for (const pattern of SQL_ERROR_PATTERNS) {
          const match = content.match(pattern);
          if (match) {
            findings.push({
              id: randomUUID(),
              category: 'sqli',
              severity: 'critical',
              title: `SQL Injection in Form Input "${textInputs[0].name}"`,
              description: `SQL error message detected when injecting payload into "${textInputs[0].name}". This indicates the input is not properly parameterized.`,
              url: form.pageUrl,
              evidence: `Payload: ${payload}\nSQL error: ${match[0]}`,
              request: {
                method: form.method,
                url: form.action,
                body: textInputs.map((i) => `${i.name}=${payload}`).join('&'),
              },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        }
      } catch {
        // Continue
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);

      // If we found a SQLi finding for this form, skip remaining payloads
      if (findings.some((f) => f.category === 'sqli' && f.url === form.pageUrl)) {
        break;
      }
    }
  }

  return findings;
}

async function testCorsMisconfiguration(
  context: BrowserContext,
  origins: string[],
  pages: CrawledPage[],
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const evilOrigin = 'https://evil.example.com';

  for (const origin of origins) {
    // Test a few representative URLs from this origin
    const testUrls = pages
      .filter((p) => p.url.startsWith(origin))
      .slice(0, 3)
      .map((p) => p.url);

    for (const url of testUrls) {
      const page = await context.newPage();
      try {
        const response = await page.request.fetch(url, {
          headers: { Origin: evilOrigin },
        });

        const acao = response.headers()['access-control-allow-origin'];
        const acac = response.headers()['access-control-allow-credentials'];

        if (acao === '*' && acac === 'true') {
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity: 'high',
            title: 'CORS Wildcard with Credentials',
            description:
              'The server allows any origin with credentials, enabling cross-site data theft.',
            url,
            evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
            response: {
              status: response.status(),
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
          });
        } else if (acao === evilOrigin) {
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity: 'high',
            title: 'CORS Reflects Arbitrary Origin',
            description:
              'The server reflects the Origin header in Access-Control-Allow-Origin, allowing any site to read responses.',
            url,
            evidence: `Origin: ${evilOrigin}\nAccess-Control-Allow-Origin: ${acao}`,
            response: {
              status: response.status(),
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
          });
        } else if (acao === 'null') {
          findings.push({
            id: randomUUID(),
            category: 'cors-misconfiguration',
            severity: 'medium',
            title: 'CORS Allows Null Origin',
            description:
              'The server allows the "null" origin, which can be exploited via sandboxed iframes.',
            url,
            evidence: `Access-Control-Allow-Origin: null`,
            response: {
              status: response.status(),
              headers: response.headers(),
            },
            timestamp: new Date().toISOString(),
          });
        }
      } catch {
        // Continue
      } finally {
        await page.close();
      }
    }
  }

  return findings;
}

async function testOpenRedirect(
  context: BrowserContext,
  urls: string[],
  config: ScanConfig,
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
          const response = await page.goto(testUrl.href, {
            timeout: config.timeout,
            waitUntil: 'domcontentloaded',
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

async function testDirectoryTraversal(
  context: BrowserContext,
  apiEndpoints: string[],
  config: ScanConfig,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const endpoint of apiEndpoints) {
    for (const payload of TRAVERSAL_PAYLOADS.slice(0, 2)) {
      // Append traversal payload to the path
      const testUrl = endpoint.replace(/\/[^/]*$/, `/${payload}`);

      const page = await context.newPage();
      try {
        const response = await page.request.fetch(testUrl);
        const body = await response.text();

        for (const pattern of TRAVERSAL_SUCCESS_PATTERNS) {
          if (pattern.test(body)) {
            findings.push({
              id: randomUUID(),
              category: 'directory-traversal',
              severity: 'critical',
              title: 'Directory Traversal on API Endpoint',
              description: `The API endpoint is vulnerable to directory traversal, allowing access to system files.`,
              url: endpoint,
              evidence: `Payload: ${payload}\nResponse contains system file content`,
              request: { method: 'GET', url: testUrl },
              response: { status: response.status(), bodySnippet: body.slice(0, 200) },
              timestamp: new Date().toISOString(),
            });
            break;
          }
        }
      } catch {
        // Continue
      } finally {
        await page.close();
      }

      await delay(config.requestDelay);
    }
  }

  return findings;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

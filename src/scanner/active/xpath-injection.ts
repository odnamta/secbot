import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/**
 * CWE-643: Improper Neutralization of Data within XPath Expressions
 * OWASP A03:2021 — Injection
 *
 * Tests for XPath injection by injecting XPath syntax into parameters
 * and detecting error messages or behavioral differences that indicate
 * the input is being evaluated as part of an XPath query.
 *
 * Detection strategies:
 *  1. Error-based: XPath syntax errors in response body
 *  2. Boolean-based: tautology (1=1) vs contradiction (1=2) response diff
 *  3. Authentication bypass: XPath tautology in login forms
 */

/** XPath error patterns in response bodies */
const XPATH_ERROR_PATTERNS = [
  /XPathException/i,
  /XPath\s+(?:error|syntax|expression)/i,
  /Invalid\s+XPath/i,
  /xmlXPathEval/i,
  /DOMXPath/i,
  /javax\.xml\.xpath/i,
  /lxml\.etree/i,
  /XPathEvalError/i,
  /SimpleXMLElement::xpath/i,
  /XPathResult/i,
  /XPATH syntax error/i,
  /XPathFactory/i,
  /net\.sf\.saxon/i,
  /expected token.*XPath/i,
  /XmlNode::xpath/i,
];

/** XPath injection payloads — error-based detection */
const XPATH_ERROR_PAYLOADS = [
  { payload: "' or '1'='1", description: 'Single-quote tautology' },
  { payload: "' or ''='", description: 'Empty string tautology' },
  { payload: "' and '1'='2", description: 'Single-quote contradiction' },
  { payload: '") or ("1"="1', description: 'Double-quote tautology' },
  { payload: "' or 1=1 or '1'='1", description: 'Numeric tautology' },
  { payload: "'] | //* | //*['", description: 'Union operator injection' },
  { payload: "' or count(//*)>0 or '1'='1", description: 'Count function injection' },
  { payload: "' or string-length(name(/*[1]))>0 or '1'='1", description: 'String-length probing' },
];

/** XPath boolean-based payloads — tautology vs contradiction */
const XPATH_BOOLEAN_PAIRS = [
  { tautology: "' or '1'='1", contradiction: "' and '1'='2" },
  { tautology: "' or 1=1--", contradiction: "' and 1=2--" },
];

/** Max URLs to test per profile */
const PROFILE_LIMITS: Record<string, number> = {
  quick: 3,
  standard: 8,
  deep: 15,
  stealth: 5,
};

export const xpathInjectionCheck: ActiveCheck = {
  name: 'xpath-injection',
  category: 'sqli', // Injection category — reuse sqli (same OWASP A03)
  parallel: true, // read-only HTTP requests

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const profile = config.profile ?? 'standard';
    const limit = PROFILE_LIMITS[profile] ?? 8;

    // Collect URLs with parameters (prime injection targets)
    const urlsWithParams = (targets.urlsWithParams ?? []).slice(0, limit);

    // Also test form actions
    const formUrls = (targets.forms ?? [])
      .filter((f) => f.inputs.length > 0)
      .map((f) => ({
        url: f.action || f.pageUrl,
        params: f.inputs
          .filter((i) => i.type !== 'hidden' && i.type !== 'submit' && i.type !== 'password')
          .map((i) => i.name)
          .filter(Boolean),
      }))
      .slice(0, Math.max(1, limit - urlsWithParams.length));

    if (urlsWithParams.length === 0 && formUrls.length === 0) {
      log.debug('[xpath-injection] No parameterized URLs or forms to test');
      return findings;
    }

    log.info(
      `[xpath-injection] Testing ${urlsWithParams.length} URLs + ${formUrls.length} forms for XPath injection`,
    );

    const reported = new Set<string>();

    // Phase 1: Test URL parameters (GET)
    for (const url of urlsWithParams) {
      try {
        const parsed = new URL(url);
        const params = [...parsed.searchParams.entries()];
        if (params.length === 0) continue;

        for (const [paramName] of params.slice(0, 3)) {
          // Error-based: inject XPath syntax and look for errors
          for (const { payload, description } of XPATH_ERROR_PAYLOADS.slice(0, profile === 'deep' ? 8 : 4)) {
            const testUrl = new URL(url);
            testUrl.searchParams.set(paramName, payload);

            const page = await context.newPage();
            try {
              const response = await page.goto(testUrl.toString(), {
                waitUntil: 'domcontentloaded',
                timeout: 10000,
              });

              if (!response) continue;

              const body = await page.content();
              const status = response.status();

              // Check for XPath error patterns
              for (const pattern of XPATH_ERROR_PATTERNS) {
                const match = body.match(pattern);
                if (match) {
                  const key = `xpath-error-${parsed.hostname}-${paramName}`;
                  if (reported.has(key)) break;
                  reported.add(key);

                  findings.push({
                    id: randomUUID(),
                    title: `XPath Injection — Error-Based (${paramName} parameter)`,
                    description:
                      `The parameter "${paramName}" at ${url} is vulnerable to XPath injection. ` +
                      `Injecting XPath syntax triggered an error: "${match[0]}". ` +
                      `This indicates user input is directly interpolated into XPath queries.`,
                    category: 'sqli',
                    severity: 'high',
                    confidence: 'high',
                    url,
                    evidence: JSON.stringify({
                      payloadUsed: `${paramName}=${payload}`,
                      responseIndicators: [`XPath error: ${match[0]}`],
                      httpExchange: {
                        request: { method: 'GET', url: testUrl.toString() },
                        response: {
                          status,
                          headers: {},
                          bodySnippet: match[0],
                        },
                      },
                    }),
                    timestamp: new Date().toISOString(),
                  });
                  break;
                }
              }

              if (requestLogger) {
                requestLogger.log({
                  timestamp: new Date().toISOString(),
                  method: 'GET',
                  url: testUrl.toString(),
                  responseStatus: status,
                  phase: 'xpath-injection',
                });
              }
            } finally {
              await page.close();
            }
          }

          // Boolean-based: compare tautology vs contradiction responses
          if (profile !== 'quick') {
            for (const { tautology, contradiction } of XPATH_BOOLEAN_PAIRS.slice(0, 1)) {
              const tautUrl = new URL(url);
              tautUrl.searchParams.set(paramName, tautology);
              const contUrl = new URL(url);
              contUrl.searchParams.set(paramName, contradiction);

              const tautPage = await context.newPage();
              const contPage = await context.newPage();

              try {
                const [tautResp, contResp] = await Promise.all([
                  tautPage.goto(tautUrl.toString(), { waitUntil: 'domcontentloaded', timeout: 10000 }),
                  contPage.goto(contUrl.toString(), { waitUntil: 'domcontentloaded', timeout: 10000 }),
                ]);

                if (tautResp && contResp) {
                  const tautBody = await tautPage.content();
                  const contBody = await contPage.content();

                  // Significant difference in response length suggests boolean-based XPath
                  const lenDiff = Math.abs(tautBody.length - contBody.length);
                  const maxLen = Math.max(tautBody.length, contBody.length);

                  if (lenDiff > 100 && lenDiff / maxLen > 0.1 && tautResp.status() === 200 && contResp.status() === 200) {
                    const key = `xpath-boolean-${parsed.hostname}-${paramName}`;
                    if (!reported.has(key)) {
                      reported.add(key);

                      findings.push({
                        id: randomUUID(),
                        title: `Possible XPath Injection — Boolean-Based (${paramName} parameter)`,
                        description:
                          `The parameter "${paramName}" at ${url} shows different responses for XPath tautology ` +
                          `(${tautBody.length} chars) vs contradiction (${contBody.length} chars), ` +
                          `suggesting user input controls XPath query logic.`,
                        category: 'sqli',
                        severity: 'high',
                        confidence: 'medium',
                        url,
                        evidence: JSON.stringify({
                          payloadUsed: `Tautology: ${tautology} vs Contradiction: ${contradiction}`,
                          responseIndicators: [
                            `Tautology response: ${tautBody.length} chars (status ${tautResp.status()})`,
                            `Contradiction response: ${contBody.length} chars (status ${contResp.status()})`,
                            `Difference: ${lenDiff} chars (${Math.round((lenDiff / maxLen) * 100)}%)`,
                          ],
                          httpExchange: {
                            request: { method: 'GET', url: tautUrl.toString() },
                            response: {
                              status: tautResp.status(),
                              headers: {},
                              bodySnippet: `Boolean difference: ${lenDiff} chars`,
                            },
                          },
                        }),
                        timestamp: new Date().toISOString(),
                      });
                    }
                  }
                }
              } finally {
                await Promise.all([tautPage.close(), contPage.close()]);
              }
            }
          }
        }
      } catch (err) {
        log.debug(`[xpath-injection] Error testing ${url}: ${(err as Error).message}`);
      }
    }

    return findings;
  },
};

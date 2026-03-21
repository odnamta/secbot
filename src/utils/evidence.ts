import type { RawFinding, EvidencePack } from '../scanner/types.js';

/**
 * Generate a curl command from a RawFinding's request data.
 * Produces a copy-paste ready command for reproduction.
 */
export function generateCurlCommand(finding: RawFinding): string | undefined {
  const req = finding.request ?? finding.evidencePack?.httpExchange?.request;
  if (!req) return undefined;

  const parts: string[] = ['curl'];

  // Method
  if (req.method && req.method !== 'GET') {
    parts.push(`-X ${req.method}`);
  }

  // Headers
  if (req.headers) {
    for (const [key, value] of Object.entries(req.headers)) {
      // Skip pseudo-headers and internal ones
      if (key.startsWith(':') || key.toLowerCase() === 'host') continue;
      parts.push(`-H '${key}: ${escapeShell(value)}'`);
    }
  }

  // Body
  if (req.body) {
    // Detect if it's JSON
    const isJson = req.body.trimStart().startsWith('{') || req.body.trimStart().startsWith('[');
    if (isJson) {
      parts.push(`-H 'Content-Type: application/json'`);
    }
    parts.push(`-d '${escapeShell(req.body)}'`);
  }

  // Follow redirects
  parts.push('-L');

  // Show response headers
  parts.push('-i');

  // URL (always last)
  parts.push(`'${escapeShell(req.url)}'`);

  return parts.join(' \\\n  ');
}

/**
 * Enrich a RawFinding with a structured EvidencePack.
 * Generates curl commands and structures existing evidence data.
 * Even findings without request data get enriched with response data and detection method.
 */
export function enrichFindingEvidence(finding: RawFinding): RawFinding {

  const existingPack = finding.evidencePack ?? {};

  // Build httpExchange from request/response if not already present
  let httpExchange = existingPack.httpExchange;
  if (!httpExchange) {
    if (finding.request) {
      httpExchange = {
        request: {
          method: finding.request.method,
          url: finding.request.url,
          ...(finding.request.headers ? { headers: finding.request.headers } : {}),
          ...(finding.request.body ? { body: finding.request.body } : {}),
        },
        response: finding.response ? {
          status: finding.response.status,
          ...(finding.response.headers ? { headers: finding.response.headers } : {}),
          ...(finding.response.bodySnippet ? { body: finding.response.bodySnippet } : {}),
        } : { status: 0 },
      };
    } else if (finding.response) {
      // Passive findings: construct implicit GET request from finding URL
      httpExchange = {
        request: {
          method: 'GET',
          url: finding.url,
        },
        response: {
          status: finding.response.status,
          ...(finding.response.headers ? { headers: finding.response.headers } : {}),
          ...(finding.response.bodySnippet ? { body: finding.response.bodySnippet } : {}),
        },
      };
    }
  }

  // Generate curl command — use request data or fall back to simple GET
  let curlCommand = existingPack.curlCommand ?? generateCurlCommand(finding);
  if (!curlCommand && finding.url) {
    // Generate a simple curl -I for header-based findings
    const isHeaderFinding = ['security-headers', 'cookie-flags', 'cross-origin-policy'].includes(finding.category);
    if (isHeaderFinding) {
      curlCommand = `curl -sI \\\n  '${escapeShell(finding.url)}'`;
    } else {
      curlCommand = `curl -s -i -L \\\n  '${escapeShell(finding.url)}'`;
    }
  }

  // Build reproduction URL from request or finding URL
  const reproductionUrl = existingPack.reproductionUrl ?? finding.request?.url ?? finding.url;

  // Infer detection method from category and evidence
  const detectionMethod = existingPack.detectionMethod ?? inferDetectionMethod(finding);

  // Extract response indicators from evidence string
  const responseIndicators = existingPack.responseIndicators ?? extractIndicators(finding);

  const enrichedPack: EvidencePack = {
    ...existingPack,
    ...(httpExchange ? { httpExchange } : {}),
    ...(curlCommand ? { curlCommand } : {}),
    ...(reproductionUrl ? { reproductionUrl } : {}),
    ...(detectionMethod ? { detectionMethod } : {}),
    ...(responseIndicators.length > 0 ? { responseIndicators } : {}),
  };

  return {
    ...finding,
    evidencePack: enrichedPack,
  };
}

/**
 * Batch-enrich all findings with evidence packs.
 */
export function enrichAllFindings(findings: RawFinding[]): RawFinding[] {
  return findings.map(enrichFindingEvidence);
}

/**
 * Infer the detection method from category and evidence text.
 */
function inferDetectionMethod(finding: RawFinding): string | undefined {
  const ev = finding.evidence.toLowerCase();
  const cat = finding.category;

  if (cat === 'sqli') {
    if (ev.includes('sleep') || ev.includes('delay') || ev.includes('timing')) return 'timing-based';
    if (ev.includes('error') || ev.includes('syntax')) return 'error-pattern';
    if (ev.includes('union')) return 'union-based';
    if (ev.includes('boolean') || ev.includes('body length')) return 'boolean-blind';
    return 'error-pattern';
  }
  if (cat === 'xss') {
    if (ev.includes('dom') || ev.includes('innerhtml') || ev.includes('sink')) return 'dom-sink';
    if (ev.includes('reflected') || ev.includes('body')) return 'reflection';
    if (ev.includes('stored')) return 'stored';
    return 'reflection';
  }
  if (cat === 'ssrf') return 'callback';
  if (cat === 'ssti') return 'math-evaluation';
  if (cat === 'command-injection') return 'marker-reflection';
  if (cat === 'crlf-injection') return 'header-injection';
  if (cat === 'open-redirect') return 'redirect-follow';
  if (cat === 'cors-misconfiguration') return 'header-reflection';
  if (cat === 'host-header') return 'header-injection';
  if (cat === 'file-upload') return 'upload-execution';
  if (cat === 'subdomain-takeover') return 'dns-dangling';
  if (cat === 'jwt') return 'token-manipulation';
  if (cat === 'race-condition') return 'concurrent-abuse';

  // Passive checks
  if (cat === 'security-headers' || cat === 'cookie-flags') return 'header-absence';
  if (cat === 'info-disclosure' || cat === 'info-leakage') return 'content-match';

  return undefined;
}

/**
 * Extract key response indicators from the evidence string.
 */
function extractIndicators(finding: RawFinding): string[] {
  const indicators: string[] = [];
  const ev = finding.evidence;

  // Extract quoted strings from evidence (common pattern: "found 'X' in response")
  const quoted = ev.match(/['"]([^'"]{3,80})['"]/g);
  if (quoted) {
    indicators.push(...quoted.map(q => q.replace(/['"]/g, '')).slice(0, 5));
  }

  // If response has bodySnippet, note the key part
  if (finding.response?.bodySnippet) {
    const snippet = finding.response.bodySnippet.slice(0, 100);
    if (snippet.length > 10) {
      indicators.push(`Response body contains: ${snippet}...`);
    }
  }

  // Response status as indicator
  if (finding.response?.status) {
    indicators.push(`HTTP ${finding.response.status}`);
  }

  return indicators;
}

/**
 * Generate a reproduction URL from a RawFinding.
 * For GET requests with query parameters, returns the URL with the payload embedded.
 * For other methods or findings without request data, returns the finding URL.
 */
export function generateReproductionUrl(finding: RawFinding): string | undefined {
  const req = finding.request ?? finding.evidencePack?.httpExchange?.request;

  // If we have request data, use its URL directly (it should already contain the payload)
  if (req?.url) {
    return req.url;
  }

  // Fall back to finding.url if available
  if (finding.url) {
    return finding.url;
  }

  return undefined;
}

/**
 * Escape a string for safe use in a shell single-quoted context.
 */
function escapeShell(str: string): string {
  return str.replace(/'/g, "'\\''");
}

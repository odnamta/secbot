import { describe, it, expect } from 'vitest';
import { generateCurlCommand, enrichFindingEvidence, enrichAllFindings } from '../../src/utils/evidence.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: 'test-1',
    category: 'xss',
    severity: 'high',
    title: 'Reflected XSS',
    description: 'XSS via q parameter',
    url: 'https://example.com/search?q=test',
    evidence: "Payload '<script>alert(1)</script>' reflected in response body",
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('generateCurlCommand', () => {
  it('generates GET curl command from request', () => {
    const finding = makeFinding({
      request: { method: 'GET', url: 'https://example.com/search?q=<script>alert(1)</script>' },
    });
    const curl = generateCurlCommand(finding);
    expect(curl).toBeDefined();
    expect(curl).toContain('curl');
    expect(curl).toContain('https://example.com/search');
    expect(curl).toContain('-L');
    expect(curl).toContain('-i');
    // GET should not have -X GET
    expect(curl).not.toContain('-X GET');
  });

  it('generates POST curl command with body', () => {
    const finding = makeFinding({
      category: 'sqli',
      request: {
        method: 'POST',
        url: 'https://example.com/login',
        body: 'username=admin&password=test',
      },
    });
    const curl = generateCurlCommand(finding);
    expect(curl).toBeDefined();
    expect(curl).toContain('-X POST');
    expect(curl).toContain("-d 'username=admin&password=test'");
  });

  it('generates POST curl command with JSON body', () => {
    const finding = makeFinding({
      request: {
        method: 'POST',
        url: 'https://example.com/api/data',
        body: '{"username":"admin"}',
      },
    });
    const curl = generateCurlCommand(finding);
    expect(curl).toContain("Content-Type: application/json");
    expect(curl).toContain('{"username":"admin"}');
  });

  it('includes custom headers', () => {
    const finding = makeFinding({
      request: {
        method: 'GET',
        url: 'https://example.com/',
        headers: { 'Origin': 'https://evil.com', 'X-Custom': 'value' },
      },
    });
    const curl = generateCurlCommand(finding);
    expect(curl).toContain("Origin: https://evil.com");
    expect(curl).toContain("X-Custom: value");
  });

  it('returns undefined when no request data', () => {
    const finding = makeFinding();
    const curl = generateCurlCommand(finding);
    expect(curl).toBeUndefined();
  });

  it('escapes single quotes in URL', () => {
    const finding = makeFinding({
      request: { method: 'GET', url: "https://example.com/search?q=' OR 1=1--" },
    });
    const curl = generateCurlCommand(finding);
    expect(curl).toBeDefined();
    expect(curl).toContain("'\\''");
  });
});

describe('enrichFindingEvidence', () => {
  it('adds evidence pack with curl command', () => {
    const finding = makeFinding({
      request: { method: 'GET', url: 'https://example.com/search?q=<script>' },
      response: { status: 200, bodySnippet: '<script>alert(1)</script>' },
    });
    const enriched = enrichFindingEvidence(finding);
    expect(enriched.evidencePack).toBeDefined();
    expect(enriched.evidencePack!.curlCommand).toContain('curl');
    expect(enriched.evidencePack!.httpExchange).toBeDefined();
    expect(enriched.evidencePack!.httpExchange!.request.method).toBe('GET');
    expect(enriched.evidencePack!.httpExchange!.response.status).toBe(200);
  });

  it('sets detection method based on category', () => {
    const xss = enrichFindingEvidence(makeFinding({
      request: { method: 'GET', url: 'https://example.com/x' },
    }));
    expect(xss.evidencePack!.detectionMethod).toBe('reflection');

    const sqli = enrichFindingEvidence(makeFinding({
      category: 'sqli',
      evidence: "SQL error in response: syntax error near 'secbot'",
      request: { method: 'GET', url: 'https://example.com/x' },
    }));
    expect(sqli.evidencePack!.detectionMethod).toBe('error-pattern');

    const blind = enrichFindingEvidence(makeFinding({
      category: 'sqli',
      evidence: 'SLEEP(5) caused 5200ms delay',
      request: { method: 'GET', url: 'https://example.com/x' },
    }));
    expect(blind.evidencePack!.detectionMethod).toBe('timing-based');
  });

  it('sets reproduction URL from request', () => {
    const finding = makeFinding({
      request: { method: 'GET', url: 'https://example.com/search?q=test' },
    });
    const enriched = enrichFindingEvidence(finding);
    expect(enriched.evidencePack!.reproductionUrl).toBe('https://example.com/search?q=test');
  });

  it('extracts response indicators from evidence', () => {
    const finding = makeFinding({
      evidence: "Found 'SQL syntax error' in response body",
      request: { method: 'GET', url: 'https://example.com/' },
      response: { status: 500 },
    });
    const enriched = enrichFindingEvidence(finding);
    expect(enriched.evidencePack!.responseIndicators).toBeDefined();
    expect(enriched.evidencePack!.responseIndicators!.length).toBeGreaterThan(0);
  });

  it('enriches findings without request data using finding URL', () => {
    const finding = makeFinding();
    const enriched = enrichFindingEvidence(finding);
    expect(enriched.evidencePack).toBeDefined();
    expect(enriched.evidencePack!.detectionMethod).toBe('reflection');
    expect(enriched.evidencePack!.reproductionUrl).toBe(finding.url);
    expect(enriched.evidencePack!.curlCommand).toContain('curl');
  });

  it('generates curl -sI for header-based findings', () => {
    const finding = makeFinding({
      category: 'security-headers',
      evidence: "Header 'strict-transport-security' not present",
      response: { status: 200, headers: { 'x-powered-by': 'Next.js' } },
    });
    const enriched = enrichFindingEvidence(finding);
    expect(enriched.evidencePack!.curlCommand).toContain('curl -sI');
    expect(enriched.evidencePack!.httpExchange).toBeDefined();
    expect(enriched.evidencePack!.httpExchange!.response.status).toBe(200);
  });

  it('preserves existing evidence pack data', () => {
    const finding = makeFinding({
      request: { method: 'GET', url: 'https://example.com/' },
      evidencePack: {
        payloadUsed: '<script>alert(1)</script>',
        detectionMethod: 'custom-method',
      },
    });
    const enriched = enrichFindingEvidence(finding);
    expect(enriched.evidencePack!.payloadUsed).toBe('<script>alert(1)</script>');
    expect(enriched.evidencePack!.detectionMethod).toBe('custom-method');
    expect(enriched.evidencePack!.curlCommand).toBeDefined();
  });
});

describe('enrichAllFindings', () => {
  it('enriches all findings in batch', () => {
    const findings = [
      makeFinding({ id: '1', request: { method: 'GET', url: 'https://example.com/a' } }),
      makeFinding({ id: '2', request: { method: 'POST', url: 'https://example.com/b', body: 'x=1' } }),
      makeFinding({ id: '3' }), // no request — still gets basic enrichment
    ];
    const enriched = enrichAllFindings(findings);
    expect(enriched).toHaveLength(3);
    expect(enriched[0].evidencePack?.curlCommand).toBeDefined();
    expect(enriched[1].evidencePack?.curlCommand).toContain('-X POST');
    expect(enriched[2].evidencePack).toBeDefined(); // gets curl from finding URL
    expect(enriched[2].evidencePack!.detectionMethod).toBeDefined();
  });
});

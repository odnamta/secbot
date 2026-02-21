import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, unlinkSync, existsSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeJsonReport } from '../../src/reporter/json.js';
import { writeHtmlReport } from '../../src/reporter/html.js';
import { writeBountyReport } from '../../src/reporter/bounty.js';
import { printTerminalReport } from '../../src/reporter/terminal.js';
import type { ScanResult, InterpretedFinding, Severity } from '../../src/scanner/types.js';

// ─── Factories ────────────────────────────────────────────────────────

function makeInterpretedFinding(overrides: Partial<InterpretedFinding> = {}): InterpretedFinding {
  return {
    title: 'Reflected XSS in /search',
    severity: 'high',
    confidence: 'high',
    owaspCategory: 'A03:2021 Injection',
    description: 'User input is reflected in the response without encoding.',
    impact: 'An attacker can execute arbitrary JavaScript in a victim browser.',
    reproductionSteps: [
      '1. Navigate to /search?q=<script>alert(1)</script>',
      '2. Observe the script executes in the page context',
    ],
    suggestedFix: 'Encode all user-controlled output using context-aware encoding.',
    codeExample: 'GET /search?q=<script>alert(1)</script> HTTP/1.1',
    affectedUrls: ['https://example.com/search?q=test'],
    rawFindingIds: ['raw-1'],
    ...overrides,
  };
}

function makeScanResult(
  interpretedFindings: InterpretedFinding[] = [],
  overrides: Partial<ScanResult> = {},
): ScanResult {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of interpretedFindings) {
    bySeverity[f.severity]++;
  }

  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    startedAt: '2026-01-15T10:00:00.000Z',
    completedAt: '2026-01-15T10:05:00.000Z',
    pagesScanned: 10,
    rawFindings: [],
    interpretedFindings,
    summary: {
      totalRawFindings: 3,
      totalInterpretedFindings: interpretedFindings.length,
      bySeverity,
      topIssues: interpretedFindings.length > 0 ? ['Fix XSS vulnerabilities'] : [],
      passedChecks: ['cors-misconfiguration'],
    },
    exitCode: interpretedFindings.length > 0 ? 1 : 0,
    scanDuration: 300000,
    checksRun: ['security-headers', 'xss', 'sqli'],
    ...overrides,
  };
}

// ─── Temp file management ─────────────────────────────────────────────

const tmpFiles: string[] = [];

function tmpPath(ext: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'secbot-reporter-test-'));
  const p = join(dir, `report.${ext}`);
  tmpFiles.push(p);
  return p;
}

afterEach(() => {
  for (const f of tmpFiles) {
    if (existsSync(f)) unlinkSync(f);
  }
  tmpFiles.length = 0;
});

// ─── JSON Reporter ────────────────────────────────────────────────────

describe('JSON reporter', () => {
  it('writes valid JSON to disk', () => {
    const path = tmpPath('json');
    const result = makeScanResult([makeInterpretedFinding()]);
    writeJsonReport(result, path);

    expect(existsSync(path)).toBe(true);
    const content = readFileSync(path, 'utf-8');
    expect(() => JSON.parse(content)).not.toThrow();
  });

  it('contains all top-level ScanResult fields', () => {
    const path = tmpPath('json');
    const result = makeScanResult([makeInterpretedFinding()]);
    writeJsonReport(result, path);

    const parsed = JSON.parse(readFileSync(path, 'utf-8'));
    expect(parsed.targetUrl).toBe('https://example.com');
    expect(parsed.profile).toBe('standard');
    expect(parsed.startedAt).toBe('2026-01-15T10:00:00.000Z');
    expect(parsed.completedAt).toBe('2026-01-15T10:05:00.000Z');
    expect(parsed.pagesScanned).toBe(10);
    expect(parsed.rawFindings).toBeInstanceOf(Array);
    expect(parsed.interpretedFindings).toBeInstanceOf(Array);
    expect(parsed.summary).toBeDefined();
    expect(parsed.exitCode).toBeDefined();
    expect(parsed.scanDuration).toBe(300000);
    expect(parsed.checksRun).toBeInstanceOf(Array);
  });

  it('preserves interpreted findings structure', () => {
    const path = tmpPath('json');
    const finding = makeInterpretedFinding({ title: 'SQL Injection in /api' });
    const result = makeScanResult([finding]);
    writeJsonReport(result, path);

    const parsed = JSON.parse(readFileSync(path, 'utf-8'));
    const f = parsed.interpretedFindings[0];
    expect(f.title).toBe('SQL Injection in /api');
    expect(f.severity).toBe('high');
    expect(f.confidence).toBe('high');
    expect(f.owaspCategory).toBe('A03:2021 Injection');
    expect(f.reproductionSteps).toBeInstanceOf(Array);
    expect(f.reproductionSteps.length).toBeGreaterThan(0);
    expect(f.affectedUrls).toBeInstanceOf(Array);
    expect(f.rawFindingIds).toBeInstanceOf(Array);
  });

  it('preserves summary severity counts', () => {
    const path = tmpPath('json');
    const findings = [
      makeInterpretedFinding({ severity: 'critical' }),
      makeInterpretedFinding({ severity: 'high' }),
      makeInterpretedFinding({ severity: 'medium' }),
    ];
    const result = makeScanResult(findings);
    writeJsonReport(result, path);

    const parsed = JSON.parse(readFileSync(path, 'utf-8'));
    expect(parsed.summary.bySeverity.critical).toBe(1);
    expect(parsed.summary.bySeverity.high).toBe(1);
    expect(parsed.summary.bySeverity.medium).toBe(1);
    expect(parsed.summary.bySeverity.low).toBe(0);
    expect(parsed.summary.bySeverity.info).toBe(0);
  });

  it('handles empty findings', () => {
    const path = tmpPath('json');
    const result = makeScanResult([]);
    writeJsonReport(result, path);

    const parsed = JSON.parse(readFileSync(path, 'utf-8'));
    expect(parsed.interpretedFindings).toEqual([]);
    expect(parsed.summary.totalInterpretedFindings).toBe(0);
    expect(parsed.summary.bySeverity.critical).toBe(0);
  });

  it('is pretty-printed with 2-space indentation', () => {
    const path = tmpPath('json');
    writeJsonReport(makeScanResult([]), path);

    const content = readFileSync(path, 'utf-8');
    // JSON.stringify with 2-space indent starts object properties on new lines with 2 spaces
    expect(content).toContain('\n  "targetUrl"');
  });
});

// ─── HTML Reporter ────────────────────────────────────────────────────

describe('HTML reporter', () => {
  it('writes valid HTML to disk', () => {
    const path = tmpPath('html');
    writeHtmlReport(makeScanResult([makeInterpretedFinding()]), path);

    expect(existsSync(path)).toBe(true);
    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html');
    expect(html).toContain('</html>');
  });

  it('contains head with charset and title', () => {
    const path = tmpPath('html');
    writeHtmlReport(makeScanResult([makeInterpretedFinding()]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('<meta charset="UTF-8">');
    expect(html).toContain('<title>SecBot Report');
    expect(html).toContain('example.com');
  });

  it('includes summary statistics section', () => {
    const path = tmpPath('html');
    const findings = [
      makeInterpretedFinding({ severity: 'critical' }),
      makeInterpretedFinding({ severity: 'high' }),
    ];
    const result = makeScanResult(findings);
    writeHtmlReport(result, path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('Raw Findings');
    expect(html).toContain('Actionable');
    expect(html).toContain('Critical/High');
    expect(html).toContain('Pages Scanned');
  });

  it('renders severity badges when findings exist', () => {
    const path = tmpPath('html');
    const findings = [
      makeInterpretedFinding({ severity: 'critical' }),
      makeInterpretedFinding({ severity: 'high' }),
      makeInterpretedFinding({ severity: 'medium' }),
      makeInterpretedFinding({ severity: 'low' }),
      makeInterpretedFinding({ severity: 'info' }),
    ];
    const result = makeScanResult(findings);
    writeHtmlReport(result, path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('sev-badge sev-critical');
    expect(html).toContain('sev-badge sev-high');
    expect(html).toContain('sev-badge sev-medium');
    expect(html).toContain('sev-badge sev-low');
    expect(html).toContain('sev-badge sev-info');
  });

  it('renders finding cards with title, description, and impact', () => {
    const path = tmpPath('html');
    const finding = makeInterpretedFinding({
      title: 'Missing CSP Header',
      description: 'No Content-Security-Policy header is set.',
      impact: 'Allows injection of arbitrary resources.',
    });
    writeHtmlReport(makeScanResult([finding]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('Missing CSP Header');
    expect(html).toContain('No Content-Security-Policy header is set.');
    expect(html).toContain('Allows injection of arbitrary resources.');
  });

  it('renders reproduction steps as an ordered list', () => {
    const path = tmpPath('html');
    const finding = makeInterpretedFinding({
      reproductionSteps: ['Open the URL', 'Inject payload', 'Observe result'],
    });
    writeHtmlReport(makeScanResult([finding]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('<ol>');
    expect(html).toContain('<li>Open the URL</li>');
    expect(html).toContain('<li>Inject payload</li>');
    expect(html).toContain('<li>Observe result</li>');
  });

  it('renders code examples in pre/code blocks', () => {
    const path = tmpPath('html');
    const finding = makeInterpretedFinding({
      codeExample: 'GET /api?id=1 OR 1=1',
    });
    writeHtmlReport(makeScanResult([finding]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('<pre><code>');
    expect(html).toContain('GET /api?id=1 OR 1=1');
  });

  it('renders affected URLs list', () => {
    const path = tmpPath('html');
    const finding = makeInterpretedFinding({
      affectedUrls: ['https://example.com/page1', 'https://example.com/page2'],
    });
    writeHtmlReport(makeScanResult([finding]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('Affected URLs');
    expect(html).toContain('https://example.com/page1');
    expect(html).toContain('https://example.com/page2');
  });

  it('escapes HTML special characters in finding content', () => {
    const path = tmpPath('html');
    const finding = makeInterpretedFinding({
      title: 'XSS via <script> & "quotes"',
      description: 'Payload: <img src=x onerror=alert(1)>',
    });
    writeHtmlReport(makeScanResult([finding]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('&amp;');
    expect(html).toContain('&quot;quotes&quot;');
    // Raw unescaped tags should not appear in finding content
    expect(html).not.toMatch(/<script>.*<\/script>/);
  });

  it('shows "no vulnerabilities" message for empty findings', () => {
    const path = tmpPath('html');
    writeHtmlReport(makeScanResult([]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('No actionable vulnerabilities found!');
  });

  it('includes footer with SecBot version', () => {
    const path = tmpPath('html');
    writeHtmlReport(makeScanResult([]), path);

    const html = readFileSync(path, 'utf-8');
    expect(html).toContain('Generated by SecBot');
    expect(html).toContain('<footer>');
  });

  it('sorts findings by severity (critical first)', () => {
    const path = tmpPath('html');
    const findings = [
      makeInterpretedFinding({ title: 'Low Issue', severity: 'low' }),
      makeInterpretedFinding({ title: 'Critical Issue', severity: 'critical' }),
      makeInterpretedFinding({ title: 'Medium Issue', severity: 'medium' }),
    ];
    writeHtmlReport(makeScanResult(findings), path);

    const html = readFileSync(path, 'utf-8');
    const criticalPos = html.indexOf('Critical Issue');
    const mediumPos = html.indexOf('Medium Issue');
    const lowPos = html.indexOf('Low Issue');
    expect(criticalPos).toBeLessThan(mediumPos);
    expect(mediumPos).toBeLessThan(lowPos);
  });
});

// ─── Bounty Markdown Reporter ─────────────────────────────────────────

describe('Bounty markdown reporter', () => {
  it('writes valid markdown to disk', () => {
    const path = tmpPath('md');
    writeBountyReport(makeScanResult([makeInterpretedFinding()]), path);

    expect(existsSync(path)).toBe(true);
    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('# Security Assessment Report');
  });

  it('includes target metadata in header', () => {
    const path = tmpPath('md');
    writeBountyReport(makeScanResult([makeInterpretedFinding()]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('**Target:** https://example.com');
    expect(md).toContain('**Scan Date:**');
    expect(md).toContain('**Profile:** standard');
    expect(md).toContain('**Pages Scanned:** 10');
    expect(md).toContain('**Duration:**');
  });

  it('contains summary table with severity counts', () => {
    const path = tmpPath('md');
    const findings = [
      makeInterpretedFinding({ severity: 'critical' }),
      makeInterpretedFinding({ severity: 'high' }),
    ];
    writeBountyReport(makeScanResult(findings), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('## Summary');
    expect(md).toContain('| Severity | Count |');
    expect(md).toContain('| Critical |');
    expect(md).toContain('| High |');
    expect(md).toContain('| Medium |');
    expect(md).toContain('| Low |');
    expect(md).toContain('| Info |');
    expect(md).toContain('| **Total** |');
  });

  it('renders finding sections with severity label in heading', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      title: 'Open Redirect via returnUrl',
      severity: 'medium',
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('## 1. [MEDIUM] Open Redirect via returnUrl');
  });

  it('includes CWE weakness mapping', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      title: 'Reflected XSS in search',
      severity: 'high',
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('**Weakness:** CWE-');
  });

  it('includes OWASP category and confidence', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      owaspCategory: 'A03:2021 Injection',
      confidence: 'high',
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('**OWASP Category:** A03:2021 Injection');
    expect(md).toContain('**Confidence:** high');
  });

  it('includes reproduction steps section', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      reproductionSteps: [
        '1. Navigate to /search',
        '2. Enter payload <script>alert(1)</script>',
        '3. Observe XSS fires',
      ],
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('### Steps to Reproduce');
    expect(md).toContain('1. Navigate to /search');
    expect(md).toContain('2. Enter payload <script>alert(1)</script>');
    expect(md).toContain('3. Observe XSS fires');
  });

  it('includes impact section', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      impact: 'Full account takeover via session hijacking.',
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('### Impact');
    expect(md).toContain('Full account takeover via session hijacking.');
  });

  it('includes affected URLs as supporting evidence', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      affectedUrls: ['https://example.com/a', 'https://example.com/b'],
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('### Supporting Evidence');
    expect(md).toContain('**Affected URLs:**');
    expect(md).toContain('- https://example.com/a');
    expect(md).toContain('- https://example.com/b');
  });

  it('includes code example in fenced code block', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      codeExample: 'GET /api?token=secret HTTP/1.1\nHost: example.com',
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('**HTTP Request/Response:**');
    expect(md).toContain('```');
    expect(md).toContain('GET /api?token=secret HTTP/1.1');
  });

  it('includes suggested remediation section', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({
      suggestedFix: 'Implement proper output encoding for all user-controlled data.',
    });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('### Suggested Remediation');
    expect(md).toContain('Implement proper output encoding for all user-controlled data.');
  });

  it('handles empty findings with a clean message', () => {
    const path = tmpPath('md');
    writeBountyReport(makeScanResult([]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('# Security Assessment Report');
    expect(md).toContain('## Summary');
    expect(md).toContain('No actionable vulnerabilities were identified');
    // Should not have finding headers
    expect(md).not.toContain('### Description');
    expect(md).not.toContain('### Steps to Reproduce');
  });

  it('includes footer with SecBot attribution', () => {
    const path = tmpPath('md');
    writeBountyReport(makeScanResult([makeInterpretedFinding()]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('Generated by SecBot');
  });

  it('sorts findings by severity (critical first)', () => {
    const path = tmpPath('md');
    const findings = [
      makeInterpretedFinding({ title: 'Info Disclosure', severity: 'info' }),
      makeInterpretedFinding({ title: 'Critical SQLi', severity: 'critical' }),
      makeInterpretedFinding({ title: 'Medium CORS', severity: 'medium' }),
    ];
    writeBountyReport(makeScanResult(findings), path);

    const md = readFileSync(path, 'utf-8');
    const criticalPos = md.indexOf('[CRITICAL] Critical SQLi');
    const mediumPos = md.indexOf('[MEDIUM] Medium CORS');
    const infoPos = md.indexOf('[INFO] Info Disclosure');
    expect(criticalPos).toBeLessThan(mediumPos);
    expect(mediumPos).toBeLessThan(infoPos);
  });

  it('maps XSS findings to CWE-79', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({ title: 'Reflected XSS in /page' });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('CWE-79');
  });

  it('maps SQL injection findings to CWE-89', () => {
    const path = tmpPath('md');
    const finding = makeInterpretedFinding({ title: 'SQL Injection in /api/users' });
    writeBountyReport(makeScanResult([finding]), path);

    const md = readFileSync(path, 'utf-8');
    expect(md).toContain('CWE-89');
  });
});

// ─── Terminal Reporter ────────────────────────────────────────────────

describe('Terminal reporter', () => {
  it('does not throw with findings', () => {
    const result = makeScanResult([
      makeInterpretedFinding({ severity: 'critical' }),
      makeInterpretedFinding({ severity: 'high' }),
      makeInterpretedFinding({ severity: 'medium' }),
      makeInterpretedFinding({ severity: 'low' }),
      makeInterpretedFinding({ severity: 'info' }),
    ]);
    expect(() => printTerminalReport(result)).not.toThrow();
  });

  it('does not throw with empty findings', () => {
    const result = makeScanResult([]);
    expect(() => printTerminalReport(result)).not.toThrow();
  });

  it('does not throw with findings that have no optional fields', () => {
    const minimalFinding = makeInterpretedFinding({
      codeExample: undefined,
      affectedUrls: [],
      reproductionSteps: [],
    });
    const result = makeScanResult([minimalFinding]);
    expect(() => printTerminalReport(result)).not.toThrow();
  });

  it('does not throw with many affected URLs (truncation path)', () => {
    const finding = makeInterpretedFinding({
      affectedUrls: Array.from({ length: 20 }, (_, i) => `https://example.com/page${i}`),
    });
    const result = makeScanResult([finding]);
    expect(() => printTerminalReport(result)).not.toThrow();
  });

  it('does not throw with top issues populated', () => {
    const result = makeScanResult([makeInterpretedFinding()], {
      summary: {
        totalRawFindings: 1,
        totalInterpretedFindings: 1,
        bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        topIssues: ['Fix XSS in /search', 'Add CSP header', 'Enable HSTS'],
        passedChecks: [],
      },
    });
    expect(() => printTerminalReport(result)).not.toThrow();
  });

  it('does not throw with multiline code examples', () => {
    const finding = makeInterpretedFinding({
      codeExample: 'GET /api HTTP/1.1\nHost: example.com\nCookie: session=abc\n\n<script>alert(1)</script>',
    });
    const result = makeScanResult([finding]);
    expect(() => printTerminalReport(result)).not.toThrow();
  });
});

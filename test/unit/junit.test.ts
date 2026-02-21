import { describe, it, expect, afterEach } from 'vitest';
import { writeJunitReport } from '../../src/reporter/junit.js';
import { readFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanResult, InterpretedFinding } from '../../src/scanner/types.js';

function makeScanResult(findings: InterpretedFinding[] = [], checksRun: string[] = []): ScanResult {
  return {
    targetUrl: 'http://example.com',
    profile: 'standard',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    pagesScanned: 5,
    rawFindings: [],
    interpretedFindings: findings,
    summary: {
      totalRawFindings: findings.length,
      totalInterpretedFindings: findings.length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      topIssues: [],
      passedChecks: [],
    },
    exitCode: 0,
    scanDuration: 5000,
    checksRun,
  };
}

function makeFinding(overrides: Partial<InterpretedFinding> = {}): InterpretedFinding {
  return {
    title: 'Test XSS Finding',
    severity: 'high',
    confidence: 'high',
    owaspCategory: 'A03:2021',
    description: 'A reflected XSS vulnerability was found.',
    impact: 'An attacker can execute arbitrary JavaScript.',
    reproductionSteps: ['Send payload', 'Observe reflection'],
    suggestedFix: 'Encode output',
    affectedUrls: ['http://example.com/search?q=test'],
    rawFindingIds: ['id-1'],
    ...overrides,
  };
}

describe('JUnit XML Reporter', () => {
  const tmpFiles: string[] = [];

  function tmpPath(): string {
    const p = join(tmpdir(), `secbot-junit-${Date.now()}-${Math.random().toString(36).slice(2)}.xml`);
    tmpFiles.push(p);
    return p;
  }

  afterEach(() => {
    for (const f of tmpFiles) {
      if (existsSync(f)) unlinkSync(f);
    }
    tmpFiles.length = 0;
  });

  it('produces valid XML with 0 findings', () => {
    const path = tmpPath();
    writeJunitReport(makeScanResult([], ['xss', 'sqli']), path);

    const xml = readFileSync(path, 'utf-8');
    expect(xml).toContain('<?xml version="1.0"');
    expect(xml).toContain('<testsuites');
    expect(xml).toContain('failures="0"');
    expect(xml).toContain('</testsuites>');
  });

  it('creates test cases for findings', () => {
    const path = tmpPath();
    const findings = [
      makeFinding({ title: 'Reflected XSS in /search', severity: 'high' }),
      makeFinding({ title: 'SQL Injection in /api', severity: 'critical' }),
    ];
    writeJunitReport(makeScanResult(findings, ['xss', 'sqli']), path);

    const xml = readFileSync(path, 'utf-8');
    expect(xml).toContain('failures="2"');
    expect(xml).toContain('Reflected XSS');
    expect(xml).toContain('SQL Injection');
  });

  it('maps check categories to test suites', () => {
    const path = tmpPath();
    const findings = [
      makeFinding({ title: 'XSS in form', severity: 'high' }),
    ];
    writeJunitReport(makeScanResult(findings, ['xss', 'sqli', 'cors-misconfiguration']), path);

    const xml = readFileSync(path, 'utf-8');
    // XSS category should have a failure
    expect(xml).toContain('testsuite name="xss"');
    // SQLi and CORS should be passed (no findings)
    expect(xml).toContain('No sqli findings');
    expect(xml).toContain('No cors-misconfiguration findings');
  });

  it('escapes XML special characters', () => {
    const path = tmpPath();
    const findings = [
      makeFinding({
        title: 'XSS via <script> & "quotes"',
        description: 'Payload: <img src=x onerror=alert(1)>',
      }),
    ];
    writeJunitReport(makeScanResult(findings), path);

    const xml = readFileSync(path, 'utf-8');
    expect(xml).toContain('&lt;script&gt;');
    expect(xml).toContain('&amp;');
    expect(xml).toContain('&quot;');
    expect(xml).not.toContain('<script>');
  });

  it('includes severity and fix info in failure details', () => {
    const path = tmpPath();
    const findings = [
      makeFinding({ severity: 'critical', suggestedFix: 'Use parameterized queries' }),
    ];
    writeJunitReport(makeScanResult(findings), path);

    const xml = readFileSync(path, 'utf-8');
    expect(xml).toContain('type="critical"');
    expect(xml).toContain('Use parameterized queries');
  });

  it('includes scan duration in time attribute', () => {
    const path = tmpPath();
    writeJunitReport(makeScanResult([], []), path);

    const xml = readFileSync(path, 'utf-8');
    expect(xml).toContain('time="5.00"');
  });
});

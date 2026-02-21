import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, unlinkSync, existsSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeSarifReport, buildSarifLog } from '../../src/reporter/sarif.js';
import type { ScanResult, RawFinding, Severity } from '../../src/scanner/types.js';

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    category: 'xss',
    severity: 'high',
    title: 'Reflected XSS',
    description: 'User input reflected in response without encoding',
    url: 'https://example.com/search?q=test',
    evidence: '<script>alert(1)</script> found in response',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeScanResult(findings: RawFinding[] = []): ScanResult {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    bySeverity[f.severity]++;
  }

  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    startedAt: '2026-01-01T00:00:00.000Z',
    completedAt: '2026-01-01T00:05:00.000Z',
    pagesScanned: 5,
    rawFindings: findings,
    interpretedFindings: [],
    summary: {
      totalRawFindings: findings.length,
      totalInterpretedFindings: 0,
      bySeverity,
      topIssues: [],
      passedChecks: [],
    },
    exitCode: 0,
    scanDuration: 300000,
    checksRun: ['security-headers', 'xss'],
  };
}

let tmpDir: string;
let tmpFile: string;

function getTmpFile(): string {
  tmpDir = mkdtempSync(join(tmpdir(), 'secbot-sarif-test-'));
  tmpFile = join(tmpDir, 'test-report.sarif');
  return tmpFile;
}

afterEach(() => {
  if (tmpFile && existsSync(tmpFile)) {
    unlinkSync(tmpFile);
  }
});

describe('SARIF reporter', () => {
  describe('writeSarifReport', () => {
    it('writes valid JSON to disk', () => {
      const outPath = getTmpFile();
      const result = makeScanResult([makeFinding()]);
      writeSarifReport(result, outPath);

      expect(existsSync(outPath)).toBe(true);
      const content = readFileSync(outPath, 'utf-8');
      expect(() => JSON.parse(content)).not.toThrow();
    });

    it('includes the correct SARIF schema', () => {
      const outPath = getTmpFile();
      const result = makeScanResult([makeFinding()]);
      writeSarifReport(result, outPath);

      const sarif = JSON.parse(readFileSync(outPath, 'utf-8'));
      expect(sarif.$schema).toBe(SARIF_SCHEMA);
      expect(sarif.version).toBe('2.1.0');
    });

    it('creates parent directories if needed', () => {
      const deepPath = join(mkdtempSync(join(tmpdir(), 'secbot-sarif-deep-')), 'sub', 'dir', 'report.sarif');
      tmpFile = deepPath; // for cleanup
      const result = makeScanResult([]);
      writeSarifReport(result, deepPath);
      expect(existsSync(deepPath)).toBe(true);
    });
  });

  describe('buildSarifLog', () => {
    it('includes correct tool driver metadata', () => {
      const result = makeScanResult([]);
      const sarif = buildSarifLog(result);

      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe('SecBot');
      expect(sarif.runs[0].tool.driver.version).toBeTruthy();
      expect(sarif.runs[0].tool.driver.informationUri).toBeTruthy();
    });

    it('maps findings to SARIF results', () => {
      const findings = [
        makeFinding({ category: 'xss', title: 'XSS found', description: 'Reflected XSS', url: 'https://example.com/page1' }),
        makeFinding({ category: 'sqli', title: 'SQL Injection', description: 'SQL error in response', url: 'https://example.com/page2', severity: 'critical' }),
      ];
      const result = makeScanResult(findings);
      const sarif = buildSarifLog(result);

      expect(sarif.runs[0].results).toHaveLength(2);

      const r0 = sarif.runs[0].results[0];
      expect(r0.ruleId).toBe('xss');
      expect(r0.message.text).toContain('XSS found');
      expect(r0.locations[0].physicalLocation.artifactLocation.uri).toBe('https://example.com/page1');

      const r1 = sarif.runs[0].results[1];
      expect(r1.ruleId).toBe('sqli');
      expect(r1.message.text).toContain('SQL Injection');
      expect(r1.locations[0].physicalLocation.artifactLocation.uri).toBe('https://example.com/page2');
    });

    it('builds unique rules from finding categories', () => {
      const findings = [
        makeFinding({ category: 'xss' }),
        makeFinding({ category: 'xss' }),
        makeFinding({ category: 'sqli', severity: 'critical' }),
      ];
      const result = makeScanResult(findings);
      const sarif = buildSarifLog(result);

      const rules = sarif.runs[0].tool.driver.rules;
      expect(rules).toHaveLength(2);

      const ruleIds = rules.map((r) => r.id);
      expect(ruleIds).toContain('xss');
      expect(ruleIds).toContain('sqli');
    });

    it('produces valid SARIF with 0 results for empty findings', () => {
      const result = makeScanResult([]);
      const sarif = buildSarifLog(result);

      expect(sarif.$schema).toBe(SARIF_SCHEMA);
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].results).toHaveLength(0);
      expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
      expect(sarif.runs[0].tool.driver.name).toBe('SecBot');
    });
  });

  describe('severity mapping', () => {
    it('maps critical to error', () => {
      const findings = [makeFinding({ severity: 'critical' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].level).toBe('error');
    });

    it('maps high to error', () => {
      const findings = [makeFinding({ severity: 'high' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].level).toBe('error');
    });

    it('maps medium to warning', () => {
      const findings = [makeFinding({ severity: 'medium' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].level).toBe('warning');
    });

    it('maps low to note', () => {
      const findings = [makeFinding({ severity: 'low' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].level).toBe('note');
    });

    it('maps info to note', () => {
      const findings = [makeFinding({ severity: 'info' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].level).toBe('note');
    });
  });

  describe('result message and location', () => {
    it('includes both title and description in message text', () => {
      const findings = [makeFinding({ title: 'My Title', description: 'My Description' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].message.text).toBe('My Title: My Description');
    });

    it('uses finding URL as artifact location URI', () => {
      const findings = [makeFinding({ url: 'https://target.com/api/v1/users' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri)
        .toBe('https://target.com/api/v1/users');
    });
  });

  describe('rules defaultConfiguration', () => {
    it('sets rule default level from the first finding of that category', () => {
      const findings = [
        makeFinding({ category: 'cors-misconfiguration', severity: 'medium' }),
      ];
      const sarif = buildSarifLog(makeScanResult(findings));
      const rule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'cors-misconfiguration');
      expect(rule).toBeDefined();
      expect(rule!.defaultConfiguration.level).toBe('warning');
    });

    it('has human-readable rule name and shortDescription', () => {
      const findings = [makeFinding({ category: 'command-injection', severity: 'critical' })];
      const sarif = buildSarifLog(makeScanResult(findings));
      const rule = sarif.runs[0].tool.driver.rules[0];
      expect(rule.name).toBe('Command Injection');
      expect(rule.shortDescription.text).toBe('Command Injection');
    });
  });
});

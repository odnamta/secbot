import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ScanResult, Severity, RawFinding, CheckCategory } from '../scanner/types.js';
import { log } from '../utils/logger.js';

const sarifPkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'));

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

/**
 * Map SecBot severity to SARIF level.
 * SARIF levels: error, warning, note, none
 */
function mapSeverityToLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

/**
 * Map a CheckCategory to a human-readable rule name.
 */
function categoryToRuleName(category: CheckCategory): string {
  const map: Record<CheckCategory, string> = {
    'security-headers': 'Missing Security Headers',
    'cookie-flags': 'Insecure Cookie Flags',
    'info-leakage': 'Information Leakage',
    'mixed-content': 'Mixed Content',
    'sensitive-url-data': 'Sensitive Data in URL',
    'xss': 'Cross-Site Scripting (XSS)',
    'sqli': 'SQL Injection',
    'open-redirect': 'Open Redirect',
    'cross-origin-policy': 'Cross-Origin Policy Issue',
    'cors-misconfiguration': 'CORS Misconfiguration',
    'directory-traversal': 'Directory Traversal',
    'ssrf': 'Server-Side Request Forgery (SSRF)',
    'ssti': 'Server-Side Template Injection (SSTI)',
    'idor': 'Insecure Direct Object Reference (IDOR)',
    'command-injection': 'Command Injection',
    'tls': 'TLS/SSL Issue',
    'sri': 'Subresource Integrity (SRI) Missing',
  };
  return map[category] ?? category;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
}

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

/**
 * Build a SARIF v2.1.0 log from a SecBot scan result.
 */
export function buildSarifLog(result: ScanResult): SarifLog {
  // Collect unique categories from raw findings to build rules
  const categorySet = new Set<CheckCategory>();
  for (const finding of result.rawFindings) {
    categorySet.add(finding.category);
  }

  const rules: SarifRule[] = [...categorySet].map((category) => ({
    id: category,
    name: categoryToRuleName(category),
    shortDescription: { text: categoryToRuleName(category) },
    defaultConfiguration: {
      level: mapSeverityToLevel(
        result.rawFindings.find((f) => f.category === category)!.severity,
      ),
    },
  }));

  const results: SarifResult[] = result.rawFindings.map((finding) => ({
    ruleId: finding.category,
    level: mapSeverityToLevel(finding.severity),
    message: { text: `${finding.title}: ${finding.description}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.url },
        },
      },
    ],
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SecBot',
            version: sarifPkg.version,
            informationUri: 'https://github.com/odnamta/secbot',
            rules,
          },
        },
        results,
      },
    ],
  };
}

/**
 * Write a SARIF v2.1.0 report file from a SecBot scan result.
 */
export function writeSarifReport(result: ScanResult, outputPath: string): void {
  const sarifLog = buildSarifLog(result);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(sarifLog, null, 2), 'utf-8');
  log.info(`SARIF report written to: ${outputPath}`);
}

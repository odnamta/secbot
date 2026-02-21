import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ScanResult } from '../scanner/types.js';
import { log } from '../utils/logger.js';

/**
 * Escape XML special characters.
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Write scan results as JUnit XML for Jenkins/GitLab CI integration.
 *
 * Each check category becomes a test suite.
 * Each finding becomes a failed test case.
 * Checks that ran with 0 findings become passed test cases.
 */
export function writeJunitReport(result: ScanResult, outputPath: string): void {
  const findings = result.interpretedFindings;
  const checksRun = result.checksRun || [];

  // Group findings by category
  const findingsByCategory = new Map<string, typeof findings>();
  for (const finding of findings) {
    // Use first rawFindingId to determine category, or infer from title
    const category = inferCategory(finding.title);
    const existing = findingsByCategory.get(category) || [];
    existing.push(finding);
    findingsByCategory.set(category, existing);
  }

  // Determine passed checks (ran but no findings)
  const categoriesWithFindings = new Set(findingsByCategory.keys());
  const passedChecks = checksRun.filter(c => !categoriesWithFindings.has(c));

  const totalTests = findingsByCategory.size + passedChecks.length;
  const totalFailures = findings.length;
  const duration = (result.scanDuration / 1000).toFixed(2);

  let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
  xml += `<testsuites name="SecBot Security Scan" tests="${totalTests}" failures="${totalFailures}" time="${duration}">\n`;

  // Add test suites for categories with findings
  for (const [category, categoryFindings] of findingsByCategory) {
    xml += `  <testsuite name="${escapeXml(category)}" tests="${categoryFindings.length}" failures="${categoryFindings.length}" time="${duration}">\n`;
    for (const finding of categoryFindings) {
      xml += `    <testcase name="${escapeXml(finding.title)}" classname="secbot.${escapeXml(category)}">\n`;
      xml += `      <failure message="${escapeXml(finding.title)}" type="${escapeXml(finding.severity)}">\n`;
      xml += `${escapeXml(finding.description)}\n\n`;
      xml += `Severity: ${finding.severity}\n`;
      xml += `Confidence: ${finding.confidence}\n`;
      xml += `OWASP: ${finding.owaspCategory}\n`;
      xml += `URLs: ${finding.affectedUrls.join(', ')}\n`;
      if (finding.suggestedFix) {
        xml += `\nFix: ${escapeXml(finding.suggestedFix)}\n`;
      }
      xml += `      </failure>\n`;
      xml += `    </testcase>\n`;
    }
    xml += `  </testsuite>\n`;
  }

  // Add passed test suites
  for (const check of passedChecks) {
    xml += `  <testsuite name="${escapeXml(check)}" tests="1" failures="0" time="0">\n`;
    xml += `    <testcase name="No ${escapeXml(check)} findings" classname="secbot.${escapeXml(check)}" />\n`;
    xml += `  </testsuite>\n`;
  }

  xml += `</testsuites>\n`;

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, xml, 'utf-8');
  log.info(`JUnit XML report written to ${outputPath}`);
}

/**
 * Infer check category from finding title.
 */
function inferCategory(title: string): string {
  const titleLower = title.toLowerCase();
  if (titleLower.includes('xss') || titleLower.includes('cross-site scripting')) return 'xss';
  if (titleLower.includes('sql') || titleLower.includes('injection') && !titleLower.includes('command')) return 'sqli';
  if (titleLower.includes('cors')) return 'cors-misconfiguration';
  if (titleLower.includes('redirect')) return 'open-redirect';
  if (titleLower.includes('traversal')) return 'directory-traversal';
  if (titleLower.includes('ssrf')) return 'ssrf';
  if (titleLower.includes('ssti') || titleLower.includes('template')) return 'ssti';
  if (titleLower.includes('command') || titleLower.includes('cmdi')) return 'command-injection';
  if (titleLower.includes('idor') || titleLower.includes('insecure direct')) return 'idor';
  if (titleLower.includes('tls') || titleLower.includes('ssl') || titleLower.includes('certificate')) return 'tls';
  if (titleLower.includes('sri') || titleLower.includes('subresource')) return 'sri';
  if (titleLower.includes('header')) return 'security-headers';
  if (titleLower.includes('cookie')) return 'cookie-flags';
  if (titleLower.includes('leak') || titleLower.includes('disclosure')) return 'info-leakage';
  return 'other';
}

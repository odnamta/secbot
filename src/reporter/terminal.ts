import chalk from 'chalk';
import type { ScanResult, InterpretedFinding, Severity } from '../scanner/types.js';

export function printTerminalReport(result: ScanResult): void {
  console.log();
  console.log(chalk.bold('═══════════════════════════════════════════════'));
  console.log(chalk.bold('  SecBot Security Scan Report'));
  console.log(chalk.bold('═══════════════════════════════════════════════'));
  console.log();

  // Summary
  console.log(chalk.bold.underline('Summary'));
  console.log(`  Target:     ${result.targetUrl}`);
  console.log(`  Profile:    ${result.profile}`);
  console.log(`  Pages:      ${result.pagesScanned}`);
  console.log(`  Duration:   ${formatDuration(result.startedAt, result.completedAt)}`);
  console.log(`  Raw:        ${result.summary.totalRawFindings} findings`);
  console.log(`  Actionable: ${result.summary.totalInterpretedFindings} findings`);
  console.log();

  // Severity breakdown
  console.log(chalk.bold.underline('Severity Breakdown'));
  const { bySeverity } = result.summary;
  if (bySeverity.critical > 0) console.log(chalk.bgRed.white(`  CRITICAL  ${bySeverity.critical}`));
  if (bySeverity.high > 0) console.log(chalk.red(`  HIGH      ${bySeverity.high}`));
  if (bySeverity.medium > 0) console.log(chalk.yellow(`  MEDIUM    ${bySeverity.medium}`));
  if (bySeverity.low > 0) console.log(chalk.cyan(`  LOW       ${bySeverity.low}`));
  if (bySeverity.info > 0) console.log(chalk.gray(`  INFO      ${bySeverity.info}`));
  console.log();

  // Findings
  if (result.interpretedFindings.length === 0) {
    console.log(chalk.green('  No actionable vulnerabilities found!'));
    console.log();
    return;
  }

  console.log(chalk.bold.underline('Findings'));
  console.log();

  const sorted = [...result.interpretedFindings].sort(
    (a, b) => severityOrder(b.severity) - severityOrder(a.severity),
  );

  for (let i = 0; i < sorted.length; i++) {
    printFinding(i + 1, sorted[i]);
  }

  // Top priorities
  if (result.summary.topIssues.length > 0) {
    console.log(chalk.bold.underline('Top Priorities'));
    for (const issue of result.summary.topIssues) {
      console.log(`  ${chalk.yellow('→')} ${issue}`);
    }
    console.log();
  }
}

function printFinding(index: number, finding: InterpretedFinding): void {
  const sevColor = getSeverityColor(finding.severity);
  const badge = sevColor(`[${finding.severity.toUpperCase()}]`);
  const confidenceBadge = finding.confidence === 'high'
    ? chalk.green(`[${finding.confidence}]`)
    : finding.confidence === 'medium'
      ? chalk.yellow(`[${finding.confidence}]`)
      : chalk.gray(`[${finding.confidence}]`);

  console.log(`  ${chalk.bold(`#${index}`)} ${badge} ${confidenceBadge} ${chalk.bold(finding.title)}`);
  console.log(`     ${chalk.dim(finding.owaspCategory)}`);
  console.log();
  console.log(`     ${finding.description}`);
  console.log();
  console.log(`     ${chalk.bold('Impact:')} ${finding.impact}`);
  console.log();

  if (finding.affectedUrls?.length > 0) {
    console.log(`     ${chalk.bold('Affected URLs:')}`);
    for (const url of finding.affectedUrls.slice(0, 5)) {
      console.log(`       - ${chalk.dim(url)}`);
    }
    if (finding.affectedUrls.length > 5) {
      console.log(`       ${chalk.dim(`... and ${finding.affectedUrls.length - 5} more`)}`);
    }
    console.log();
  }

  if (finding.reproductionSteps?.length > 0) {
    console.log(`     ${chalk.bold('Reproduction Steps:')}`);
    for (const step of finding.reproductionSteps) {
      console.log(`       ${step}`);
    }
    console.log();
  }

  if (finding.suggestedFix) {
    console.log(`     ${chalk.bold('Suggested Fix:')}`);
    console.log(`     ${finding.suggestedFix}`);
  }

  if (finding.codeExample) {
    console.log();
    console.log(`     ${chalk.bold('Code Example:')}`);
    console.log(chalk.dim('     ```'));
    for (const line of finding.codeExample.split('\n')) {
      console.log(chalk.dim(`     ${line}`));
    }
    console.log(chalk.dim('     ```'));
  }

  console.log();
  console.log(chalk.dim('  ─────────────────────────────────────────'));
  console.log();
}

function getSeverityColor(severity: Severity) {
  switch (severity) {
    case 'critical': return chalk.bgRed.white;
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.cyan;
    case 'info': return chalk.gray;
  }
}

function severityOrder(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}

function formatDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

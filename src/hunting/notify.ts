import type { HuntSummary, EscalationItem } from './types.js';
import type { TriageResult } from './auto-triage.js';
import { appendFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

export interface TriageInfo {
  /** Per-program triage results from auto-staging */
  perProgram: Record<string, TriageResult>;
  /** Escalation items that need human review */
  escalationItems?: EscalationItem[];
}

export function formatHuntSummary(summary: HuntSummary, triageInfo?: TriageInfo): string {
  const parts: string[] = [];
  parts.push(`Hunt complete — ${summary.programs} programs scanned`);

  const total = summary.findings.high + summary.findings.medium + summary.findings.low;
  if (total > 0) {
    parts.push(`${total} findings (${summary.findings.high} high-confidence, ${summary.findings.medium} medium, ${summary.findings.low} low)`);
  } else {
    parts.push('No findings');
  }

  if (summary.escalations > 0) {
    parts.push(`${summary.escalations} need your help`);
  }

  parts.push(`Duration: ${summary.duration}`);

  // Append triage section if auto-triage was run
  if (triageInfo) {
    const triageLine = formatTriageLine(triageInfo);
    if (triageLine) {
      parts.push(triageLine);
    }
  }

  return parts.join(' | ');
}

/**
 * Format a detailed hunt notification with ACTION REQUIRED sections.
 * Used for file-based and future webhook notifications.
 */
export function formatDetailedNotification(summary: HuntSummary, triageInfo?: TriageInfo): string {
  const lines: string[] = [];

  lines.push('=== SecBot Hunt Report ===');
  lines.push(`Time: ${summary.scannedAt}`);
  lines.push(`Programs: ${summary.programs} | Duration: ${summary.duration}`);
  lines.push('');

  // Findings summary
  const total = summary.findings.high + summary.findings.medium + summary.findings.low;
  lines.push(`--- Findings: ${total} total ---`);
  lines.push(`  High-confidence: ${summary.findings.high}`);
  lines.push(`  Medium: ${summary.findings.medium}`);
  lines.push(`  Low: ${summary.findings.low}`);
  lines.push('');

  // Triage results per program
  if (triageInfo && Object.keys(triageInfo.perProgram).length > 0) {
    const totalStaged = Object.values(triageInfo.perProgram).reduce((sum, r) => sum + r.staged, 0);
    lines.push(`--- Pending Bounty Reports: ${totalStaged} staged ---`);
    for (const [program, result] of Object.entries(triageInfo.perProgram)) {
      if (result.staged > 0) {
        lines.push(`  ${program}: ${result.staged} new (${result.skippedDuplicate} dup, ${result.skippedLowConfidence} filtered)`);
      }
    }
    lines.push('');
  }

  // ACTION REQUIRED section
  const hasEscalations = summary.escalations > 0;
  const hasStaged = triageInfo && Object.values(triageInfo.perProgram).some(r => r.staged > 0);

  if (hasEscalations || hasStaged) {
    lines.push('*** ACTION REQUIRED ***');

    if (hasStaged) {
      const totalStaged = Object.values(triageInfo!.perProgram).reduce((sum, r) => sum + r.staged, 0);
      lines.push(`  [REVIEW] ${totalStaged} finding(s) staged in bounty-pool/pending/ — review and submit`);
    }

    if (hasEscalations) {
      lines.push(`  [ESCALATION] ${summary.escalations} item(s) need human intervention`);
      if (triageInfo?.escalationItems) {
        for (const item of triageInfo.escalationItems.slice(0, 5)) {
          lines.push(`    - ${item.reason}: ${item.url}`);
        }
        if (triageInfo.escalationItems.length > 5) {
          lines.push(`    - ... and ${triageInfo.escalationItems.length - 5} more`);
        }
      }
    }

    lines.push('');
  }

  lines.push('=== End Report ===');
  return lines.join('\n');
}

/**
 * Build a compact triage summary line for the one-line format.
 */
function formatTriageLine(triageInfo: TriageInfo): string | null {
  const totalStaged = Object.values(triageInfo.perProgram).reduce((sum, r) => sum + r.staged, 0);
  if (totalStaged === 0) return null;

  const programs = Object.entries(triageInfo.perProgram)
    .filter(([, r]) => r.staged > 0)
    .map(([name, r]) => `${name}:${r.staged}`)
    .join(', ');

  return `Staged: ${totalStaged} (${programs})`;
}

export async function sendNotification(summary: HuntSummary, triageInfo?: TriageInfo): Promise<boolean> {
  // Use detailed format for file-based notifications
  const message = triageInfo
    ? formatDetailedNotification(summary, triageInfo)
    : formatHuntSummary(summary);

  // Try Nara MCP via environment-configured endpoint
  // For now, always fall back to file-based notification
  const logDir = join(homedir(), '.secbot');
  const logPath = join(logDir, 'notifications.log');

  try {
    await mkdir(logDir, { recursive: true });
    const entry = `[${new Date().toISOString()}] ${message}\n`;
    await appendFile(logPath, entry);
    return true;
  } catch {
    return false;
  }
}

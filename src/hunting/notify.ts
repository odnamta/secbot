import type { HuntSummary } from './types.js';
import { appendFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

export function formatHuntSummary(summary: HuntSummary): string {
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

  return parts.join(' | ');
}

export async function sendNotification(summary: HuntSummary): Promise<boolean> {
  const message = formatHuntSummary(summary);

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

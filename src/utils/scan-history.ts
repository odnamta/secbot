import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { ScanResult, Severity } from '../scanner/types.js';
import { log } from './logger.js';

/**
 * A compact record of a single scan for trend tracking.
 */
export interface ScanHistoryEntry {
  id: string;
  targetUrl: string;
  timestamp: string;
  duration: number; // ms
  profile: string;
  pagesScanned: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  checksRun: string[];
  newFindings: number; // findings not in previous scan
  resolvedFindings: number; // findings in previous scan but not in this one
  exitCode: number;
}

/**
 * Full history file structure.
 */
export interface ScanHistory {
  version: 1;
  target: string;
  entries: ScanHistoryEntry[];
}

const HISTORY_VERSION = 1;

/**
 * Get the default history file path for a target URL.
 */
export function getHistoryPath(outputDir: string, targetUrl: string): string {
  const hostname = new URL(targetUrl).hostname.replace(/[^a-z0-9.-]/gi, '_');
  return join(outputDir, `secbot-history-${hostname}.json`);
}

/**
 * Load scan history from disk. Returns empty history if file doesn't exist.
 */
export function loadHistory(filePath: string): ScanHistory {
  if (!existsSync(filePath)) {
    return { version: HISTORY_VERSION, target: '', entries: [] };
  }

  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    if (parsed?.version === HISTORY_VERSION && Array.isArray(parsed.entries)) {
      return parsed as ScanHistory;
    }
  } catch (err) {
    log.debug(`Failed to load scan history: ${(err as Error).message}`);
  }

  return { version: HISTORY_VERSION, target: '', entries: [] };
}

/**
 * Save scan history to disk.
 */
export function saveHistory(history: ScanHistory, filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(history, null, 2), 'utf-8');
}

/**
 * Build a history entry from a scan result.
 * Compares against the previous entry to calculate new/resolved findings.
 */
export function buildHistoryEntry(
  result: ScanResult,
  previousEntry?: ScanHistoryEntry,
): ScanHistoryEntry {
  // Fingerprint current findings by category+url+title
  const currentFingerprints = new Set(
    result.rawFindings.map((f) => `${f.category}|${f.url}|${f.title}`),
  );

  // Fingerprint previous findings
  const previousFingerprints = previousEntry
    ? new Set(
        // Reconstruct fingerprints from the previous entry's summary
        // We don't store individual findings in history, so this is approximate
        [] as string[],
      )
    : new Set<string>();

  const newFindings = previousEntry
    ? currentFingerprints.size - Math.min(currentFingerprints.size, previousEntry.totalFindings)
    : currentFingerprints.size;

  const resolvedFindings = previousEntry
    ? Math.max(0, previousEntry.totalFindings - currentFingerprints.size)
    : 0;

  return {
    id: result.startedAt.replace(/[^0-9]/g, '').slice(0, 14),
    targetUrl: result.targetUrl,
    timestamp: result.startedAt,
    duration: result.scanDuration,
    profile: result.profile,
    pagesScanned: result.pagesScanned,
    totalFindings: result.rawFindings.length,
    bySeverity: result.summary.bySeverity,
    checksRun: result.checksRun,
    newFindings: Math.max(0, newFindings),
    resolvedFindings,
    exitCode: result.exitCode,
  };
}

/**
 * Add a scan result to history and return the updated history.
 * Keeps the last 100 entries.
 */
export function addToHistory(
  history: ScanHistory,
  result: ScanResult,
): ScanHistory {
  const previousEntry = history.entries[history.entries.length - 1];
  const entry = buildHistoryEntry(result, previousEntry);

  return {
    version: HISTORY_VERSION,
    target: result.targetUrl,
    entries: [...history.entries.slice(-99), entry], // Keep last 100
  };
}

/**
 * Generate a trend summary from scan history.
 */
export function getTrendSummary(history: ScanHistory): string {
  if (history.entries.length === 0) return 'No scan history available.';
  if (history.entries.length === 1) return 'First scan recorded — no trends yet.';

  const latest = history.entries[history.entries.length - 1];
  const previous = history.entries[history.entries.length - 2];
  const oldest = history.entries[0];

  const lines: string[] = [];
  lines.push(`Scan history: ${history.entries.length} scans since ${oldest.timestamp.split('T')[0]}`);

  // Finding trend
  const delta = latest.totalFindings - previous.totalFindings;
  if (delta > 0) {
    lines.push(`Findings: ${latest.totalFindings} (+${delta} from last scan)`);
  } else if (delta < 0) {
    lines.push(`Findings: ${latest.totalFindings} (${delta} from last scan — improving!)`);
  } else {
    lines.push(`Findings: ${latest.totalFindings} (unchanged)`);
  }

  // Severity trend
  const critHigh = (latest.bySeverity.critical || 0) + (latest.bySeverity.high || 0);
  const prevCritHigh = (previous.bySeverity.critical || 0) + (previous.bySeverity.high || 0);
  if (critHigh !== prevCritHigh) {
    lines.push(`Critical/High: ${critHigh} (was ${prevCritHigh})`);
  }

  // Duration trend
  if (latest.duration && previous.duration) {
    const durationDelta = ((latest.duration - previous.duration) / previous.duration * 100).toFixed(0);
    lines.push(`Scan duration: ${(latest.duration / 1000).toFixed(1)}s (${Number(durationDelta) > 0 ? '+' : ''}${durationDelta}%)`);
  }

  return lines.join('\n');
}

/**
 * Auto-triage pipeline — stages high-confidence findings to bounty-pool/pending/.
 *
 * After a hunt scan completes, qualifying findings are automatically formatted
 * as bounty markdown reports and saved for human review before submission.
 */

import { mkdirSync, writeFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { InterpretedFinding, RawFinding, Severity, EvidencePack } from '../scanner/types.js';
import { formatForHackerOne } from '../reporter/bounty-export.js';
import { log } from '../utils/logger.js';

export interface TriageResult {
  staged: number;
  skippedDuplicate: number;
  skippedLowConfidence: number;
}

/**
 * Severities that qualify for auto-staging to the bounty pool.
 * Low and info findings are not worth submitting.
 */
const BOUNTY_SEVERITIES: Set<Severity> = new Set(['critical', 'high', 'medium']);

/**
 * Auto-triage interpreted findings: filter for high-confidence medium+ severity,
 * check for duplicates against already-submitted reports, and stage qualifying
 * findings as markdown files in bounty-pool/pending/{program}/.
 */
export function autoTriageFindings(
  interpretedFindings: InterpretedFinding[],
  rawFindings: RawFinding[],
  programName: string,
  bountyPoolDir: string,
): TriageResult {
  const result: TriageResult = { staged: 0, skippedDuplicate: 0, skippedLowConfidence: 0 };
  const pendingDir = join(bountyPoolDir, 'pending', programName);
  mkdirSync(pendingDir, { recursive: true });

  for (const finding of interpretedFindings) {
    // Only stage high-confidence, medium+ severity
    if (finding.confidence !== 'high') {
      result.skippedLowConfidence++;
      continue;
    }
    if (!BOUNTY_SEVERITIES.has(finding.severity)) {
      result.skippedLowConfidence++;
      continue;
    }

    // Check for duplicate (same title slug in submitted/accepted dirs)
    if (isDuplicateOfSubmitted(finding, bountyPoolDir, programName)) {
      result.skippedDuplicate++;
      continue;
    }

    // Generate markdown report using the HackerOne formatter
    const md = formatFindingForBounty(finding, rawFindings);
    const id = finding.rawFindingIds[0] ?? 'unknown';
    const fileName = `${id.slice(0, 8)}-${slugify(finding.title)}.md`;
    writeFileSync(join(pendingDir, fileName), md);
    log.debug(`Staged finding: ${fileName}`);
    result.staged++;
  }

  if (result.staged > 0) {
    log.info(`Auto-triage: ${result.staged} finding(s) staged to ${pendingDir}`);
  }
  if (result.skippedDuplicate > 0) {
    log.debug(`Auto-triage: ${result.skippedDuplicate} skipped (already submitted)`);
  }

  return result;
}

/**
 * Check if a finding has already been submitted or accepted for this program.
 *
 * Dedup strategy:
 * 1. Slug match: if a file with the same title slug exists in submitted/ or accepted/
 * 2. URL match: if any file in those dirs contains the same primary affected URL
 */
export function isDuplicateOfSubmitted(
  finding: InterpretedFinding,
  bountyPoolDir: string,
  programName: string,
): boolean {
  const titleSlug = slugify(finding.title);
  const primaryUrl = finding.affectedUrls?.[0];

  for (const subdir of ['submitted', 'accepted']) {
    const dir = join(bountyPoolDir, subdir, programName);
    if (!existsSync(dir)) continue;

    let files: string[];
    try {
      files = readdirSync(dir).filter(f => f.endsWith('.md'));
    } catch {
      continue;
    }

    for (const file of files) {
      // Strategy 1: slug match in filename
      // Files are named like "{id}-{title-slug}.md"
      if (file.includes(titleSlug)) {
        return true;
      }

      // Strategy 2: URL match — check if the file contains the same primary URL
      if (primaryUrl) {
        try {
          const content = readFileSync(join(dir, file), 'utf-8');
          if (content.includes(primaryUrl)) {
            return true;
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  return false;
}

/**
 * Format a single finding as a standalone bounty markdown report.
 * Uses the HackerOne formatter as the base, with a header banner.
 */
export function formatFindingForBounty(
  finding: InterpretedFinding,
  rawFindings: RawFinding[],
): string {
  const lines: string[] = [];

  // Header metadata
  lines.push('<!-- Auto-triaged by SecBot -->');
  lines.push(`<!-- Staged: ${new Date().toISOString()} -->`);
  lines.push(`<!-- Confidence: ${finding.confidence} | Severity: ${finding.severity} -->`);
  lines.push('');

  // Use the existing HackerOne formatter for the body
  const body = formatForHackerOne(finding, { rawFindings });
  lines.push(body);

  return lines.join('\n');
}

/**
 * Convert a string to a URL/filename-safe slug.
 */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

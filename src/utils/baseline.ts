import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RawFinding } from '../scanner/types.js';

export interface BaselineFinding {
  fingerprint: string;
  category: string;
  url: string;
  title: string;
  firstSeen: string;
}

/**
 * Generate a deterministic fingerprint for a finding based on
 * category + url + title. Ignores timestamp, id, and other volatile fields.
 */
export function generateFindingFingerprint(finding: RawFinding): string {
  const data = `${finding.category}|${finding.url}|${finding.title}`;
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Load a baseline file from disk. Returns an array of BaselineFinding.
 * Throws if the file cannot be read or parsed.
 */
export function loadBaseline(filePath: string): BaselineFinding[] {
  const raw = readFileSync(filePath, 'utf-8');
  const parsed = JSON.parse(raw);

  if (!Array.isArray(parsed)) {
    throw new Error('Baseline file must contain a JSON array');
  }

  return parsed as BaselineFinding[];
}

/**
 * Compare current findings against a baseline and return only new findings
 * (those whose fingerprint does not appear in the baseline).
 */
export function diffFindings(
  current: RawFinding[],
  baseline: BaselineFinding[],
): RawFinding[] {
  const baselineFingerprints = new Set(baseline.map((b) => b.fingerprint));

  return current.filter((finding) => {
    const fingerprint = generateFindingFingerprint(finding);
    return !baselineFingerprints.has(fingerprint);
  });
}

/**
 * Save the current findings as a baseline JSON file.
 * Each finding is stored as a BaselineFinding with its fingerprint.
 */
export function saveBaseline(findings: RawFinding[], filePath: string): void {
  const baselineEntries: BaselineFinding[] = findings.map((f) => ({
    fingerprint: generateFindingFingerprint(f),
    category: f.category,
    url: f.url,
    title: f.title,
    firstSeen: f.timestamp,
  }));

  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(baselineEntries, null, 2), 'utf-8');
}

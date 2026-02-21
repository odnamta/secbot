import type { RawFinding } from '../scanner/types.js';

/**
 * Deduplicate raw findings by (category, severity, title).
 * Collapses identical findings across multiple URLs into one finding
 * with an affectedUrls array. Keeps the first finding's details.
 */
export function deduplicateFindings(findings: RawFinding[]): RawFinding[] {
  const groups = new Map<string, RawFinding[]>();

  for (const finding of findings) {
    const key = `${finding.category}|${finding.severity}|${finding.title}`;
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }

  return Array.from(groups.values()).map((group) => {
    const primary = group[0];
    const urls = [...new Set(group.map((f) => f.url))];
    return {
      ...primary,
      affectedUrls: urls,
    };
  });
}

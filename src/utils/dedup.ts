import type { RawFinding, Confidence } from '../scanner/types.js';

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/**
 * Deduplicate raw findings by (category, severity, title).
 * Collapses identical findings across multiple URLs into one finding
 * with an affectedUrls array. Keeps the first finding's details.
 * Preserves the highest confidence level when merging.
 * Defaults missing confidence to 'medium'.
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

    // Pick highest confidence across merged findings (default: medium)
    let bestConfidence: Confidence = (primary.confidence as Confidence) ?? 'medium';
    for (const f of group) {
      const c = (f.confidence as Confidence) ?? 'medium';
      if (CONFIDENCE_RANK[c] > CONFIDENCE_RANK[bestConfidence]) {
        bestConfidence = c;
      }
    }

    return {
      ...primary,
      confidence: bestConfidence,
      affectedUrls: urls,
    };
  });
}

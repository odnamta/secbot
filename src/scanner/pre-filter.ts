import type { RawFinding, Confidence } from './types.js';

const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export interface PreFilterResult {
  passed: RawFinding[];
  dropped: RawFinding[];
}

export function preFilterFindings(
  findings: RawFinding[],
  minConfidence: Confidence = 'medium',
): PreFilterResult {
  const threshold = CONFIDENCE_ORDER[minConfidence];
  const passed: RawFinding[] = [];
  const dropped: RawFinding[] = [];
  for (const f of findings) {
    const level = CONFIDENCE_ORDER[(f.confidence as Confidence) ?? 'medium'];
    if (level >= threshold) {
      passed.push(f);
    } else {
      dropped.push(f);
    }
  }
  return { passed, dropped };
}

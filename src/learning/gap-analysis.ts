import type { ScanResult, CheckAuditEntry } from '../scanner/types.js';
import { log } from '../utils/logger.js';

export interface GapAnalysisResult {
  /** Checks that ran but found nothing — might be FPs or might indicate gaps */
  silentChecks: string[];
  /** Checks that failed/timed out — couldn't even test */
  failedChecks: Array<{ name: string; error: string }>;
  /** Checks that were skipped (excluded or WAF-blocked) */
  skippedChecks: string[];
  /** Surface coverage: how much of the attack surface was tested */
  surfaceCoverage: {
    pagesScanned: number;
    apiEndpoints: number;
    formsFound: number;
    paramsDiscovered: number;
    subdomainsFound: number;
  };
  /** Detection depth per category */
  categoryDepth: Record<string, 'deep' | 'shallow' | 'none'>;
  /** Actionable suggestions for improving detection */
  suggestions: string[];
  /** Overall scan quality score (0-100) */
  qualityScore: number;
}

/**
 * Analyze scan results to identify detection gaps and improvement opportunities.
 */
export function analyzeGaps(result: ScanResult): GapAnalysisResult {
  const audit = result.checkAudit ?? [];

  // Categorize checks
  const completed = audit.filter(a => a.status === 'completed');
  const failed = audit.filter(a => a.status === 'failed');
  const skipped = audit.filter(a => a.status === 'skipped');
  const silentChecks = completed.filter(a => a.findingsCount === 0).map(a => a.name);

  // Surface coverage
  const surfaceCoverage = {
    pagesScanned: result.pagesScanned,
    apiEndpoints: result.recon?.endpoints?.apiRoutes?.length ?? 0,
    formsFound: result.recon?.endpoints?.forms?.length ?? 0,
    paramsDiscovered: 0,
    subdomainsFound: 0,
  };

  // Category depth — based on duration and whether findings were produced
  const categoryDepth: Record<string, 'deep' | 'shallow' | 'none'> = {};
  for (const check of completed) {
    const depth = check.durationMs > 30000 ? 'deep' : check.durationMs > 5000 ? 'shallow' : 'none';
    categoryDepth[check.name] = check.findingsCount > 0 ? 'deep' : depth;
  }
  for (const check of failed) {
    categoryDepth[check.name] = 'none';
  }

  // Generate suggestions
  const suggestions = generateSuggestions(result, completed, failed, surfaceCoverage);

  // Quality score
  const qualityScore = calculateQualityScore(result, completed, failed, skipped, surfaceCoverage);

  return {
    silentChecks,
    failedChecks: failed.map(f => ({ name: f.name, error: f.error ?? 'unknown' })),
    skippedChecks: skipped.map(s => s.name),
    surfaceCoverage,
    categoryDepth,
    suggestions,
    qualityScore,
  };
}

function generateSuggestions(
  result: ScanResult,
  completed: CheckAuditEntry[],
  failed: CheckAuditEntry[],
  surfaceCoverage: GapAnalysisResult['surfaceCoverage'],
): string[] {
  const suggestions: string[] = [];

  if (surfaceCoverage.pagesScanned < 5) {
    suggestions.push('Low page count — consider authenticated scanning (--auth) to access more pages');
  }
  if (surfaceCoverage.apiEndpoints === 0) {
    suggestions.push('No API endpoints discovered — try JS analysis or content discovery with API wordlists');
  }
  if (surfaceCoverage.formsFound === 0) {
    suggestions.push('No forms found — injection checks (XSS, SQLi, SSTI) had no targets');
  }
  if (failed.length > 0 && failed.length > completed.length * 0.3) {
    suggestions.push(`${failed.length} checks failed — consider increasing timeout or using standard profile`);
  }
  if (failed.some(f => f.error?.includes('timed out'))) {
    suggestions.push('Timeout issues detected — increase --timeout or use fewer max-pages');
  }
  if (result.rawFindings.length === 0) {
    suggestions.push('Zero findings — target may be well-secured, or scanner needs authenticated access');
  }

  // Tech-stack-specific suggestions
  const tech = result.recon?.techStack?.detected ?? [];
  if (tech.some(t => /wordpress/i.test(t)) && !completed.some(c => c.name === 'sqli' && c.findingsCount > 0)) {
    suggestions.push('WordPress detected but no SQLi found — try deep profile with /wp-json/ endpoints');
  }
  if (tech.some(t => /graphql/i.test(t)) && !completed.some(c => c.name === 'graphql' && c.findingsCount > 0)) {
    suggestions.push('GraphQL detected but no issues found — check introspection and depth limits manually');
  }

  return suggestions;
}

export function calculateQualityScore(
  result: ScanResult,
  completed: CheckAuditEntry[],
  failed: CheckAuditEntry[],
  skipped: CheckAuditEntry[],
  surface: GapAnalysisResult['surfaceCoverage'],
): number {
  let score = 0;

  // Check completion rate (40 points max)
  const total = completed.length + failed.length + skipped.length;
  if (total > 0) score += Math.round((completed.length / total) * 40);

  // Surface coverage (30 points max)
  if (surface.pagesScanned >= 10) score += 10;
  else if (surface.pagesScanned >= 5) score += 5;
  if (surface.apiEndpoints > 0) score += 10;
  if (surface.formsFound > 0) score += 10;

  // Finding quality (30 points max)
  const highFindings = result.rawFindings.filter(f => f.confidence === 'high').length;
  if (highFindings > 0) score += 15;
  if (result.rawFindings.length > 0 && result.rawFindings.length < 50) score += 15; // not too noisy

  return Math.min(100, score);
}

/**
 * Format gap analysis as human-readable report.
 */
export function formatGapReport(analysis: GapAnalysisResult): string {
  const lines: string[] = [];
  lines.push(`\n=== Scan Quality Report (Score: ${analysis.qualityScore}/100) ===\n`);

  if (analysis.failedChecks.length > 0) {
    lines.push(`Failed checks (${analysis.failedChecks.length}):`);
    for (const f of analysis.failedChecks.slice(0, 5)) {
      lines.push(`  x ${f.name}: ${f.error.slice(0, 60)}`);
    }
  }

  if (analysis.suggestions.length > 0) {
    lines.push(`\nSuggestions:`);
    for (const s of analysis.suggestions) {
      lines.push(`  -> ${s}`);
    }
  }

  lines.push(`\nSurface: ${analysis.surfaceCoverage.pagesScanned} pages, ${analysis.surfaceCoverage.apiEndpoints} API endpoints, ${analysis.surfaceCoverage.formsFound} forms`);

  return lines.join('\n');
}

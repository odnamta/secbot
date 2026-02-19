import type {
  RawFinding,
  ValidatedFinding,
  ReconResult,
  InterpretedFinding,
  ScanSummary,
} from '../scanner/types.js';
import { askClaude, parseJsonResponse } from './client.js';
import { REPORTER_SYSTEM_PROMPT, buildReporterUserPrompt } from './prompts.js';
import { fallbackInterpretation } from './fallback.js';
import { log } from '../utils/logger.js';

interface ReportResult {
  findings: InterpretedFinding[];
  summary: ScanSummary;
}

/**
 * Use AI to generate the final interpreted report.
 * Filters to only validated findings before sending to Claude.
 * Falls back to rule-based interpretation if AI unavailable.
 */
export async function generateReport(
  url: string,
  rawFindings: RawFinding[],
  validations: ValidatedFinding[],
  recon: ReconResult,
): Promise<ReportResult> {
  // Filter to only validated findings
  const validIds = new Set(validations.filter((v) => v.isValid).map((v) => v.findingId));
  const validFindings = rawFindings.filter((f) => validIds.has(f.id));

  if (validFindings.length === 0) {
    log.info('No validated findings — generating empty report');
    return fallbackInterpretation([]);
  }

  log.info(`Generating AI report for ${validFindings.length} validated findings...`);

  const userPrompt = buildReporterUserPrompt(url, rawFindings, validations, recon);
  const response = await askClaude(REPORTER_SYSTEM_PROMPT, userPrompt, { maxTokens: 8192 });

  if (response) {
    const parsed = parseJsonResponse<ReportResult>(response);
    if (parsed?.findings && parsed?.summary) {
      log.info(
        `AI report: ${rawFindings.length} raw → ${validFindings.length} validated → ${parsed.findings.length} actionable`,
      );
      return parsed;
    }
    log.warn('AI reporter returned invalid JSON — using fallback');
  } else {
    log.info('AI unavailable — using rule-based report generation');
  }

  return fallbackInterpretation(validFindings);
}

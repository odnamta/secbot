import type {
  RawFinding,
  ValidatedFinding,
  ReconResult,
  InterpretedFinding,
  ScanSummary,
} from '../scanner/types.js';
import { askClaude, parseJsonResponse } from './client.js';
import { REPORTER_SYSTEM_PROMPT, buildReporterUserPrompt, buildReducedReporterUserPrompt } from './prompts.js';
import { fallbackInterpretation } from './fallback.js';
import { log } from '../utils/logger.js';
import { getCvssForFinding, inferCategoryFromTitle } from '../utils/cvss.js';
import { generateCurlCommand } from '../utils/evidence.js';

interface ReportResult {
  findings: InterpretedFinding[];
  summary: ScanSummary;
}

/**
 * Enrich InterpretedFindings with curlCommand, cvssScore, cvssVector, and detectionMethod
 * by correlating each finding back to its raw findings.
 */
function enrichInterpretedFindings(
  findings: InterpretedFinding[],
  rawFindings: RawFinding[],
): InterpretedFinding[] {
  const rawById = new Map(rawFindings.map(r => [r.id, r]));

  for (const finding of findings) {
    const matchingRaw = finding.rawFindingIds
      .map(id => rawById.get(id))
      .filter((r): r is RawFinding => r !== undefined);
    const bestRaw = matchingRaw[0];
    if (bestRaw) {
      finding.curlCommand = bestRaw.evidencePack?.curlCommand ?? generateCurlCommand(bestRaw);
      finding.detectionMethod = bestRaw.evidencePack?.detectionMethod;
      const category = bestRaw.category;
      const cvss = getCvssForFinding(category, finding.severity);
      finding.cvssScore = cvss.score;
      finding.cvssVector = cvss.vector;
    } else {
      // No raw finding match — infer category from title for CVSS
      const category = inferCategoryFromTitle(finding.title);
      const cvss = getCvssForFinding(category, finding.severity);
      finding.cvssScore = cvss.score;
      finding.cvssVector = cvss.vector;
    }
  }

  return findings;
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
  passedChecks?: string[],
): Promise<ReportResult> {
  // Filter to only validated findings
  const validIds = new Set(validations.filter((v) => v.isValid).map((v) => v.findingId));
  const validFindings = rawFindings.filter((f) => validIds.has(f.id));

  if (validFindings.length === 0) {
    log.info('No validated findings — generating empty report');
    return fallbackInterpretation([], passedChecks);
  }

  log.info(`Generating AI report for ${validFindings.length} validated findings...`);

  const userPrompt = buildReporterUserPrompt(url, rawFindings, validations, recon, passedChecks);
  const response = await askClaude(REPORTER_SYSTEM_PROMPT, userPrompt, {
    maxTokens: 16384,
    timeout: 120000,
  });

  if (response) {
    const parsed = parseJsonResponse<ReportResult>(response);
    if (parsed?.findings && parsed?.summary) {
      if (passedChecks) {
        parsed.summary.passedChecks = passedChecks;
      }
      enrichInterpretedFindings(parsed.findings, rawFindings);
      log.info(
        `AI report: ${rawFindings.length} raw → ${validFindings.length} validated → ${parsed.findings.length} actionable`,
      );
      return parsed;
    }

    // Retry with reduced prompt (no code examples, shorter descriptions)
    log.warn('AI reporter returned invalid JSON — retrying with reduced prompt...');
    const reducedPrompt = buildReducedReporterUserPrompt(url, rawFindings, validations, recon, passedChecks);
    const retryResponse = await askClaude(REPORTER_SYSTEM_PROMPT, reducedPrompt, {
      maxTokens: 8192,
      timeout: 60000,
    });

    if (retryResponse) {
      const retryParsed = parseJsonResponse<ReportResult>(retryResponse);
      if (retryParsed?.findings && retryParsed?.summary) {
        if (passedChecks) {
          retryParsed.summary.passedChecks = passedChecks;
        }
        enrichInterpretedFindings(retryParsed.findings, rawFindings);
        log.info(
          `AI report (retry): ${rawFindings.length} raw → ${validFindings.length} validated → ${retryParsed.findings.length} actionable`,
        );
        return retryParsed;
      }
    }

    log.warn('AI reporter retry also failed — using fallback');
  } else {
    log.warn('AI unavailable — using rule-based report generation (set ANTHROPIC_API_KEY for AI-powered reports)');
  }

  const fallbackResult = fallbackInterpretation(validFindings, passedChecks);
  enrichInterpretedFindings(fallbackResult.findings, rawFindings);
  return fallbackResult;
}

import type { RawFinding, ReconResult, ValidatedFinding } from '../scanner/types.js';
import { askClaude, parseJsonResponse } from './client.js';
import { VALIDATOR_SYSTEM_PROMPT, buildValidatorUserPrompt } from './prompts.js';
import { log } from '../utils/logger.js';
import { AICache } from '../utils/ai-cache.js';

const aiCache = new AICache();

const BATCH_SIZE = 10;

/**
 * Use AI to validate each finding as a real vulnerability or false positive.
 * Batches findings in groups of 10 per API call.
 * Falls back to marking all findings as valid with medium confidence.
 */
export async function validateFindings(
  url: string,
  findings: RawFinding[],
  recon: ReconResult,
): Promise<ValidatedFinding[]> {
  if (findings.length === 0) return [];

  log.info(`Validating ${findings.length} findings with AI...`);

  const allValidations: ValidatedFinding[] = [];

  // Process in batches
  for (let i = 0; i < findings.length; i += BATCH_SIZE) {
    const batch = findings.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(findings.length / BATCH_SIZE);

    if (totalBatches > 1) {
      log.info(`Validating batch ${batchNum}/${totalBatches} (${batch.length} findings)...`);
    }

    try {
      // Build a cache key from each finding's category + URL + evidence
      const batchHash = aiCache.generateKey({
        findings: batch.map((f) => ({ category: f.category, url: f.url, evidence: f.evidence })),
      });
      const cacheKey = aiCache.generateKey({ type: 'validator', batchHash });

      // Check cache before making an API call
      const cached = await aiCache.get(cacheKey);
      if (cached) {
        const parsed = parseJsonResponse<{ validations: ValidatedFinding[] }>(cached);
        if (parsed?.validations) {
          log.info(`Using cached validation for batch ${batchNum}`);
          allValidations.push(...parsed.validations);
          continue;
        }
      }

      const userPrompt = buildValidatorUserPrompt(url, batch, recon);
      const response = await askClaude(VALIDATOR_SYSTEM_PROMPT, userPrompt);

      if (response) {
        const parsed = parseJsonResponse<{ validations: ValidatedFinding[] }>(response);
        if (parsed?.validations) {
          // Cache the raw response for future runs
          await aiCache.set(cacheKey, response);
          allValidations.push(...parsed.validations);
          continue;
        }
        log.warn('AI validator returned invalid JSON — using fallback for this batch');
      }
    } catch (err) {
      log.warn(`Validator batch ${batchNum} failed: ${(err as Error).message} — using fallback`);
    }

    // Fallback: mark all as valid with medium confidence
    allValidations.push(...fallbackValidation(batch));
  }

  const validCount = allValidations.filter((v) => v.isValid).length;
  const invalidCount = allValidations.filter((v) => !v.isValid).length;
  log.info(`Validation complete: ${validCount} valid, ${invalidCount} false positives filtered`);

  return allValidations;
}

function fallbackValidation(findings: RawFinding[]): ValidatedFinding[] {
  return findings.map((f) => ({
    findingId: f.id,
    isValid: true,
    confidence: 'medium' as const,
    reasoning: 'AI unavailable — marked as valid by default',
  }));
}

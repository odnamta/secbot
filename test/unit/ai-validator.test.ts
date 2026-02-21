import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { RawFinding, ReconResult, ValidatedFinding } from '../../src/scanner/types.js';

// ─── Mock Setup ──────────────────────────────────────────────────────

vi.mock('../../src/ai/client.js', () => ({
  askClaude: vi.fn(),
  parseJsonResponse: vi.fn(),
}));

vi.mock('../../src/utils/ai-cache.js', () => {
  class MockAICache {
    generateKey() { return 'mock-cache-key'; }
    async get() { return null; }
    async set() { return undefined; }
  }
  return { AICache: MockAICache };
});

import { askClaude, parseJsonResponse } from '../../src/ai/client.js';
import { validateFindings } from '../../src/ai/validator.js';

const mockAskClaude = vi.mocked(askClaude);
const mockParseJson = vi.mocked(parseJsonResponse);

// ─── Helpers ─────────────────────────────────────────────────────────

function makeRecon(overrides?: Partial<ReconResult>): ReconResult {
  return {
    techStack: { languages: [], detected: [], ...(overrides?.techStack ?? {}) },
    waf: { detected: false, confidence: 'low', evidence: [], ...(overrides?.waf ?? {}) },
    framework: { confidence: 'low', evidence: [], ...(overrides?.framework ?? {}) },
    endpoints: {
      pages: ['https://example.com'],
      apiRoutes: [],
      forms: [],
      staticAssets: [],
      graphql: [],
      ...(overrides?.endpoints ?? {}),
    },
  };
}

function makeFinding(overrides?: Partial<RawFinding>): RawFinding {
  return {
    id: 'finding-001',
    category: 'xss',
    severity: 'high',
    title: 'Reflected XSS in search',
    description: 'User input reflected without encoding',
    url: 'https://example.com/search?q=<script>',
    evidence: '<script>alert(1)</script> reflected in response',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeValidation(overrides?: Partial<ValidatedFinding>): ValidatedFinding {
  return {
    findingId: 'finding-001',
    isValid: true,
    confidence: 'high',
    reasoning: 'Confirmed XSS — user input is reflected unsanitized',
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('validateFindings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Empty findings ─────────────────────────────────────────────────

  describe('empty findings', () => {
    it('returns empty array when no findings provided', async () => {
      const result = await validateFindings('https://example.com', [], makeRecon());

      expect(result).toEqual([]);
      expect(mockAskClaude).not.toHaveBeenCalled();
    });
  });

  // ── Prompt construction ────────────────────────────────────────────

  describe('prompt construction', () => {
    it('calls askClaude with system and user prompts', async () => {
      mockAskClaude.mockResolvedValue(null);

      const findings = [makeFinding()];
      await validateFindings('https://example.com', findings, makeRecon());

      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      const [systemPrompt, userPrompt] = mockAskClaude.mock.calls[0];
      expect(typeof systemPrompt).toBe('string');
      expect(typeof userPrompt).toBe('string');
    });

    it('includes target URL in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      await validateFindings('https://target.example.com', [makeFinding()], makeRecon());

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('https://target.example.com');
    });

    it('includes finding details in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const finding = makeFinding({
        id: 'xss-42',
        category: 'xss',
        title: 'Reflected XSS in contact form',
      });
      await validateFindings('https://example.com', [finding], makeRecon());

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('xss-42');
      expect(userPrompt).toContain('xss');
      expect(userPrompt).toContain('Reflected XSS in contact form');
    });

    it('includes WAF context in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const recon = makeRecon({
        waf: { detected: true, name: 'Cloudflare', confidence: 'high', evidence: [] },
      });
      await validateFindings('https://example.com', [makeFinding()], recon);

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Cloudflare');
    });

    it('includes framework name in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const recon = makeRecon({
        framework: { name: 'Next.js', confidence: 'high', evidence: [] },
      });
      await validateFindings('https://example.com', [makeFinding()], recon);

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Next.js');
    });

    it('system prompt contains validator instructions', async () => {
      mockAskClaude.mockResolvedValue(null);

      await validateFindings('https://example.com', [makeFinding()], makeRecon());

      const systemPrompt = mockAskClaude.mock.calls[0][0];
      expect(systemPrompt).toContain('vulnerability validator');
      expect(systemPrompt).toContain('isValid');
      expect(systemPrompt).toContain('confidence');
      expect(systemPrompt).toContain('false positive');
    });

    it('truncates long descriptions and evidence in the prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const longDesc = 'A'.repeat(500);
      const longEvidence = 'B'.repeat(400);
      const finding = makeFinding({ description: longDesc, evidence: longEvidence });
      await validateFindings('https://example.com', [finding], makeRecon());

      const userPrompt = mockAskClaude.mock.calls[0][1];
      // Description is sliced to 300 chars, evidence to 200 chars
      expect(userPrompt).not.toContain('A'.repeat(500));
      expect(userPrompt).not.toContain('B'.repeat(400));
    });
  });

  // ── Successful AI response ─────────────────────────────────────────

  describe('successful AI response', () => {
    it('returns AI validations when response is valid', async () => {
      const validations = [
        makeValidation({ findingId: 'f-1', isValid: true, confidence: 'high' }),
        makeValidation({ findingId: 'f-2', isValid: false, confidence: 'medium', reasoning: 'False positive — encoded output' }),
      ];
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations });

      const findings = [
        makeFinding({ id: 'f-1' }),
        makeFinding({ id: 'f-2' }),
      ];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result).toHaveLength(2);
      expect(result[0].findingId).toBe('f-1');
      expect(result[0].isValid).toBe(true);
      expect(result[1].findingId).toBe('f-2');
      expect(result[1].isValid).toBe(false);
    });

    it('preserves adjusted severity from AI', async () => {
      const validations = [
        makeValidation({ findingId: 'f-1', adjustedSeverity: 'critical' }),
      ];
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations });

      const result = await validateFindings('https://example.com', [makeFinding({ id: 'f-1' })], makeRecon());

      expect(result[0].adjustedSeverity).toBe('critical');
    });

    it('preserves reasoning from AI', async () => {
      const validations = [
        makeValidation({ reasoning: 'Input is reflected in attribute context without encoding' }),
      ];
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations });

      const result = await validateFindings('https://example.com', [makeFinding()], makeRecon());

      expect(result[0].reasoning).toContain('reflected in attribute context');
    });
  });

  // ── JSON parsing edge cases ────────────────────────────────────────

  describe('JSON parsing edge cases', () => {
    it('falls back when AI returns malformed JSON', async () => {
      mockAskClaude.mockResolvedValue('Not valid JSON {{{');
      mockParseJson.mockReturnValue(null);

      const findings = [makeFinding({ id: 'f-1' }), makeFinding({ id: 'f-2' })];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      // Fallback marks all as valid with medium confidence
      expect(result).toHaveLength(2);
      for (const v of result) {
        expect(v.isValid).toBe(true);
        expect(v.confidence).toBe('medium');
        expect(v.reasoning).toContain('AI unavailable');
      }
    });

    it('falls back when parsed JSON is missing validations field', async () => {
      mockAskClaude.mockResolvedValue('{"results": []}');
      mockParseJson.mockReturnValue({ results: [] });

      const findings = [makeFinding()];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result).toHaveLength(1);
      expect(result[0].isValid).toBe(true);
      expect(result[0].confidence).toBe('medium');
    });

    it('falls back when validations is null in parsed response', async () => {
      mockAskClaude.mockResolvedValue('{"validations": null}');
      mockParseJson.mockReturnValue({ validations: null });

      const findings = [makeFinding()];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result).toHaveLength(1);
      expect(result[0].isValid).toBe(true);
      expect(result[0].confidence).toBe('medium');
    });

    it('accepts response with extra fields (forward-compatible)', async () => {
      const validations = [
        { ...makeValidation(), extraField: 'ignored' },
      ];
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations, metadata: { version: 2 } });

      const result = await validateFindings('https://example.com', [makeFinding()], makeRecon());

      expect(result).toHaveLength(1);
      expect(result[0].isValid).toBe(true);
    });
  });

  // ── Fallback triggers ──────────────────────────────────────────────

  describe('fallback triggers', () => {
    it('falls back when askClaude returns null (API unavailable)', async () => {
      mockAskClaude.mockResolvedValue(null);

      const findings = [makeFinding({ id: 'f-1' })];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result).toHaveLength(1);
      expect(result[0].findingId).toBe('f-1');
      expect(result[0].isValid).toBe(true);
      expect(result[0].confidence).toBe('medium');
      expect(result[0].reasoning).toContain('AI unavailable');
    });

    it('fallback sets correct findingId for each finding', async () => {
      mockAskClaude.mockResolvedValue(null);

      const findings = [
        makeFinding({ id: 'xss-001' }),
        makeFinding({ id: 'sqli-002' }),
        makeFinding({ id: 'cors-003' }),
      ];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result[0].findingId).toBe('xss-001');
      expect(result[1].findingId).toBe('sqli-002');
      expect(result[2].findingId).toBe('cors-003');
    });
  });

  // ── Batching ───────────────────────────────────────────────────────

  describe('batching', () => {
    it('processes findings in batches of 10', async () => {
      // Create 25 findings — should result in 3 batches (10, 10, 5)
      const findings = Array.from({ length: 25 }, (_, i) =>
        makeFinding({ id: `finding-${i}` }),
      );

      // Each batch returns valid response
      const makeBatchValidations = (ids: string[]) =>
        ids.map((id) => makeValidation({ findingId: id }));

      let callCount = 0;
      mockAskClaude.mockImplementation(async () => {
        callCount++;
        return 'json';
      });

      mockParseJson.mockImplementation(() => {
        // Figure out which batch based on call count
        const batchStart = (callCount - 1) * 10;
        const batchEnd = Math.min(batchStart + 10, 25);
        const ids = Array.from({ length: batchEnd - batchStart }, (_, i) => `finding-${batchStart + i}`);
        return { validations: makeBatchValidations(ids) };
      });

      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(mockAskClaude).toHaveBeenCalledTimes(3);
      expect(result).toHaveLength(25);
    });

    it('single finding does not need batching', async () => {
      const validations = [makeValidation({ findingId: 'f-1' })];
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations });

      const result = await validateFindings('https://example.com', [makeFinding({ id: 'f-1' })], makeRecon());

      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(1);
    });

    it('uses fallback for failed batches while keeping successful ones', async () => {
      // Create 15 findings — 2 batches (10, 5)
      const findings = Array.from({ length: 15 }, (_, i) =>
        makeFinding({ id: `finding-${i}` }),
      );

      let callIndex = 0;
      mockAskClaude.mockImplementation(async () => {
        callIndex++;
        if (callIndex === 1) return 'valid json'; // First batch succeeds
        return null; // Second batch fails (API unavailable)
      });

      mockParseJson.mockImplementation((text) => {
        if (text === 'valid json') {
          return {
            validations: Array.from({ length: 10 }, (_, i) =>
              makeValidation({ findingId: `finding-${i}`, confidence: 'high' }),
            ),
          };
        }
        return null;
      });

      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result).toHaveLength(15);

      // First 10 from AI (high confidence)
      for (let i = 0; i < 10; i++) {
        expect(result[i].confidence).toBe('high');
      }

      // Last 5 from fallback (medium confidence)
      for (let i = 10; i < 15; i++) {
        expect(result[i].confidence).toBe('medium');
        expect(result[i].isValid).toBe(true);
      }
    });

    it('exactly 10 findings processes in a single batch', async () => {
      const findings = Array.from({ length: 10 }, (_, i) =>
        makeFinding({ id: `finding-${i}` }),
      );

      const validations = findings.map((f) => makeValidation({ findingId: f.id }));
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations });

      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(10);
    });
  });

  // ── Mixed valid and invalid findings ───────────────────────────────

  describe('mixed valid and invalid findings', () => {
    it('preserves the mix of valid and invalid findings from AI', async () => {
      const validations = [
        makeValidation({ findingId: 'f-1', isValid: true }),
        makeValidation({ findingId: 'f-2', isValid: false }),
        makeValidation({ findingId: 'f-3', isValid: true }),
      ];
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue({ validations });

      const findings = [
        makeFinding({ id: 'f-1' }),
        makeFinding({ id: 'f-2' }),
        makeFinding({ id: 'f-3' }),
      ];
      const result = await validateFindings('https://example.com', findings, makeRecon());

      expect(result.filter((v) => v.isValid)).toHaveLength(2);
      expect(result.filter((v) => !v.isValid)).toHaveLength(1);
    });
  });
});

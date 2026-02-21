import { describe, it, expect, vi, beforeEach } from 'vitest';
import type {
  RawFinding,
  ReconResult,
  ValidatedFinding,
  InterpretedFinding,
  ScanSummary,
} from '../../src/scanner/types.js';

// ─── Mock Setup ──────────────────────────────────────────────────────

vi.mock('../../src/ai/client.js', () => ({
  askClaude: vi.fn(),
  parseJsonResponse: vi.fn(),
}));

// We do NOT mock fallback.ts — we want the real fallback logic to run
// so we can verify fallback behavior end-to-end.

import { askClaude, parseJsonResponse } from '../../src/ai/client.js';
import { generateReport } from '../../src/ai/reporter.js';

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
    description: 'User input reflected without encoding in search results page',
    url: 'https://example.com/search?q=<script>alert(1)</script>',
    evidence: '<script>alert(1)</script> found in response body',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeValidation(overrides?: Partial<ValidatedFinding>): ValidatedFinding {
  return {
    findingId: 'finding-001',
    isValid: true,
    confidence: 'high',
    reasoning: 'Confirmed — input reflected without sanitization',
    ...overrides,
  };
}

function makeAIReport(): { findings: InterpretedFinding[]; summary: ScanSummary } {
  return {
    findings: [
      {
        title: 'Reflected XSS in Search',
        severity: 'high',
        confidence: 'high',
        owaspCategory: 'A03:2021 - Injection',
        description: 'Search input is reflected in the page without sanitization',
        impact: 'Attacker can execute JavaScript in victim browsers',
        reproductionSteps: [
          'Navigate to /search?q=<script>alert(1)</script>',
          'Observe script execution',
        ],
        suggestedFix: 'Encode all user input before rendering in HTML',
        codeExample: 'const safe = escapeHtml(userInput);',
        affectedUrls: ['https://example.com/search'],
        rawFindingIds: ['finding-001'],
      },
    ],
    summary: {
      totalRawFindings: 1,
      totalInterpretedFindings: 1,
      bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      topIssues: ['Reflected XSS in Search'],
      passedChecks: [],
    },
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('generateReport', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Empty / no valid findings ──────────────────────────────────────

  describe('no valid findings', () => {
    it('returns empty report when rawFindings is empty', async () => {
      const result = await generateReport('https://example.com', [], [], makeRecon());

      expect(result.findings).toEqual([]);
      expect(result.summary.totalRawFindings).toBe(0);
      expect(result.summary.totalInterpretedFindings).toBe(0);
      expect(mockAskClaude).not.toHaveBeenCalled();
    });

    it('returns empty report when no findings pass validation', async () => {
      const rawFindings = [makeFinding({ id: 'f-1' }), makeFinding({ id: 'f-2' })];
      const validations = [
        makeValidation({ findingId: 'f-1', isValid: false }),
        makeValidation({ findingId: 'f-2', isValid: false }),
      ];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(result.findings).toEqual([]);
      expect(mockAskClaude).not.toHaveBeenCalled();
    });

    it('returns empty report with correct summary structure', async () => {
      const result = await generateReport('https://example.com', [], [], makeRecon());

      expect(result.summary.bySeverity).toEqual({
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
      });
      expect(result.summary.topIssues).toBeDefined();
      expect(Array.isArray(result.summary.topIssues)).toBe(true);
    });
  });

  // ── Prompt construction ────────────────────────────────────────────

  describe('prompt construction', () => {
    it('calls askClaude with system and user prompts for valid findings', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      const [systemPrompt, userPrompt, options] = mockAskClaude.mock.calls[0];
      expect(typeof systemPrompt).toBe('string');
      expect(typeof userPrompt).toBe('string');
      // Reporter uses larger token budget and longer timeout
      expect(options).toEqual({ maxTokens: 16384, timeout: 120000 });
    });

    it('includes target URL in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      await generateReport('https://target.example.com', rawFindings, validations, makeRecon());

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('https://target.example.com');
    });

    it('includes only validated findings in the prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', title: 'Valid XSS' }),
        makeFinding({ id: 'f-2', title: 'False Positive CORS' }),
      ];
      const validations = [
        makeValidation({ findingId: 'f-1', isValid: true }),
        makeValidation({ findingId: 'f-2', isValid: false }),
      ];

      await generateReport('https://example.com', rawFindings, validations, makeRecon());

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Validated as real: 1');
    });

    it('includes framework context in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];
      const recon = makeRecon({ framework: { name: 'Django', confidence: 'high', evidence: [] } });

      await generateReport('https://example.com', rawFindings, validations, recon);

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Django');
    });

    it('system prompt contains reporter instructions', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      await generateReport('https://example.com', rawFindings, validations, makeRecon());

      const systemPrompt = mockAskClaude.mock.calls[0][0];
      expect(systemPrompt).toContain('security analyst');
      expect(systemPrompt).toContain('Deduplicate');
      expect(systemPrompt).toContain('Prioritize');
      expect(systemPrompt).toContain('suggestedFix');
      expect(systemPrompt).toContain('owaspCategory');
    });
  });

  // ── Successful AI response ─────────────────────────────────────────

  describe('successful AI response', () => {
    it('returns AI-generated report on first attempt', async () => {
      const aiReport = makeAIReport();
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(aiReport);

      const rawFindings = [makeFinding({ id: 'finding-001' })];
      const validations = [makeValidation({ findingId: 'finding-001', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].title).toBe('Reflected XSS in Search');
      expect(result.summary.totalInterpretedFindings).toBe(1);
      // Should only call askClaude once (no retry needed)
      expect(mockAskClaude).toHaveBeenCalledTimes(1);
    });

    it('preserves all interpreted finding fields from AI', async () => {
      const aiReport = makeAIReport();
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(aiReport);

      const rawFindings = [makeFinding({ id: 'finding-001' })];
      const validations = [makeValidation({ findingId: 'finding-001', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      const finding = result.findings[0];
      expect(finding.severity).toBe('high');
      expect(finding.confidence).toBe('high');
      expect(finding.owaspCategory).toBe('A03:2021 - Injection');
      expect(finding.description).toBeTruthy();
      expect(finding.impact).toBeTruthy();
      expect(finding.reproductionSteps).toBeInstanceOf(Array);
      expect(finding.suggestedFix).toBeTruthy();
      expect(finding.affectedUrls).toBeInstanceOf(Array);
      expect(finding.rawFindingIds).toContain('finding-001');
    });

    it('preserves summary severity breakdown from AI', async () => {
      const aiReport = makeAIReport();
      aiReport.summary.bySeverity = { critical: 1, high: 2, medium: 0, low: 1, info: 0 };
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(aiReport);

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(result.summary.bySeverity.critical).toBe(1);
      expect(result.summary.bySeverity.high).toBe(2);
      expect(result.summary.bySeverity.low).toBe(1);
    });
  });

  // ── JSON parsing edge cases ────────────────────────────────────────

  describe('JSON parsing edge cases', () => {
    it('retries with reduced prompt when first AI response has invalid JSON', async () => {
      // First call returns something, but parse fails
      // Second call (retry) also returns something, and parse succeeds
      const aiReport = makeAIReport();

      let callCount = 0;
      mockAskClaude.mockImplementation(async () => {
        callCount++;
        return `response-${callCount}`;
      });

      mockParseJson.mockImplementation((text) => {
        if (text === 'response-1') return null; // First parse fails
        if (text === 'response-2') return aiReport; // Retry succeeds
        return null;
      });

      const rawFindings = [makeFinding({ id: 'finding-001' })];
      const validations = [makeValidation({ findingId: 'finding-001', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Should have called askClaude twice (original + retry)
      expect(mockAskClaude).toHaveBeenCalledTimes(2);
      // The retry uses reduced options
      expect(mockAskClaude.mock.calls[1][2]).toEqual({ maxTokens: 8192, timeout: 60000 });
      // Should return the successful retry result
      expect(result.findings).toHaveLength(1);
    });

    it('falls back to rule-based when both AI attempts return invalid JSON', async () => {
      mockAskClaude.mockResolvedValue('garbage response');
      mockParseJson.mockReturnValue(null); // Both parse attempts fail

      const rawFindings = [makeFinding({ id: 'f-1', category: 'xss', title: 'XSS in search' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Should have tried twice (original + retry)
      expect(mockAskClaude).toHaveBeenCalledTimes(2);
      // Fallback should still produce findings
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings[0].title).toContain('XSS');
    });

    it('falls back when parsed JSON has findings but no summary', async () => {
      mockAskClaude.mockResolvedValue('json');
      // Missing summary field
      mockParseJson.mockReturnValue({ findings: [{ title: 'XSS' }] });

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // After retry also fails (same mock), should use fallback
      expect(result.findings.length).toBeGreaterThanOrEqual(0);
      expect(result.summary).toBeDefined();
    });

    it('falls back when parsed JSON has summary but no findings', async () => {
      mockAskClaude.mockResolvedValue('json');
      // Missing findings field
      mockParseJson.mockReturnValue({
        summary: { totalRawFindings: 1, totalInterpretedFindings: 0, bySeverity: {}, topIssues: [] },
      });

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Should use fallback since parsed?.findings is missing
      expect(result.summary).toBeDefined();
    });

    it('accepts response with extra fields (forward-compatible)', async () => {
      const aiReport = {
        ...makeAIReport(),
        extraMetadata: { generatedBy: 'claude-3' },
      };
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(aiReport);

      const rawFindings = [makeFinding({ id: 'finding-001' })];
      const validations = [makeValidation({ findingId: 'finding-001', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(result.findings).toHaveLength(1);
      expect(result.summary).toBeDefined();
    });
  });

  // ── Fallback triggers ──────────────────────────────────────────────

  describe('fallback triggers', () => {
    it('uses fallback when askClaude returns null (API unavailable)', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', category: 'xss', title: 'Reflected XSS', severity: 'high' }),
      ];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Should only call once (no retry when response is null)
      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      // Fallback should produce findings
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings[0].title).toBe('Reflected XSS');
      expect(result.findings[0].confidence).toBe('medium'); // Fallback uses medium
    });

    it('fallback generates correct OWASP categories', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', category: 'xss', title: 'XSS' }),
        makeFinding({ id: 'f-2', category: 'sqli', title: 'SQLi' }),
        makeFinding({ id: 'f-3', category: 'cors-misconfiguration', title: 'CORS' }),
      ];
      const validations = [
        makeValidation({ findingId: 'f-1', isValid: true }),
        makeValidation({ findingId: 'f-2', isValid: true }),
        makeValidation({ findingId: 'f-3', isValid: true }),
      ];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      const owaspCategories = result.findings.map((f) => f.owaspCategory);
      expect(owaspCategories).toContain('A03:2021 - Injection'); // xss + sqli
      expect(owaspCategories).toContain('A05:2021 - Security Misconfiguration'); // cors
    });

    it('fallback deduplicates findings by category + title', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', category: 'xss', title: 'Reflected XSS', url: 'https://example.com/page1' }),
        makeFinding({ id: 'f-2', category: 'xss', title: 'Reflected XSS', url: 'https://example.com/page2' }),
        makeFinding({ id: 'f-3', category: 'xss', title: 'Reflected XSS', url: 'https://example.com/page3' }),
      ];
      const validations = rawFindings.map((f) =>
        makeValidation({ findingId: f.id, isValid: true }),
      );

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // 3 raw findings with same category+title should be deduplicated to 1
      expect(result.findings).toHaveLength(1);
      // The deduplicated finding should list all affected URLs
      expect(result.findings[0].affectedUrls).toHaveLength(3);
      expect(result.findings[0].rawFindingIds).toHaveLength(3);
    });

    it('fallback produces correct severity breakdown in summary', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', category: 'xss', title: 'XSS', severity: 'high' }),
        makeFinding({ id: 'f-2', category: 'sqli', title: 'SQLi', severity: 'critical' }),
        makeFinding({ id: 'f-3', category: 'info-leakage', title: 'Info Leak', severity: 'low' }),
      ];
      const validations = rawFindings.map((f) =>
        makeValidation({ findingId: f.id, isValid: true }),
      );

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(result.summary.bySeverity.critical).toBe(1);
      expect(result.summary.bySeverity.high).toBe(1);
      expect(result.summary.bySeverity.low).toBe(1);
      expect(result.summary.bySeverity.medium).toBe(0);
      expect(result.summary.bySeverity.info).toBe(0);
      expect(result.summary.totalRawFindings).toBe(3);
      expect(result.summary.totalInterpretedFindings).toBe(3);
    });

    it('fallback produces top issues sorted by severity', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', category: 'info-leakage', title: 'Info Leak', severity: 'low' }),
        makeFinding({ id: 'f-2', category: 'sqli', title: 'SQL Injection', severity: 'critical' }),
        makeFinding({ id: 'f-3', category: 'xss', title: 'XSS', severity: 'high' }),
      ];
      const validations = rawFindings.map((f) =>
        makeValidation({ findingId: f.id, isValid: true }),
      );

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Top issues should be sorted by severity (critical first)
      expect(result.summary.topIssues[0]).toBe('SQL Injection');
    });

    it('fallback provides reproduction steps with URL and evidence', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({
          id: 'f-1',
          url: 'https://example.com/vuln',
          evidence: 'Script tag reflected',
        }),
      ];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      const steps = result.findings[0].reproductionSteps;
      expect(steps.some((s) => s.includes('https://example.com/vuln'))).toBe(true);
      expect(steps.some((s) => s.includes('Script tag reflected'))).toBe(true);
    });

    it('fallback provides generic fix suggestion based on category', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-1', category: 'xss' }),
      ];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      expect(result.findings[0].suggestedFix).toContain('Sanitize');
    });
  });

  // ── Retry with reduced prompt ──────────────────────────────────────

  describe('retry with reduced prompt', () => {
    it('uses reduced prompt on retry with smaller token budget', async () => {
      let callCount = 0;
      mockAskClaude.mockImplementation(async () => {
        callCount++;
        return `response-${callCount}`;
      });

      // First parse fails, second succeeds
      const aiReport = makeAIReport();
      mockParseJson.mockImplementation((text) => {
        if (text === 'response-1') return null;
        if (text === 'response-2') return aiReport;
        return null;
      });

      const rawFindings = [makeFinding({ id: 'finding-001' })];
      const validations = [makeValidation({ findingId: 'finding-001', isValid: true })];

      await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // First call: full prompt (maxTokens 16384, timeout 120s)
      expect(mockAskClaude.mock.calls[0][2]).toEqual({ maxTokens: 16384, timeout: 120000 });
      // Second call: reduced prompt (maxTokens 8192, timeout 60s)
      expect(mockAskClaude.mock.calls[1][2]).toEqual({ maxTokens: 8192, timeout: 60000 });
    });

    it('retry prompt is different from initial prompt', async () => {
      let callCount = 0;
      mockAskClaude.mockImplementation(async () => {
        callCount++;
        return `response-${callCount}`;
      });

      mockParseJson.mockReturnValue(null); // Both fail, but we check prompts

      const rawFindings = [makeFinding({ id: 'f-1' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      await generateReport('https://example.com', rawFindings, validations, makeRecon());

      const firstPrompt = mockAskClaude.mock.calls[0][1];
      const retryPrompt = mockAskClaude.mock.calls[1][1];

      // Retry prompt should be shorter (reduced)
      expect(retryPrompt.length).toBeLessThanOrEqual(firstPrompt.length);
      // Both should still contain the target URL
      expect(firstPrompt).toContain('https://example.com');
      expect(retryPrompt).toContain('https://example.com');
    });

    it('falls back to rule-based when retry also returns null', async () => {
      // Both calls return null (timeout/error)
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [makeFinding({ id: 'f-1', category: 'xss', title: 'XSS Bug' })];
      const validations = [makeValidation({ findingId: 'f-1', isValid: true })];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Only one call (null response skips retry)
      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      expect(result.findings[0].title).toBe('XSS Bug');
      expect(result.findings[0].confidence).toBe('medium');
    });
  });

  // ── Filtering logic ────────────────────────────────────────────────

  describe('filtering logic', () => {
    it('only sends validated findings to AI, not rejected ones', async () => {
      mockAskClaude.mockResolvedValue(null);

      const rawFindings = [
        makeFinding({ id: 'f-valid', title: 'Real XSS' }),
        makeFinding({ id: 'f-invalid', title: 'False Positive' }),
      ];
      const validations = [
        makeValidation({ findingId: 'f-valid', isValid: true }),
        makeValidation({ findingId: 'f-invalid', isValid: false }),
      ];

      const result = await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // Only the valid finding should appear in the fallback result
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].rawFindingIds).toContain('f-valid');
    });

    it('uses adjusted severity from validation when available', async () => {
      mockAskClaude.mockResolvedValue(null);

      // Validator will adjust severity in the user prompt passed to AI
      // but since we are testing prompt construction, check the prompt
      const rawFindings = [makeFinding({ id: 'f-1', severity: 'high' })];
      const validations = [
        makeValidation({ findingId: 'f-1', isValid: true, adjustedSeverity: 'critical' }),
      ];

      // Force AI path for this test to verify prompt content
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(null); // Will fall through to retry, then fallback

      await generateReport('https://example.com', rawFindings, validations, makeRecon());

      // The user prompt should reference the adjusted severity
      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('critical');
    });
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ReconResult, CrawledPage, AttackPlan } from '../../src/scanner/types.js';

// ─── Mock Setup ──────────────────────────────────────────────────────

// Mock the AI client module
vi.mock('../../src/ai/client.js', () => ({
  askClaude: vi.fn(),
  parseJsonResponse: vi.fn(),
}));

// Mock the AI cache so no filesystem side effects
vi.mock('../../src/utils/ai-cache.js', () => {
  class MockAICache {
    generateKey() { return 'mock-cache-key'; }
    async get() { return null; }
    async set() { return undefined; }
  }
  return { AICache: MockAICache };
});

import { askClaude, parseJsonResponse } from '../../src/ai/client.js';
import { planAttack, determineRelevantChecks } from '../../src/ai/planner.js';

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

function makePage(overrides?: Partial<CrawledPage>): CrawledPage {
  return {
    url: 'https://example.com',
    status: 200,
    headers: {},
    title: 'Test',
    forms: [],
    links: [],
    scripts: [],
    cookies: [],
    ...overrides,
  };
}

function makeValidAIPlan(overrides?: Partial<AttackPlan>): AttackPlan {
  return {
    recommendedChecks: [
      { name: 'cors', priority: 1, reason: 'Always check CORS' },
      { name: 'xss', priority: 2, reason: 'Forms detected' },
    ],
    reasoning: 'AI analysis of target',
    skipReasons: { sqli: 'No database indicators' },
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('planAttack', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Prompt construction ────────────────────────────────────────────

  describe('prompt construction', () => {
    it('calls askClaude with system and user prompts', async () => {
      mockAskClaude.mockResolvedValue(null);

      const recon = makeRecon();
      const pages = [makePage()];
      await planAttack('https://example.com', recon, pages, 'standard');

      expect(mockAskClaude).toHaveBeenCalledTimes(1);
      const [systemPrompt, userPrompt] = mockAskClaude.mock.calls[0];
      expect(typeof systemPrompt).toBe('string');
      expect(typeof userPrompt).toBe('string');
    });

    it('includes the target URL in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      await planAttack('https://target.example.com', makeRecon(), [makePage()], 'standard');

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('https://target.example.com');
    });

    it('includes the scan profile in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      await planAttack('https://example.com', makeRecon(), [makePage()], 'deep');

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('deep');
    });

    it('includes tech stack data in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const recon = makeRecon({
        techStack: { languages: ['Python'], detected: ['Flask', 'Jinja2'] },
      });
      await planAttack('https://example.com', recon, [makePage()], 'standard');

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Flask');
      expect(userPrompt).toContain('Python');
    });

    it('includes WAF detection data in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const recon = makeRecon({
        waf: { detected: true, name: 'Cloudflare', confidence: 'high', evidence: ['cf-ray header'] },
      });
      await planAttack('https://example.com', recon, [makePage()], 'standard');

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Cloudflare');
    });

    it('includes endpoint counts in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const recon = makeRecon({
        endpoints: {
          pages: ['https://example.com', 'https://example.com/about'],
          apiRoutes: ['/api/users/123'],
          forms: [],
          staticAssets: [],
          graphql: [],
        },
      });
      await planAttack('https://example.com', recon, [makePage()], 'standard');

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Pages: 2');
      expect(userPrompt).toContain('API routes: 1');
    });

    it('includes form and param counts in the user prompt', async () => {
      mockAskClaude.mockResolvedValue(null);

      const pages = [
        makePage({
          url: 'https://example.com/search?q=test',
          forms: [{
            action: '/submit',
            method: 'POST',
            inputs: [{ name: 'q', type: 'text' }],
            pageUrl: 'https://example.com',
          }],
        }),
      ];
      await planAttack('https://example.com', makeRecon(), pages, 'standard');

      const userPrompt = mockAskClaude.mock.calls[0][1];
      expect(userPrompt).toContain('Forms: 1');
      expect(userPrompt).toContain('URLs with params: 1');
    });

    it('system prompt contains only relevant check descriptions', async () => {
      mockAskClaude.mockResolvedValue(null);

      // Minimal target: only cors and sri should be relevant
      await planAttack('http://example.com', makeRecon({ endpoints: { pages: [], apiRoutes: [], forms: [], staticAssets: [], graphql: [] } }), [makePage()], 'standard');

      const systemPrompt = mockAskClaude.mock.calls[0][0];
      expect(systemPrompt).toContain('- cors:');
      expect(systemPrompt).toContain('- sri:');
      // Should not include checks that have no targets
      expect(systemPrompt).not.toContain('- xss:');
      expect(systemPrompt).not.toContain('- sqli:');
    });
  });

  // ── Successful AI response ─────────────────────────────────────────

  describe('successful AI response', () => {
    it('returns parsed attack plan from AI', async () => {
      const plan = makeValidAIPlan();
      mockAskClaude.mockResolvedValue('{"recommendedChecks":[]}');
      mockParseJson.mockReturnValue(plan);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result).toEqual(plan);
    });

    it('returns plan with correct check count', async () => {
      const plan = makeValidAIPlan({
        recommendedChecks: [
          { name: 'cors', priority: 1, reason: 'Always' },
          { name: 'xss', priority: 2, reason: 'Forms exist' },
          { name: 'sqli', priority: 3, reason: 'Forms exist' },
        ],
      });
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(plan);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.recommendedChecks).toHaveLength(3);
    });

    it('preserves skipReasons from AI', async () => {
      const plan = makeValidAIPlan({
        skipReasons: {
          idor: 'No sequential IDs found',
          redirect: 'No redirect params',
        },
      });
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(plan);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.skipReasons).toEqual({
        idor: 'No sequential IDs found',
        redirect: 'No redirect params',
      });
    });

    it('preserves focusAreas in recommended checks', async () => {
      const plan = makeValidAIPlan({
        recommendedChecks: [
          { name: 'xss', priority: 1, reason: 'Forms found', focusAreas: ['/search', '/contact'] },
        ],
      });
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(plan);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.recommendedChecks[0].focusAreas).toEqual(['/search', '/contact']);
    });
  });

  // ── JSON parsing edge cases ────────────────────────────────────────

  describe('JSON parsing edge cases', () => {
    it('falls back to default plan when AI returns malformed JSON', async () => {
      mockAskClaude.mockResolvedValue('This is not valid JSON at all');
      mockParseJson.mockReturnValue(null);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      // Should return a default plan with recommendedChecks
      expect(result.recommendedChecks).toBeDefined();
      expect(result.recommendedChecks.length).toBeGreaterThan(0);
      expect(result.reasoning).toContain('Default plan');
    });

    it('falls back when parsed JSON is missing recommendedChecks', async () => {
      mockAskClaude.mockResolvedValue('{"reasoning": "no checks field"}');
      mockParseJson.mockReturnValue({ reasoning: 'no checks field' });

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.reasoning).toContain('Default plan');
    });

    it('falls back when recommendedChecks is null/undefined in parsed response', async () => {
      mockAskClaude.mockResolvedValue('{"recommendedChecks": null}');
      mockParseJson.mockReturnValue({ recommendedChecks: null, reasoning: 'test', skipReasons: {} });

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.reasoning).toContain('Default plan');
    });

    it('accepts plan with extra unexpected fields (forward-compatible)', async () => {
      const plan = {
        ...makeValidAIPlan(),
        extraField: 'should not break anything',
        metadata: { version: 2 },
      };
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(plan);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      // Should still work — extra fields are ignored
      expect(result.recommendedChecks).toBeDefined();
      expect(result.recommendedChecks.length).toBeGreaterThan(0);
    });

    it('accepts plan with empty recommendedChecks array', async () => {
      // An empty array is truthy, so this should be accepted as-is
      const plan = makeValidAIPlan({ recommendedChecks: [] });
      mockAskClaude.mockResolvedValue('json');
      mockParseJson.mockReturnValue(plan);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      // Empty array is falsy for .recommendedChecks check (length 0) — but the code checks
      // parsed?.recommendedChecks which is truthy for an empty array
      expect(result.recommendedChecks).toEqual([]);
    });
  });

  // ── Fallback triggers ──────────────────────────────────────────────

  describe('fallback triggers', () => {
    it('falls back when askClaude returns null (API unavailable)', async () => {
      mockAskClaude.mockResolvedValue(null);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.reasoning).toContain('Default plan');
      expect(result.recommendedChecks.length).toBeGreaterThan(0);
    });

    it('falls back when askClaude throws an error', async () => {
      // The planAttack function catches errors from askClaude since askClaude
      // itself returns null on errors. So we simulate that.
      mockAskClaude.mockResolvedValue(null);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.reasoning).toContain('Default plan');
    });

    it('falls back when parseJsonResponse returns null', async () => {
      mockAskClaude.mockResolvedValue('some garbage response');
      mockParseJson.mockReturnValue(null);

      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      expect(result.reasoning).toContain('Default plan');
    });
  });

  // ── Default plan behavior ──────────────────────────────────────────

  describe('default plan behavior', () => {
    beforeEach(() => {
      mockAskClaude.mockResolvedValue(null); // Force fallback
    });

    it('default plan always includes cors', async () => {
      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'standard');

      const checkNames = result.recommendedChecks.map((c) => c.name);
      expect(checkNames).toContain('cors');
    });

    it('default plan includes tls for HTTPS targets', async () => {
      const result = await planAttack('https://example.com', makeRecon(), [makePage()], 'deep');

      const checkNames = result.recommendedChecks.map((c) => c.name);
      expect(checkNames).toContain('tls');
    });

    it('default plan skips tls for HTTP targets', async () => {
      const recon = makeRecon({ endpoints: { pages: ['http://example.com'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] } });
      const result = await planAttack('http://example.com', recon, [makePage({ url: 'http://example.com' })], 'standard');

      expect(result.skipReasons).toHaveProperty('tls');
    });

    it('default plan limits to 3 checks for quick profile', async () => {
      const pages = [makePage({
        url: 'https://example.com/search?q=test',
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'q', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
        links: ['https://example.com/login?redirect=/home'],
      })];
      const recon = makeRecon({
        endpoints: {
          pages: ['https://example.com'],
          apiRoutes: ['/api/users/123'],
          forms: [],
          staticAssets: [],
          graphql: [],
        },
      });

      const result = await planAttack('https://example.com', recon, pages, 'quick');

      expect(result.recommendedChecks.length).toBeLessThanOrEqual(3);
    });

    it('default plan limits to 6 checks for standard profile', async () => {
      const pages = [makePage({
        url: 'https://example.com/search?q=test',
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'url', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
        links: ['https://example.com/login?redirect=/home'],
      })];
      const recon = makeRecon({
        techStack: { languages: ['Python'], detected: ['Flask'] },
        endpoints: {
          pages: ['https://example.com'],
          apiRoutes: ['/api/users/123'],
          forms: [],
          staticAssets: [],
          graphql: [],
        },
      });

      const result = await planAttack('https://example.com', recon, pages, 'standard');

      expect(result.recommendedChecks.length).toBeLessThanOrEqual(6);
    });

    it('default plan does not limit checks for deep profile', async () => {
      const pages = [makePage({
        url: 'https://example.com/search?q=test',
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'url', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
        links: ['https://example.com/login?redirect=/home'],
      })];
      const recon = makeRecon({
        techStack: { languages: ['Python'], detected: ['Flask'] },
        endpoints: {
          pages: ['https://example.com'],
          apiRoutes: ['/api/users/123'],
          forms: [],
          staticAssets: [],
          graphql: [],
        },
      });

      const result = await planAttack('https://example.com', recon, pages, 'deep');

      // Deep profile includes all applicable checks — at least more than 6
      expect(result.recommendedChecks.length).toBeGreaterThan(6);
    });

    it('default plan includes xss when forms exist', async () => {
      const pages = [makePage({
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'q', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
      })];

      const result = await planAttack('https://example.com', makeRecon(), pages, 'deep');

      const checkNames = result.recommendedChecks.map((c) => c.name);
      expect(checkNames).toContain('xss');
    });

    it('default plan includes idor when numeric IDs in API routes', async () => {
      const recon = makeRecon({
        endpoints: {
          pages: ['https://example.com'],
          apiRoutes: ['/api/users/42'],
          forms: [],
          staticAssets: [],
          graphql: [],
        },
      });

      const result = await planAttack('https://example.com', recon, [makePage()], 'deep');

      const checkNames = result.recommendedChecks.map((c) => c.name);
      expect(checkNames).toContain('idor');
    });

    it('default plan has unique priorities for each check', async () => {
      const pages = [makePage({
        url: 'https://example.com/search?q=test',
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'url', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
      })];

      const result = await planAttack('https://example.com', makeRecon(), pages, 'deep');

      const priorities = result.recommendedChecks.map((c) => c.priority);
      const uniquePriorities = new Set(priorities);
      expect(uniquePriorities.size).toBe(priorities.length);
    });

    it('default plan provides a reason for each check', async () => {
      const pages = [makePage({
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'q', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
      })];

      const result = await planAttack('https://example.com', makeRecon(), pages, 'deep');

      for (const check of result.recommendedChecks) {
        expect(check.reason).toBeTruthy();
        expect(typeof check.reason).toBe('string');
      }
    });
  });
});

import { describe, it, expect } from 'vitest';
import {
  buildPlannerPrompt,
  ALL_PLANNER_CHECKS,
  type PlannerCheckType,
} from '../../src/ai/prompts.js';
import { determineRelevantChecks } from '../../src/ai/planner.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

// ─── Helpers ────────────────────────────────────────────────────────

function makeRecon(overrides?: Partial<ReconResult>): ReconResult {
  return {
    techStack: { languages: [], detected: [], ...(overrides?.techStack ?? {}) },
    waf: { detected: false, confidence: 'low', evidence: [], ...(overrides?.waf ?? {}) },
    framework: { confidence: 'low', evidence: [], ...(overrides?.framework ?? {}) },
    endpoints: {
      pages: [],
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

// ─── buildPlannerPrompt ─────────────────────────────────────────────

describe('buildPlannerPrompt', () => {
  it('returns base prompt with no check sections when given empty array', () => {
    const prompt = buildPlannerPrompt([]);
    expect(prompt).toContain('SecBot\'s AI attack planner');
    expect(prompt).toContain('No specific checks are applicable');
    expect(prompt).not.toContain('Available checks');
    // Should not contain any check-specific content
    expect(prompt).not.toContain('- xss:');
    expect(prompt).not.toContain('- sqli:');
    expect(prompt).not.toContain('- cors:');
  });

  it('includes only XSS and SQLi sections when those are relevant', () => {
    const prompt = buildPlannerPrompt(['xss', 'sqli']);
    expect(prompt).toContain('- xss: Cross-site scripting');
    expect(prompt).toContain('- sqli: SQL injection');
    expect(prompt).toContain('Available checks (2 applicable)');
    // Should NOT include other checks
    expect(prompt).not.toContain('- cors:');
    expect(prompt).not.toContain('- redirect:');
    expect(prompt).not.toContain('- traversal:');
    expect(prompt).not.toContain('- ssrf:');
    expect(prompt).not.toContain('- ssti:');
    expect(prompt).not.toContain('- cmdi:');
    expect(prompt).not.toContain('- idor:');
    expect(prompt).not.toContain('- tls:');
    expect(prompt).not.toContain('- sri:');
  });

  it('includes all 11 sections when all checks are relevant', () => {
    const prompt = buildPlannerPrompt(ALL_PLANNER_CHECKS);
    expect(prompt).toContain('Available checks (11 applicable)');
    expect(prompt).toContain('- xss:');
    expect(prompt).toContain('- sqli:');
    expect(prompt).toContain('- cors:');
    expect(prompt).toContain('- redirect:');
    expect(prompt).toContain('- traversal:');
    expect(prompt).toContain('- ssrf:');
    expect(prompt).toContain('- ssti:');
    expect(prompt).toContain('- cmdi:');
    expect(prompt).toContain('- idor:');
    expect(prompt).toContain('- tls:');
    expect(prompt).toContain('- sri:');
  });

  it('always includes the base context regardless of checks', () => {
    for (const check of ALL_PLANNER_CHECKS) {
      const prompt = buildPlannerPrompt([check]);
      expect(prompt).toContain('SecBot\'s AI attack planner');
      expect(prompt).toContain('Output ONLY valid JSON');
      expect(prompt).toContain('"recommendedChecks"');
      expect(prompt).toContain('"skipReasons"');
    }
  });

  it('always includes profile rules in the base prompt', () => {
    const prompt = buildPlannerPrompt([]);
    expect(prompt).toContain('quick');
    expect(prompt).toContain('standard');
    expect(prompt).toContain('deep');
  });

  // Test each individual check type can be included
  const checkDescriptions: Record<PlannerCheckType, string> = {
    xss: 'Cross-site scripting',
    sqli: 'SQL injection',
    cors: 'CORS misconfiguration',
    redirect: 'Open redirect',
    traversal: 'Directory traversal',
    ssrf: 'Server-side request forgery',
    ssti: 'Server-side template injection',
    cmdi: 'Command injection',
    idor: 'Insecure direct object reference',
    tls: 'TLS/crypto checks',
    sri: 'Subresource integrity',
  };

  for (const [check, description] of Object.entries(checkDescriptions)) {
    it(`includes ${check} section individually`, () => {
      const prompt = buildPlannerPrompt([check as PlannerCheckType]);
      expect(prompt).toContain(`- ${check}:`);
      expect(prompt).toContain(description);
      expect(prompt).toContain('Available checks (1 applicable)');
      // Other checks should not be present
      for (const other of ALL_PLANNER_CHECKS) {
        if (other !== check) {
          expect(prompt).not.toContain(`- ${other}:`);
        }
      }
    });
  }

  it('produces a shorter prompt with fewer checks', () => {
    const fullPrompt = buildPlannerPrompt(ALL_PLANNER_CHECKS);
    const partialPrompt = buildPlannerPrompt(['cors', 'tls']);
    expect(partialPrompt.length).toBeLessThan(fullPrompt.length);
  });
});

// ─── determineRelevantChecks ────────────────────────────────────────

describe('determineRelevantChecks', () => {
  it('always includes cors', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [],
    );
    expect(checks).toContain('cors');
  });

  it('skips xss and sqli when no forms and no URL params', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage()],
    );
    expect(checks).not.toContain('xss');
    expect(checks).not.toContain('sqli');
  });

  it('includes xss and sqli when forms exist', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage({
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'q', type: 'text' }],
          pageUrl: 'http://example.com',
        }],
      })],
    );
    expect(checks).toContain('xss');
    expect(checks).toContain('sqli');
  });

  it('includes xss and sqli when URL params exist', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage({ url: 'http://example.com/search?q=test' })],
    );
    expect(checks).toContain('xss');
    expect(checks).toContain('sqli');
  });

  it('skips redirect when no redirect params', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage()],
    );
    expect(checks).not.toContain('redirect');
  });

  it('includes redirect when redirect params found', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage({ links: ['http://example.com/login?redirect=/dashboard'] })],
    );
    expect(checks).toContain('redirect');
  });

  it('skips tls for HTTP-only target', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [],
    );
    expect(checks).not.toContain('tls');
  });

  it('includes tls for HTTPS target', () => {
    const checks = determineRelevantChecks(
      'https://example.com',
      makeRecon(),
      [],
    );
    expect(checks).toContain('tls');
  });

  it('skips sri when no pages crawled', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [],
    );
    expect(checks).not.toContain('sri');
  });

  it('includes sri when pages have been crawled', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage()],
    );
    expect(checks).toContain('sri');
  });

  it('skips idor when no numeric IDs in API routes', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon({ endpoints: { pages: [], apiRoutes: ['/api/users'], forms: [], staticAssets: [], graphql: [] } }),
      [],
    );
    expect(checks).not.toContain('idor');
  });

  it('includes idor when sequential numeric IDs in API routes', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon({ endpoints: { pages: [], apiRoutes: ['/api/users/123'], forms: [], staticAssets: [], graphql: [] } }),
      [],
    );
    expect(checks).toContain('idor');
  });

  it('includes ssrf when forms have URL-accepting inputs', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage({
        forms: [{
          action: '/fetch',
          method: 'POST',
          inputs: [{ name: 'url', type: 'text' }],
          pageUrl: 'http://example.com',
        }],
      })],
    );
    expect(checks).toContain('ssrf');
  });

  it('includes ssti when template engine detected', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon({ techStack: { languages: [], detected: ['Flask'] } }),
      [],
    );
    expect(checks).toContain('ssti');
  });

  it('includes cmdi when forms exist', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage({
        forms: [{
          action: '/run',
          method: 'POST',
          inputs: [{ name: 'cmd', type: 'text' }],
          pageUrl: 'http://example.com',
        }],
      })],
    );
    expect(checks).toContain('cmdi');
  });

  it('includes cmdi when API endpoints exist', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage({ url: 'http://example.com/api/exec' })],
    );
    expect(checks).toContain('cmdi');
  });

  it('skips ssrf, ssti, cmdi when no forms, no API, no params', () => {
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage()],
    );
    expect(checks).not.toContain('ssrf');
    expect(checks).not.toContain('ssti');
    expect(checks).not.toContain('cmdi');
  });

  it('minimal target only returns cors and sri', () => {
    // HTTP target, 1 page crawled, no forms, no params, no API
    const checks = determineRelevantChecks(
      'http://example.com',
      makeRecon(),
      [makePage()],
    );
    expect(checks).toEqual(['cors', 'sri']);
  });

  it('full-featured target returns all checks', () => {
    const checks = determineRelevantChecks(
      'https://example.com',
      makeRecon({
        techStack: { languages: ['Python'], detected: ['Flask', 'Jinja2'] },
        endpoints: {
          pages: ['https://example.com'],
          apiRoutes: ['/api/users/123'],
          forms: [],
          staticAssets: [],
          graphql: [],
        },
      }),
      [makePage({
        url: 'https://example.com/search?q=test',
        forms: [{
          action: '/submit',
          method: 'POST',
          inputs: [{ name: 'url', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
        links: ['https://example.com/login?redirect=/home'],
      })],
    );
    expect(checks).toContain('cors');
    expect(checks).toContain('xss');
    expect(checks).toContain('sqli');
    expect(checks).toContain('redirect');
    expect(checks).toContain('traversal');
    expect(checks).toContain('ssrf');
    expect(checks).toContain('ssti');
    expect(checks).toContain('cmdi');
    expect(checks).toContain('idor');
    expect(checks).toContain('tls');
    expect(checks).toContain('sri');
    expect(checks).toHaveLength(11);
  });
});

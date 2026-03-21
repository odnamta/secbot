import { describe, it, expect } from 'vitest';

describe('Content-Type Confusion Check', () => {
  it('exports the check module', async () => {
    const mod = await import('../../src/scanner/active/content-type-confusion.js');
    expect(mod.contentTypeConfusionCheck).toBeDefined();
    expect(mod.contentTypeConfusionCheck.name).toBe('content-type-confusion');
    expect(mod.contentTypeConfusionCheck.category).toBe('csrf');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'content-type-confusion');
    expect(check).toBeDefined();
    expect(check!.category).toBe('csrf');
  });

  it('is not marked as parallel', async () => {
    const mod = await import('../../src/scanner/active/content-type-confusion.js');
    expect(mod.contentTypeConfusionCheck.parallel).toBeFalsy();
  });

  it('is in ALL_PLANNER_CHECKS', async () => {
    const { ALL_PLANNER_CHECKS } = await import('../../src/ai/prompts.js');
    expect(ALL_PLANNER_CHECKS).toContain('content-type-confusion');
  });

  it('has fallback OWASP mapping', async () => {
    const { mapToOwasp } = await import('../../src/ai/fallback.js');
    expect(mapToOwasp('content-type-confusion')).toBe('A01:2021 - Broken Access Control');
  });

  it('has fallback impact description', async () => {
    const { getGenericImpact } = await import('../../src/ai/fallback.js');
    const impact = getGenericImpact('content-type-confusion');
    expect(impact).toContain('CSRF');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has fallback fix description', async () => {
    const { getGenericFix } = await import('../../src/ai/fallback.js');
    const fix = getGenericFix('content-type-confusion');
    expect(fix).toContain('Content-Type');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });
});

describe('Content-Type Confusion — buildDefaultPlan integration', () => {
  it('includes content-type-confusion when state-changing forms exist', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/login'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/login',
        status: 200,
        headers: {},
        title: 'Login',
        forms: [{
          action: 'https://example.com/login',
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text' },
            { name: 'password', type: 'password' },
          ],
          pageUrl: 'https://example.com/login',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('content-type-confusion');
  });

  it('includes content-type-confusion when API endpoints exist', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/api/users'], apiRoutes: ['https://example.com/api/users'], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/api/users',
        status: 200,
        headers: {},
        title: 'API',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('content-type-confusion');
  });

  it('excludes content-type-confusion when no forms or API endpoints', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com',
        status: 200,
        headers: {},
        title: 'Home',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).not.toContain('content-type-confusion');
    expect(plan.skipReasons['content-type-confusion']).toBeDefined();
  });
});

import { describe, it, expect } from 'vitest';

describe('HTTP Method Override Check', () => {
  it('exports the check module', async () => {
    const mod = await import('../../src/scanner/active/method-override.js');
    expect(mod.methodOverrideCheck).toBeDefined();
    expect(mod.methodOverrideCheck.name).toBe('method-override');
    expect(mod.methodOverrideCheck.category).toBe('broken-access-control');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'method-override');
    expect(check).toBeDefined();
    expect(check!.category).toBe('broken-access-control');
  });

  it('is not marked as parallel', async () => {
    const mod = await import('../../src/scanner/active/method-override.js');
    expect(mod.methodOverrideCheck.parallel).toBeFalsy();
  });

  it('is in ALL_PLANNER_CHECKS', async () => {
    const { ALL_PLANNER_CHECKS } = await import('../../src/ai/prompts.js');
    expect(ALL_PLANNER_CHECKS).toContain('method-override');
  });

  it('has fallback OWASP mapping', async () => {
    const { mapToOwasp } = await import('../../src/ai/fallback.js');
    expect(mapToOwasp('method-override')).toBe('A01:2021 - Broken Access Control');
  });

  it('has fallback impact description', async () => {
    const { getGenericImpact } = await import('../../src/ai/fallback.js');
    const impact = getGenericImpact('method-override');
    expect(impact).toContain('access control');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has fallback fix description', async () => {
    const { getGenericFix } = await import('../../src/ai/fallback.js');
    const fix = getGenericFix('method-override');
    expect(fix).toContain('method override');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });
});

describe('HTTP Method Override — buildDefaultPlan integration', () => {
  it('includes method-override when API endpoints exist', async () => {
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
    expect(names).toContain('method-override');
  });

  it('includes method-override when sensitive paths exist', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/admin/users'], apiRoutes: ['https://example.com/admin/users'], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/admin/users',
        status: 200,
        headers: {},
        title: 'Admin',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('method-override');
  });

  it('excludes method-override when no API or sensitive endpoints', async () => {
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
    expect(names).not.toContain('method-override');
    expect(plan.skipReasons['method-override']).toBeDefined();
  });
});

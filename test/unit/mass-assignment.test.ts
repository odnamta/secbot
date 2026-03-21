import { describe, it, expect } from 'vitest';

describe('Mass Assignment Check', () => {
  it('exports the check module', async () => {
    const mod = await import('../../src/scanner/active/mass-assignment.js');
    expect(mod.massAssignmentCheck).toBeDefined();
    expect(mod.massAssignmentCheck.name).toBe('mass-assignment');
    expect(mod.massAssignmentCheck.category).toBe('broken-access-control');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'mass-assignment');
    expect(check).toBeDefined();
    expect(check!.category).toBe('broken-access-control');
  });

  it('is not marked as parallel', async () => {
    const mod = await import('../../src/scanner/active/mass-assignment.js');
    expect(mod.massAssignmentCheck.parallel).toBeFalsy();
  });
});

describe('Mass Assignment — buildDefaultPlan integration', () => {
  it('includes mass-assignment when mutable API endpoints exist', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/api/user'], apiRoutes: ['https://example.com/api/user/profile'], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/api/user/profile',
        status: 200,
        headers: {},
        title: 'Profile',
        forms: [],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('mass-assignment');
  });

  it('includes mass-assignment when user data forms exist', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/settings'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/settings',
        status: 200,
        headers: {},
        title: 'Settings',
        forms: [{
          action: 'https://example.com/settings',
          method: 'POST',
          inputs: [
            { name: 'name', type: 'text' },
            { name: 'email', type: 'email' },
          ],
          pageUrl: 'https://example.com/settings',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('mass-assignment');
  });

  it('excludes mass-assignment when no relevant endpoints or forms exist', async () => {
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
    expect(names).not.toContain('mass-assignment');
    expect(plan.skipReasons['mass-assignment']).toBeDefined();
  });
});

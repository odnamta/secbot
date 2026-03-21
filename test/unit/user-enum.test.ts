import { describe, it, expect } from 'vitest';

describe('Username Enumeration Check', () => {
  it('exports the check module', async () => {
    const mod = await import('../../src/scanner/active/user-enum.js');
    expect(mod.userEnumCheck).toBeDefined();
    expect(mod.userEnumCheck.name).toBe('user-enum');
    expect(mod.userEnumCheck.category).toBe('info-disclosure');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'user-enum');
    expect(check).toBeDefined();
    expect(check!.category).toBe('info-disclosure');
  });

  it('is not marked as parallel (modifies state via form submissions)', async () => {
    const mod = await import('../../src/scanner/active/user-enum.js');
    expect(mod.userEnumCheck.parallel).toBeFalsy();
  });
});

describe('Username Enumeration — buildDefaultPlan integration', () => {
  it('includes user-enum when auth forms with username+password inputs exist', async () => {
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
    expect(names).toContain('user-enum');
  });

  it('excludes user-enum when no auth forms exist', async () => {
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
    expect(names).not.toContain('user-enum');
    expect(plan.skipReasons['user-enum']).toBeDefined();
  });

  it('includes user-enum for email+password login form', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/signin'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/signin',
        status: 200,
        headers: {},
        title: 'Sign In',
        forms: [{
          action: 'https://example.com/signin',
          method: 'POST',
          inputs: [
            { name: 'email', type: 'email' },
            { name: 'pass', type: 'password' },
          ],
          pageUrl: 'https://example.com/signin',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('user-enum');
  });
});

describe('buildDefaultPlan — deserialization, smuggling, ldap gates', () => {
  it('includes insecure-deserialization when API endpoints exist', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/api/data',
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
    expect(names).toContain('insecure-deserialization');
  });

  it('includes request-smuggling when pages have been crawled', async () => {
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
    expect(names).toContain('request-smuggling');
  });

  it('includes ldap-injection when login forms with username field exist', async () => {
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
    expect(names).toContain('ldap-injection');
  });

  it('excludes ldap-injection when no LDAP-related form fields exist', async () => {
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
        forms: [{
          action: 'https://example.com/search',
          method: 'GET',
          inputs: [{ name: 'page', type: 'text' }],
          pageUrl: 'https://example.com',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).not.toContain('ldap-injection');
  });
});

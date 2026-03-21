import { describe, it, expect } from 'vitest';

describe('Email Header Injection Check', () => {
  it('exports the check module', async () => {
    const mod = await import('../../src/scanner/active/email-injection.js');
    expect(mod.emailInjectionCheck).toBeDefined();
    expect(mod.emailInjectionCheck.name).toBe('email-injection');
    expect(mod.emailInjectionCheck.category).toBe('crlf-injection');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'email-injection');
    expect(check).toBeDefined();
    expect(check!.category).toBe('crlf-injection');
  });

  it('is not marked as parallel', async () => {
    const mod = await import('../../src/scanner/active/email-injection.js');
    expect(mod.emailInjectionCheck.parallel).toBeFalsy();
  });

  it('is in ALL_PLANNER_CHECKS', async () => {
    const { ALL_PLANNER_CHECKS } = await import('../../src/ai/prompts.js');
    expect(ALL_PLANNER_CHECKS).toContain('email-injection');
  });

  it('has fallback OWASP mapping', async () => {
    const { mapToOwasp } = await import('../../src/ai/fallback.js');
    expect(mapToOwasp('email-injection')).toBe('A03:2021 - Injection');
  });

  it('has fallback impact description', async () => {
    const { getGenericImpact } = await import('../../src/ai/fallback.js');
    const impact = getGenericImpact('email-injection');
    expect(impact).toContain('SMTP');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has fallback fix description', async () => {
    const { getGenericFix } = await import('../../src/ai/fallback.js');
    const fix = getGenericFix('email-injection');
    expect(fix).toContain('email');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });
});

describe('Email Injection — buildDefaultPlan integration', () => {
  it('includes email-injection when contact form with email field exists', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/contact'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/contact',
        status: 200,
        headers: {},
        title: 'Contact Us',
        forms: [{
          action: 'https://example.com/contact',
          method: 'POST',
          inputs: [
            { name: 'email', type: 'email' },
            { name: 'subject', type: 'text' },
            { name: 'message', type: 'text' },
          ],
          pageUrl: 'https://example.com/contact',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('email-injection');
  });

  it('includes email-injection when newsletter form exists', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/newsletter'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/newsletter',
        status: 200,
        headers: {},
        title: 'Newsletter',
        forms: [{
          action: 'https://example.com/newsletter/subscribe',
          method: 'POST',
          inputs: [
            { name: 'email', type: 'email' },
          ],
          pageUrl: 'https://example.com/newsletter',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).toContain('email-injection');
  });

  it('excludes email-injection when no email forms exist', async () => {
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
    expect(names).not.toContain('email-injection');
    expect(plan.skipReasons['email-injection']).toBeDefined();
  });

  it('excludes email-injection for GET forms on contact pages', async () => {
    const { buildDefaultPlan } = await import('../../src/ai/planner.js');
    const plan = buildDefaultPlan(
      {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: ['https://example.com/contact'], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      [{
        url: 'https://example.com/contact',
        status: 200,
        headers: {},
        title: 'Contact',
        forms: [{
          action: 'https://example.com/contact',
          method: 'GET',
          inputs: [
            { name: 'email', type: 'email' },
          ],
          pageUrl: 'https://example.com/contact',
        }],
        links: [],
        scripts: [],
        cookies: [],
      }],
      'standard',
    );
    const names = plan.recommendedChecks.map((c) => c.name);
    expect(names).not.toContain('email-injection');
  });
});

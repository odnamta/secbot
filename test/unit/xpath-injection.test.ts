import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { ALL_PLANNER_CHECKS, type PlannerCheckType } from '../../src/ai/prompts.js';
import { mapToOwasp, getGenericImpact, getGenericFix } from '../../src/ai/fallback.js';
import { buildDefaultPlan } from '../../src/ai/planner.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

describe('XPath Injection check', () => {
  // ─── Module registration ────────────────────────────────────────────
  it('exports xpathInjectionCheck in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'xpath-injection');
    expect(check).toBeDefined();
    expect(check!.category).toBe('sqli');
  });

  it('IS parallel (read-only HTTP requests)', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'xpath-injection');
    expect(check!.parallel).toBe(true);
  });

  it('is listed in ALL_PLANNER_CHECKS', () => {
    expect(ALL_PLANNER_CHECKS).toContain('xpath-injection' as PlannerCheckType);
  });

  // ─── Fallback mappings ──────────────────────────────────────────────
  it('maps to OWASP A03 Injection', () => {
    expect(mapToOwasp('xpath-injection')).toBe('A03:2021 - Injection');
  });

  it('has a generic impact description', () => {
    const impact = getGenericImpact('xpath-injection');
    expect(impact).toContain('XPath');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has a generic fix description', () => {
    const fix = getGenericFix('xpath-injection');
    expect(fix).toContain('parameterized');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });

  // ─── Planner integration: buildDefaultPlan ──────────────────────────

  const makeRecon = (pages: string[] = []): ReconResult =>
    ({
      techStack: { detected: [], confidence: {} },
      waf: { detected: false, name: null, confidence: 0 },
      endpoints: {
        pages: pages.length > 0 ? pages : ['https://example.com/'],
        apiRoutes: [],
        graphql: [],
      },
      metadata: {},
    }) as unknown as ReconResult;

  const makePage = (
    url: string,
    forms: Array<{ inputs: Array<{ name: string; type: string }> }> = [],
  ): CrawledPage =>
    ({
      url,
      links: [],
      forms: forms.map((f) => ({
        action: url,
        pageUrl: url,
        method: 'POST',
        inputs: f.inputs.map((i) => ({ ...i, value: '' })),
      })),
      scripts: [],
      cookies: [],
    }) as unknown as CrawledPage;

  it('includes xpath-injection when parameterized URLs exist', () => {
    const recon = makeRecon(['https://example.com/search?q=test']);
    const pages = [makePage('https://example.com/search?q=test')];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'xpath-injection');
    expect(check).toBeDefined();
    expect(check!.reason).toContain('parameterized');
  });

  it('includes xpath-injection when forms exist', () => {
    const recon = makeRecon(['https://example.com/']);
    const pages = [
      makePage('https://example.com/', [
        { inputs: [{ name: 'query', type: 'text' }] },
      ]),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'xpath-injection');
    expect(check).toBeDefined();
  });

  it('excludes xpath-injection when no params or forms', () => {
    const recon = makeRecon(['https://example.com/']);
    const pages = [makePage('https://example.com/')];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'xpath-injection');
    expect(check).toBeUndefined();
    expect(plan.skipReasons['xpath-injection']).toContain('No parameterized');
  });
});

import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { ALL_PLANNER_CHECKS, type PlannerCheckType } from '../../src/ai/prompts.js';
import { mapToOwasp, getGenericImpact, getGenericFix } from '../../src/ai/fallback.js';
import { buildDefaultPlan } from '../../src/ai/planner.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

describe('BFLA (Broken Function-Level Authorization) check', () => {
  // ─── Module registration ────────────────────────────────────────────
  it('exports bflaCheck in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'bfla');
    expect(check).toBeDefined();
    expect(check!.category).toBe('broken-access-control');
  });

  it('is NOT parallel (writes/probes endpoints)', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'bfla');
    expect(check!.parallel).toBeFalsy();
  });

  it('is listed in ALL_PLANNER_CHECKS', () => {
    expect(ALL_PLANNER_CHECKS).toContain('bfla' as PlannerCheckType);
  });

  // ─── Fallback mappings ──────────────────────────────────────────────
  it('maps to OWASP A01 Broken Access Control', () => {
    expect(mapToOwasp('bfla')).toBe('A01:2021 - Broken Access Control');
  });

  it('has a generic impact description', () => {
    const impact = getGenericImpact('bfla');
    expect(impact).toContain('admin-only API functions');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has a generic fix description', () => {
    const fix = getGenericFix('bfla');
    expect(fix).toContain('function-level authorization');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });

  // ─── Planner integration: buildDefaultPlan ──────────────────────────

  const makeRecon = (apiRoutes: string[] = [], pages: string[] = []): ReconResult => ({
    techStack: { detected: [], confidence: {} },
    waf: { detected: false, name: null, confidence: 0 },
    endpoints: {
      pages: pages.length > 0 ? pages : ['https://example.com/'],
      apiRoutes,
      graphql: [],
    },
    metadata: {},
  } as unknown as ReconResult);

  const makePage = (url: string, links: string[] = []): CrawledPage => ({
    url,
    links,
    forms: [],
    scripts: [],
    cookies: [],
  } as unknown as CrawledPage);

  it('includes bfla when API endpoints exist', () => {
    const recon = makeRecon(['/api/v1/users', '/api/v1/orders']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/api/v1/users'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const bflaCheck = plan.recommendedChecks.find((c) => c.name === 'bfla');
    expect(bflaCheck).toBeDefined();
    expect(bflaCheck!.reason).toContain('API endpoints');
  });

  it('excludes bfla when no API endpoints exist', () => {
    const recon = makeRecon([], ['https://example.com/']);
    const pages = [makePage('https://example.com/')];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const bflaCheck = plan.recommendedChecks.find((c) => c.name === 'bfla');
    expect(bflaCheck).toBeUndefined();
    expect(plan.skipReasons['bfla']).toContain('No API endpoints');
  });

  it('includes bfla in deep profile with API routes', () => {
    const recon = makeRecon(['/api/v2/products']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/api/v2/products'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'deep');
    const bflaCheck = plan.recommendedChecks.find((c) => c.name === 'bfla');
    expect(bflaCheck).toBeDefined();
  });
});

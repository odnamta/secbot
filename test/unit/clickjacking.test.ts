import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { ALL_PLANNER_CHECKS, type PlannerCheckType } from '../../src/ai/prompts.js';
import { mapToOwasp, getGenericImpact, getGenericFix } from '../../src/ai/fallback.js';
import { buildDefaultPlan } from '../../src/ai/planner.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

describe('Clickjacking (Active Frame Detection) check', () => {
  // ─── Module registration ────────────────────────────────────────────
  it('exports clickjackingCheck in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'clickjacking');
    expect(check).toBeDefined();
    expect(check!.category).toBe('clickjacking');
  });

  it('IS parallel (read-only browser operations)', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'clickjacking');
    expect(check!.parallel).toBe(true);
  });

  it('is listed in ALL_PLANNER_CHECKS', () => {
    expect(ALL_PLANNER_CHECKS).toContain('clickjacking' as PlannerCheckType);
  });

  // ─── Fallback mappings ──────────────────────────────────────────────
  it('maps to OWASP A05 Security Misconfiguration', () => {
    expect(mapToOwasp('clickjacking')).toBe('A05:2021 - Security Misconfiguration');
  });

  it('has a generic impact description', () => {
    const impact = getGenericImpact('clickjacking');
    expect(impact).toContain('iframe');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has a generic fix description', () => {
    const fix = getGenericFix('clickjacking');
    expect(fix).toContain('frame-ancestors');
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

  const makePage = (url: string, links: string[] = []): CrawledPage =>
    ({
      url,
      links,
      forms: [],
      scripts: [],
      cookies: [],
    }) as unknown as CrawledPage;

  it('includes clickjacking when pages exist', () => {
    const recon = makeRecon(['https://example.com/', 'https://example.com/login']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/login'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const clickjackCheck = plan.recommendedChecks.find((c) => c.name === 'clickjacking');
    expect(clickjackCheck).toBeDefined();
    expect(clickjackCheck!.reason).toContain('pages');
  });

  it('excludes clickjacking when no pages exist', () => {
    const recon = makeRecon([]);
    const pages: CrawledPage[] = [];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const clickjackCheck = plan.recommendedChecks.find((c) => c.name === 'clickjacking');
    expect(clickjackCheck).toBeUndefined();
    expect(plan.skipReasons['clickjacking']).toContain('No pages');
  });

  it('includes clickjacking in deep profile', () => {
    const recon = makeRecon(['https://example.com/']);
    const pages = [makePage('https://example.com/')];
    const plan = buildDefaultPlan(recon, pages, 'deep');
    const clickjackCheck = plan.recommendedChecks.find((c) => c.name === 'clickjacking');
    expect(clickjackCheck).toBeDefined();
  });
});

import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { ALL_PLANNER_CHECKS, type PlannerCheckType } from '../../src/ai/prompts.js';
import { mapToOwasp, getGenericImpact, getGenericFix } from '../../src/ai/fallback.js';
import { buildDefaultPlan } from '../../src/ai/planner.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

describe('Verbose Errors (Debug Mode Detection) check', () => {
  // ─── Module registration ────────────────────────────────────────────
  it('exports verboseErrorsCheck in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'verbose-errors');
    expect(check).toBeDefined();
    expect(check!.category).toBe('info-disclosure');
  });

  it('IS parallel (read-only requests)', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'verbose-errors');
    expect(check!.parallel).toBe(true);
  });

  it('is listed in ALL_PLANNER_CHECKS', () => {
    expect(ALL_PLANNER_CHECKS).toContain('verbose-errors' as PlannerCheckType);
  });

  // ─── Fallback mappings ──────────────────────────────────────────────
  it('maps to OWASP A05 Security Misconfiguration', () => {
    expect(mapToOwasp('verbose-errors')).toBe('A05:2021 - Security Misconfiguration');
  });

  it('has a generic impact description', () => {
    const impact = getGenericImpact('verbose-errors');
    expect(impact).toContain('stack traces');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has a generic fix description', () => {
    const fix = getGenericFix('verbose-errors');
    expect(fix).toContain('debug mode');
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

  const makePage = (url: string): CrawledPage =>
    ({
      url,
      links: [],
      forms: [],
      scripts: [],
      cookies: [],
    }) as unknown as CrawledPage;

  it('includes verbose-errors when pages exist', () => {
    const recon = makeRecon(['https://example.com/']);
    const pages = [makePage('https://example.com/')];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'verbose-errors');
    expect(check).toBeDefined();
    expect(check!.reason).toContain('pages');
  });

  it('excludes verbose-errors when no pages exist', () => {
    const recon = makeRecon([]);
    const pages: CrawledPage[] = [];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'verbose-errors');
    expect(check).toBeUndefined();
    expect(plan.skipReasons['verbose-errors']).toContain('No pages');
  });

  it('includes verbose-errors in deep profile', () => {
    const recon = makeRecon(['https://example.com/']);
    const pages = [makePage('https://example.com/')];
    const plan = buildDefaultPlan(recon, pages, 'deep');
    const check = plan.recommendedChecks.find((c) => c.name === 'verbose-errors');
    expect(check).toBeDefined();
  });
});

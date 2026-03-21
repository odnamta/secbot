import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { ALL_PLANNER_CHECKS, type PlannerCheckType } from '../../src/ai/prompts.js';
import { mapToOwasp, getGenericImpact, getGenericFix } from '../../src/ai/fallback.js';
import { buildDefaultPlan } from '../../src/ai/planner.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

describe('Timing Attack (Response Time Analysis) check', () => {
  // ─── Module registration ────────────────────────────────────────────
  it('exports timingAttackCheck in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'timing-attack');
    expect(check).toBeDefined();
    expect(check!.category).toBe('info-disclosure');
  });

  it('IS parallel (read-only HTTP measurements)', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'timing-attack');
    expect(check!.parallel).toBe(true);
  });

  it('is listed in ALL_PLANNER_CHECKS', () => {
    expect(ALL_PLANNER_CHECKS).toContain('timing-attack' as PlannerCheckType);
  });

  // ─── Fallback mappings ──────────────────────────────────────────────
  it('maps to OWASP A07 Identification and Authentication Failures', () => {
    expect(mapToOwasp('timing-attack')).toBe('A07:2021 - Identification and Authentication Failures');
  });

  it('has a generic impact description', () => {
    const impact = getGenericImpact('timing-attack');
    expect(impact).toContain('timing');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has a generic fix description', () => {
    const fix = getGenericFix('timing-attack');
    expect(fix).toContain('constant time');
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

  const makePage = (url: string, forms: Array<{ action?: string; inputs: Array<{ name: string; type: string }> }> = []): CrawledPage =>
    ({
      url,
      links: [],
      forms: forms.map((f) => ({
        action: f.action ?? url,
        pageUrl: url,
        method: 'POST',
        inputs: f.inputs.map((i) => ({ ...i, value: '' })),
      })),
      scripts: [],
      cookies: [],
    }) as unknown as CrawledPage;

  it('includes timing-attack when login forms exist', () => {
    const recon = makeRecon(['https://example.com/', 'https://example.com/login']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/login', [
        { inputs: [{ name: 'username', type: 'text' }, { name: 'password', type: 'password' }] },
      ]),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const timingCheck = plan.recommendedChecks.find((c) => c.name === 'timing-attack');
    expect(timingCheck).toBeDefined();
    expect(timingCheck!.reason).toContain('Auth endpoints');
  });

  it('includes timing-attack when auth URL patterns exist', () => {
    const recon = makeRecon(['https://example.com/', 'https://example.com/auth/login']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/auth/login'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const timingCheck = plan.recommendedChecks.find((c) => c.name === 'timing-attack');
    expect(timingCheck).toBeDefined();
  });

  it('excludes timing-attack when no auth endpoints exist', () => {
    const recon = makeRecon(['https://example.com/', 'https://example.com/about']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/about'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const timingCheck = plan.recommendedChecks.find((c) => c.name === 'timing-attack');
    expect(timingCheck).toBeUndefined();
    expect(plan.skipReasons['timing-attack']).toContain('No login forms');
  });
});

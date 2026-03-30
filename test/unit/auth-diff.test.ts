import { describe, it, expect } from 'vitest';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { ALL_PLANNER_CHECKS, type PlannerCheckType } from '../../src/ai/prompts.js';
import { mapToOwasp, getGenericImpact, getGenericFix } from '../../src/ai/fallback.js';
import { buildDefaultPlan } from '../../src/ai/planner.js';
import { jsonKeySimilarity, hasUserSpecificData } from '../../src/scanner/active/auth-diff.js';
import type { ReconResult, CrawledPage } from '../../src/scanner/types.js';

describe('Auth Diff (Two-User Authorization Testing) check', () => {
  // ─── Module registration ────────────────────────────────────────────
  it('exports authDiffCheck in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'auth-diff');
    expect(check).toBeDefined();
    expect(check!.category).toBe('broken-access-control');
  });

  it('is NOT parallel (launches separate browser)', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'auth-diff');
    expect(check!.parallel).toBeFalsy();
  });

  it('is listed in ALL_PLANNER_CHECKS', () => {
    expect(ALL_PLANNER_CHECKS).toContain('auth-diff' as PlannerCheckType);
  });

  // ─── Fallback mappings ──────────────────────────────────────────────
  it('maps to OWASP A01 Broken Access Control', () => {
    expect(mapToOwasp('auth-diff')).toBe('A01:2021 - Broken Access Control');
  });

  it('has a generic impact description', () => {
    const impact = getGenericImpact('auth-diff');
    expect(impact).toContain('User B');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has a generic fix description', () => {
    const fix = getGenericFix('auth-diff');
    expect(fix).toContain('authorization');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });

  // ─── JSON key similarity ───────────────────────────────────────────
  describe('jsonKeySimilarity', () => {
    it('returns 1.0 for identical JSON objects', () => {
      const body = JSON.stringify({ id: 1, name: 'Alice', email: 'a@b.com' });
      expect(jsonKeySimilarity(body, body)).toBe(1);
    });

    it('returns 0 for completely different JSON structures', () => {
      const a = JSON.stringify({ foo: 1 });
      const b = JSON.stringify({ bar: 2 });
      expect(jsonKeySimilarity(a, b)).toBe(0);
    });

    it('returns partial similarity for overlapping keys', () => {
      const a = JSON.stringify({ id: 1, name: 'Alice', email: 'a@b.com' });
      const b = JSON.stringify({ id: 2, name: 'Bob', phone: '123' });
      const sim = jsonKeySimilarity(a, b);
      expect(sim).toBeGreaterThan(0);
      expect(sim).toBeLessThan(1);
    });

    it('handles nested JSON objects', () => {
      const a = JSON.stringify({ user: { id: 1, profile: { name: 'A' } } });
      const b = JSON.stringify({ user: { id: 2, profile: { name: 'B' } } });
      expect(jsonKeySimilarity(a, b)).toBe(1); // same structure, different values
    });

    it('handles non-JSON gracefully', () => {
      expect(jsonKeySimilarity('not json', 'also not json')).toBeGreaterThanOrEqual(0);
    });

    it('returns 0 for empty strings', () => {
      expect(jsonKeySimilarity('', '')).toBe(0);
    });

    it('handles arrays of objects', () => {
      const a = JSON.stringify([{ id: 1, name: 'A' }, { id: 2, name: 'B' }]);
      const b = JSON.stringify([{ id: 3, name: 'C' }]);
      // Same structure (array of {id, name})
      expect(jsonKeySimilarity(a, b)).toBe(1);
    });
  });

  // ─── User data detection ──────────────────────────────────────────
  describe('hasUserSpecificData', () => {
    it('detects email fields', () => {
      const body = JSON.stringify({ email: 'user@example.com', name: 'Alice' });
      const { isUserData, indicators } = hasUserSpecificData(body);
      expect(isUserData).toBe(true);
      expect(indicators.length).toBeGreaterThan(0);
    });

    it('detects identity fields', () => {
      const body = JSON.stringify({ user_id: 42, data: 'something' });
      const { isUserData, indicators } = hasUserSpecificData(body);
      expect(isUserData).toBe(true);
      expect(indicators.some((i) => i.includes('identity'))).toBe(true);
    });

    it('returns false for public/generic content', () => {
      const body = JSON.stringify({ version: '1.0', status: 'ok', healthcheck: true });
      const { isUserData } = hasUserSpecificData(body);
      expect(isUserData).toBe(false);
    });

    it('returns false for content without user indicators', () => {
      const body = JSON.stringify({ items: [1, 2, 3], count: 3 });
      const { isUserData } = hasUserSpecificData(body);
      expect(isUserData).toBe(false);
    });

    it('detects payment/financial fields', () => {
      const body = JSON.stringify({ balance: 100.50, account: 'ACC-123' });
      const { isUserData } = hasUserSpecificData(body);
      expect(isUserData).toBe(true);
    });
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

  it('includes auth-diff when API endpoints exist', () => {
    const recon = makeRecon(['/api/v1/users', '/api/v1/orders']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/api/v1/users'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'auth-diff');
    expect(check).toBeDefined();
    expect(check!.reason).toContain('API endpoints');
  });

  it('excludes auth-diff when no API endpoints exist', () => {
    const recon = makeRecon([], ['https://example.com/']);
    const pages = [makePage('https://example.com/')];
    const plan = buildDefaultPlan(recon, pages, 'standard');
    const check = plan.recommendedChecks.find((c) => c.name === 'auth-diff');
    expect(check).toBeUndefined();
    expect(plan.skipReasons['auth-diff']).toContain('No API endpoints');
  });

  it('includes auth-diff in deep profile with API routes', () => {
    const recon = makeRecon(['/api/v2/products']);
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/api/v2/products'),
    ];
    const plan = buildDefaultPlan(recon, pages, 'deep');
    const check = plan.recommendedChecks.find((c) => c.name === 'auth-diff');
    expect(check).toBeDefined();
  });
});

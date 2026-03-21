import { describe, it, expect } from 'vitest';
import {
  findOAuthEndpoints,
  REDIRECT_URI_BYPASS_VARIANTS,
} from '../../src/scanner/active/oauth.js';

// ─── findOAuthEndpoints ────────────────────────────────────────────────

describe('findOAuthEndpoints', () => {
  it('finds /oauth/ endpoints', () => {
    const results = findOAuthEndpoints(['https://example.com/oauth/authorize'], []);
    expect(results).toHaveLength(1);
  });

  it('finds /authorize endpoints', () => {
    const results = findOAuthEndpoints(['https://example.com/authorize?client_id=abc'], []);
    expect(results).toHaveLength(1);
  });

  it('finds /auth/callback endpoints', () => {
    const results = findOAuthEndpoints([], ['https://example.com/auth/callback']);
    expect(results).toHaveLength(1);
  });

  it('finds .well-known/openid endpoints', () => {
    const results = findOAuthEndpoints(['https://example.com/.well-known/openid-configuration'], []);
    expect(results).toHaveLength(1);
  });

  it('finds /token endpoints', () => {
    const results = findOAuthEndpoints([], ['https://example.com/oauth/token']);
    expect(results).toHaveLength(1);
  });

  it('returns empty for non-OAuth URLs', () => {
    const results = findOAuthEndpoints(['https://example.com/', 'https://example.com/about'], []);
    expect(results).toHaveLength(0);
  });

  it('finds /oauth2/ endpoints', () => {
    const results = findOAuthEndpoints(['https://example.com/oauth2/authorize'], []);
    expect(results).toHaveLength(1);
  });
});

// ─── redirect_uri Bypass Variants ──────────────────────────────────────

describe('REDIRECT_URI_BYPASS_VARIANTS', () => {
  it('has at least 6 variants', () => {
    expect(REDIRECT_URI_BYPASS_VARIANTS.length).toBeGreaterThanOrEqual(6);
  });

  it('includes path traversal', () => {
    const names = REDIRECT_URI_BYPASS_VARIANTS.map(v => v.name);
    expect(names).toContain('path-traversal');
    expect(names).toContain('path-traversal-encoded');
  });

  it('includes at-sign bypass', () => {
    const names = REDIRECT_URI_BYPASS_VARIANTS.map(v => v.name);
    expect(names).toContain('at-sign');
  });

  it('includes backslash bypass', () => {
    const names = REDIRECT_URI_BYPASS_VARIANTS.map(v => v.name);
    expect(names).toContain('backslash');
  });

  it('includes fragment bypass', () => {
    const names = REDIRECT_URI_BYPASS_VARIANTS.map(v => v.name);
    expect(names).toContain('fragment');
  });

  it('all variants have name and suffix', () => {
    for (const variant of REDIRECT_URI_BYPASS_VARIANTS) {
      expect(variant.name).toBeTruthy();
      expect(variant.suffix).toBeTruthy();
    }
  });

  it('all suffixes reference evil domain', () => {
    for (const variant of REDIRECT_URI_BYPASS_VARIANTS) {
      expect(variant.suffix).toContain('evil');
    }
  });
});

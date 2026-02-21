import { describe, it, expect } from 'vitest';
import { parseScopePatterns, isInScope } from '../../src/utils/scope.js';

describe('parseScopePatterns', () => {
  it('parses include patterns', () => {
    const scope = parseScopePatterns('*.example.com,api.example.com');
    expect(scope.includePatterns).toEqual(['*.example.com', 'api.example.com']);
    expect(scope.excludePatterns).toEqual([]);
  });

  it('parses exclude patterns with - prefix', () => {
    const scope = parseScopePatterns('*.example.com,-admin.example.com');
    expect(scope.includePatterns).toEqual(['*.example.com']);
    expect(scope.excludePatterns).toEqual(['admin.example.com']);
  });

  it('handles empty input', () => {
    const scope = parseScopePatterns('');
    expect(scope.includePatterns).toEqual([]);
    expect(scope.excludePatterns).toEqual([]);
  });

  it('trims whitespace around patterns', () => {
    const scope = parseScopePatterns(' *.example.com , api.example.com ');
    expect(scope.includePatterns).toEqual(['*.example.com', 'api.example.com']);
  });

  it('filters out empty segments from consecutive commas', () => {
    const scope = parseScopePatterns('a.com,,b.com');
    expect(scope.includePatterns).toEqual(['a.com', 'b.com']);
  });

  it('handles only exclude patterns', () => {
    const scope = parseScopePatterns('-admin.example.com,-staging.example.com');
    expect(scope.includePatterns).toEqual([]);
    expect(scope.excludePatterns).toEqual(['admin.example.com', 'staging.example.com']);
  });
});

describe('isInScope', () => {
  const target = 'https://example.com';

  it('defaults to same-origin when no scope', () => {
    expect(isInScope('https://example.com/page', target)).toBe(true);
    expect(isInScope('https://other.com/page', target)).toBe(false);
  });

  it('defaults to same-origin when scope has empty includePatterns', () => {
    const scope = parseScopePatterns('-admin.example.com');
    expect(isInScope('https://example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://other.com/page', target, scope)).toBe(false);
  });

  it('matches wildcard patterns', () => {
    const scope = parseScopePatterns('*.example.com');
    expect(isInScope('https://sub.example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://evil.com/page', target, scope)).toBe(false);
  });

  it('matches exact hostname patterns', () => {
    const scope = parseScopePatterns('api.example.com');
    expect(isInScope('https://api.example.com/v1/users', target, scope)).toBe(true);
    expect(isInScope('https://web.example.com/', target, scope)).toBe(false);
  });

  it('respects exclude patterns', () => {
    const scope = parseScopePatterns('*.example.com,-admin.example.com');
    expect(isInScope('https://api.example.com/page', target, scope)).toBe(true);
    expect(isInScope('https://admin.example.com/page', target, scope)).toBe(false);
  });

  it('excludes take priority over includes', () => {
    // admin.example.com matches both *.example.com (include) and admin.example.com (exclude)
    // excludes are checked first, so it should be excluded
    const scope = parseScopePatterns('*.example.com,-admin.example.com');
    expect(isInScope('https://admin.example.com/', target, scope)).toBe(false);
  });

  it('returns false for invalid URLs', () => {
    expect(isInScope('not-a-url', target)).toBe(false);
  });

  it('returns false when URL is valid but target is invalid', () => {
    expect(isInScope('https://example.com/', 'not-a-url')).toBe(false);
  });

  it('returns false for URLs that match no include pattern', () => {
    const scope = parseScopePatterns('api.example.com');
    expect(isInScope('https://unrelated.com/page', target, scope)).toBe(false);
  });

  it('handles deeply nested subdomains with wildcard', () => {
    const scope = parseScopePatterns('*.example.com');
    expect(isInScope('https://a.b.example.com/page', target, scope)).toBe(true);
  });
});

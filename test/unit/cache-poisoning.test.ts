import { describe, it, expect } from 'vitest';
import { cachePoisoningCheck, detectCaching, isCacheHit } from '../../src/scanner/active/cache-poisoning.js';

describe('detectCaching', () => {
  it('returns true when x-cache header present', () => {
    expect(detectCaching({ 'x-cache': 'MISS' })).toBe(true);
  });

  it('returns true when X-Cache header present (case insensitive)', () => {
    expect(detectCaching({ 'X-Cache': 'HIT' })).toBe(true);
  });

  it('returns true when cf-cache-status header present', () => {
    expect(detectCaching({ 'cf-cache-status': 'HIT' })).toBe(true);
  });

  it('returns true when age header present', () => {
    expect(detectCaching({ 'age': '120' })).toBe(true);
  });

  it('returns true when x-varnish header present', () => {
    expect(detectCaching({ 'x-varnish': '12345' })).toBe(true);
  });

  it('returns true when x-cache-hit header present', () => {
    expect(detectCaching({ 'x-cache-hit': 'true' })).toBe(true);
  });

  it('returns true when x-cdn-cache header present', () => {
    expect(detectCaching({ 'x-cdn-cache': 'HIT' })).toBe(true);
  });

  it('returns true when x-proxy-cache header present', () => {
    expect(detectCaching({ 'x-proxy-cache': 'HIT' })).toBe(true);
  });

  it('returns false for normal non-cache headers', () => {
    expect(detectCaching({
      'content-type': 'text/html',
      'server': 'nginx',
      'content-length': '1234',
    })).toBe(false);
  });

  it('returns false for empty headers', () => {
    expect(detectCaching({})).toBe(false);
  });

  it('returns true when multiple cache headers present', () => {
    expect(detectCaching({
      'x-cache': 'HIT',
      'age': '60',
      'content-type': 'text/html',
    })).toBe(true);
  });
});

describe('isCacheHit', () => {
  it('returns true when x-cache is "hit"', () => {
    expect(isCacheHit({ 'x-cache': 'hit' })).toBe(true);
  });

  it('returns true when x-cache is "HIT" (case insensitive)', () => {
    expect(isCacheHit({ 'x-cache': 'HIT' })).toBe(true);
  });

  it('returns true when cf-cache-status is "hit"', () => {
    expect(isCacheHit({ 'cf-cache-status': 'HIT' })).toBe(true);
  });

  it('returns true when x-cache-hit is "true"', () => {
    expect(isCacheHit({ 'x-cache-hit': 'true' })).toBe(true);
  });

  it('returns true when age is > 0', () => {
    expect(isCacheHit({ 'age': '120' })).toBe(true);
  });

  it('returns false when x-cache is "miss"', () => {
    expect(isCacheHit({ 'x-cache': 'miss' })).toBe(false);
  });

  it('returns false when cf-cache-status is "miss"', () => {
    expect(isCacheHit({ 'cf-cache-status': 'miss' })).toBe(false);
  });

  it('returns false when age is 0', () => {
    expect(isCacheHit({ 'age': '0' })).toBe(false);
  });

  it('returns false for non-cache headers', () => {
    expect(isCacheHit({
      'content-type': 'text/html',
      'server': 'nginx',
    })).toBe(false);
  });

  it('returns false for empty headers', () => {
    expect(isCacheHit({})).toBe(false);
  });
});

describe('cachePoisoningCheck', () => {
  it('has correct name', () => {
    expect(cachePoisoningCheck.name).toBe('cache-poisoning');
  });

  it('has correct category', () => {
    expect(cachePoisoningCheck.category).toBe('cache-poisoning');
  });

  it('is marked as parallel', () => {
    expect(cachePoisoningCheck.parallel).toBe(true);
  });

  it('has a run function', () => {
    expect(typeof cachePoisoningCheck.run).toBe('function');
  });

  it('returns empty array when no pages or api endpoints', async () => {
    const mockContext = {} as import('playwright').BrowserContext;
    const targets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };
    const config = {
      targetUrl: 'https://example.com',
      profile: 'standard' as const,
      timeout: 5000,
    } as import('../../src/scanner/types.js').ScanConfig;

    const findings = await cachePoisoningCheck.run(mockContext, targets, config);
    expect(findings).toEqual([]);
  });
});

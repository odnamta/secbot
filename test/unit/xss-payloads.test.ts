import { describe, it, expect } from 'vitest';
import { XSS_PAYLOADS, XSS_MARKERS } from '../../src/config/payloads/xss.js';
import { collectSearchUrls, SEARCH_PARAM_RE } from '../../src/scanner/active/xss.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('SEARCH_PARAM_RE', () => {
  it('matches common search parameter names', () => {
    const shouldMatch = ['q', 'query', 'search', 's', 'keyword', 'term', 'text', 'find', 'filter', 'k', 'key', 'name', 'input'];
    for (const name of shouldMatch) {
      expect(SEARCH_PARAM_RE.test(name)).toBe(true);
    }
  });

  it('matches case-insensitively', () => {
    expect(SEARCH_PARAM_RE.test('Q')).toBe(true);
    expect(SEARCH_PARAM_RE.test('Query')).toBe(true);
    expect(SEARCH_PARAM_RE.test('SEARCH')).toBe(true);
    expect(SEARCH_PARAM_RE.test('Search')).toBe(true);
  });

  it('does NOT match non-search parameter names', () => {
    const shouldNotMatch = ['id', 'page', 'limit', 'offset', 'token', 'sort', 'order', 'callback', 'redirect', 'url', 'format'];
    for (const name of shouldNotMatch) {
      expect(SEARCH_PARAM_RE.test(name)).toBe(false);
    }
  });

  it('does NOT match partial names (requires full match)', () => {
    expect(SEARCH_PARAM_RE.test('queries')).toBe(false);
    expect(SEARCH_PARAM_RE.test('searching')).toBe(false);
    expect(SEARCH_PARAM_RE.test('mysearch')).toBe(false);
  });
});

describe('collectSearchUrls', () => {
  function makeTargets(overrides: Partial<ScanTargets> = {}): ScanTargets {
    return {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
      ...overrides,
    };
  }

  it('collects URLs with search-like query parameters', () => {
    const targets = makeTargets({
      urlsWithParams: [
        'http://example.com/search?q=test',
        'http://example.com/results?query=hello',
        'http://example.com/find?s=world',
      ],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(3);
    expect(results[0].param).toBe('q');
    expect(results[1].param).toBe('query');
    expect(results[2].param).toBe('s');
  });

  it('ignores URLs with non-search parameters', () => {
    const targets = makeTargets({
      urlsWithParams: [
        'http://example.com/page?id=123',
        'http://example.com/list?page=2&limit=10',
      ],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(0);
  });

  it('deduplicates same path + param combination', () => {
    const targets = makeTargets({
      urlsWithParams: [
        'http://example.com/search?q=test1',
        'http://example.com/search?q=test2',
        'http://example.com/search?q=test3',
      ],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('q');
  });

  it('treats different paths as separate entries', () => {
    const targets = makeTargets({
      urlsWithParams: [
        'http://example.com/search?q=test',
        'http://example.com/api/search?q=test',
      ],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(2);
  });

  it('auto-adds q param for search-like page paths without params', () => {
    const targets = makeTargets({
      pages: [
        'http://example.com/search',
        'http://example.com/find',
        'http://example.com/results',
      ],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(3);
    expect(results.every(r => r.param === 'q')).toBe(true);
  });

  it('does NOT auto-add params for non-search page paths', () => {
    const targets = makeTargets({
      pages: [
        'http://example.com/about',
        'http://example.com/contact',
        'http://example.com/login',
      ],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(0);
  });

  it('handles mixed URL and page inputs correctly', () => {
    const targets = makeTargets({
      urlsWithParams: ['http://example.com/api/search?q=hello'],
      pages: ['http://example.com/search'],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(2);
  });

  it('handles invalid URLs gracefully', () => {
    const targets = makeTargets({
      urlsWithParams: ['not-a-url', '', 'http://example.com/search?q=test'],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('q');
  });

  it('collects multiple search params from same URL', () => {
    const targets = makeTargets({
      urlsWithParams: ['http://example.com/search?q=test&filter=name&keyword=hello'],
    });

    const results = collectSearchUrls(targets);
    // Should collect both q and keyword (filter is matched by SEARCH_PARAM_RE too)
    expect(results.length).toBeGreaterThanOrEqual(2);
    const params = results.map(r => r.param);
    expect(params).toContain('q');
    expect(params).toContain('keyword');
  });
});

describe('XSS Payloads', () => {
  it('has at least 30 payloads', () => {
    expect(XSS_PAYLOADS.length).toBeGreaterThanOrEqual(30);
  });

  it('each payload contains its marker', () => {
    for (const p of XSS_PAYLOADS) {
      expect(p.payload).toContain(p.marker);
    }
  });

  it('all markers are unique', () => {
    const markers = XSS_PAYLOADS.map(p => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it('has multiple payload types', () => {
    const types = new Set(XSS_PAYLOADS.map(p => p.type));
    expect(types.size).toBeGreaterThanOrEqual(3);
  });

  it('has reflected payloads', () => {
    const reflected = XSS_PAYLOADS.filter(p => p.type === 'reflected');
    expect(reflected.length).toBeGreaterThan(0);
  });

  it('has event-handler payloads', () => {
    const eventHandler = XSS_PAYLOADS.filter(p => p.type === 'event-handler');
    expect(eventHandler.length).toBeGreaterThan(0);
  });

  it('has template payloads', () => {
    const template = XSS_PAYLOADS.filter(p => p.type === 'template');
    expect(template.length).toBeGreaterThan(0);
  });

  it('has dom payloads', () => {
    const dom = XSS_PAYLOADS.filter(p => p.type === 'dom');
    expect(dom.length).toBeGreaterThan(0);
  });

  it('each payload has valid type', () => {
    const validTypes = ['reflected', 'dom', 'event-handler', 'template'];
    for (const p of XSS_PAYLOADS) {
      expect(validTypes).toContain(p.type);
    }
  });

  it('markers follow secbot-xss-N naming convention', () => {
    for (const p of XSS_PAYLOADS) {
      expect(p.marker).toMatch(/^secbot-xss-\d+$/);
    }
  });

  it('deprecated XSS_MARKERS array matches payloads', () => {
    expect(XSS_MARKERS.length).toBe(XSS_PAYLOADS.length);
    for (let i = 0; i < XSS_PAYLOADS.length; i++) {
      expect(XSS_MARKERS[i]).toBe(XSS_PAYLOADS[i].marker);
    }
  });
});

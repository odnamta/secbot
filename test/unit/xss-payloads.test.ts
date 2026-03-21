import { describe, it, expect } from 'vitest';
import { XSS_PAYLOADS, XSS_MARKERS, JS_CONTEXT_PAYLOADS, DANGLING_MARKUP_PAYLOADS } from '../../src/config/payloads/xss.js';
import { collectSearchUrls, SEARCH_PARAM_RE, checkJsStringBreakout } from '../../src/scanner/active/xss.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';
import type { ScanConfig } from '../../src/scanner/types.js';

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
        'http://example.com/products/search?q=test',
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
      urlsWithParams: ['http://example.com/products/search?q=hello'],
      pages: ['http://example.com/search'],
    });

    const results = collectSearchUrls(targets);
    expect(results).toHaveLength(2);
  });

  it('filters out REST/API endpoints for SPA DOM XSS', () => {
    const targets = makeTargets({
      urlsWithParams: [
        'http://example.com/search?q=test',
        'http://example.com/api/search?q=test',
        'http://example.com/rest/products/search?q=test',
      ],
    });

    const results = collectSearchUrls(targets);
    // Only the non-API endpoint should remain
    expect(results).toHaveLength(1);
    expect(results[0].url).toBe('http://example.com/search?q=test');
  });

  it('generates hash-based search routes when framework is detected', () => {
    const targets = makeTargets({
      urlsWithParams: ['http://example.com/rest/products/search?q=test'],
      pages: ['http://example.com/'],
    });

    const config = { detectedFramework: { name: 'angular', router: 'angular-router', evidence: [] } } as ScanConfig;
    const results = collectSearchUrls(targets, config);
    // Should generate /#/search?q=test from the API endpoint
    expect(results.some(r => r.url.includes('#/search'))).toBe(true);
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

  it('has framework-specific template payloads (Angular/Vue)', () => {
    const template = XSS_PAYLOADS.filter(p => p.type === 'template');
    // Angular sandbox escape
    const angularPayloads = template.filter(p =>
      p.payload.includes('$on.constructor') || p.payload.includes('$eval'),
    );
    expect(angularPayloads.length).toBeGreaterThanOrEqual(1);

    // Vue template injection
    const vuePayloads = template.filter(p =>
      p.payload.includes('_c.constructor') || p.payload.includes('$el.constructor'),
    );
    expect(vuePayloads.length).toBeGreaterThanOrEqual(1);
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

describe('JS Context Payloads', () => {
  it('has at least 7 JS context payloads', () => {
    expect(JS_CONTEXT_PAYLOADS.length).toBeGreaterThanOrEqual(7);
  });

  it('each payload contains its marker', () => {
    for (const p of JS_CONTEXT_PAYLOADS) {
      expect(p.payload).toContain(p.marker);
    }
  });

  it('all markers are unique', () => {
    const markers = JS_CONTEXT_PAYLOADS.map(p => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it('has double-quote string breakout payload', () => {
    expect(JS_CONTEXT_PAYLOADS.some(p => p.payload.startsWith('";'))).toBe(true);
  });

  it('has single-quote string breakout payload', () => {
    expect(JS_CONTEXT_PAYLOADS.some(p => p.payload.startsWith("';"))).toBe(true);
  });

  it('has script tag closure payload (universal JS escape)', () => {
    expect(JS_CONTEXT_PAYLOADS.some(p => p.payload.includes('</script>'))).toBe(true);
  });

  it('has backslash escape bypass payload', () => {
    expect(JS_CONTEXT_PAYLOADS.some(p => p.payload.startsWith('\\";'))).toBe(true);
  });

  it('has JSON concatenation breakout payload', () => {
    expect(JS_CONTEXT_PAYLOADS.some(p => p.payload.startsWith('"+'))).toBe(true);
  });

  it('has numeric assignment breakout payload', () => {
    expect(JS_CONTEXT_PAYLOADS.some(p => p.payload.startsWith('1;'))).toBe(true);
  });

  it('no marker collisions with main XSS_PAYLOADS', () => {
    const mainMarkers = new Set(XSS_PAYLOADS.map(p => p.marker));
    for (const p of JS_CONTEXT_PAYLOADS) {
      expect(mainMarkers.has(p.marker)).toBe(false);
    }
  });
});

describe('checkJsStringBreakout', () => {
  it('detects double-quote breakout in script block', () => {
    const payload = '";alert("secbot-xss-51");//';
    const content = `<html><body>
      <script>var q = "${payload}";</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).not.toBeNull();
    expect(result).toContain('JS string breakout');
  });

  it('detects single-quote breakout in script block', () => {
    const payload = "';alert('secbot-xss-52');//";
    const content = `<html><body>
      <script>var q = '${payload}';</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).not.toBeNull();
  });

  it('detects backslash escape bypass in script block', () => {
    const payload = '\\";alert("secbot-xss-54");//';
    const content = `<html><body>
      <script>var q = "${payload}";</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).not.toBeNull();
  });

  it('returns null for payload outside script blocks', () => {
    const payload = '";alert("secbot-xss-51");//';
    const content = `<html><body><div>${payload}</div></body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).toBeNull();
  });

  it('returns null for payload NOT starting with quote terminator', () => {
    const payload = '<script>alert(1)</script>';
    const content = `<html><body>
      <script>var q = "${payload}";</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).toBeNull();
  });

  it('returns null when payload is properly JSON-escaped', () => {
    const rawPayload = '";alert("secbot-xss-51");//';
    const escaped = rawPayload.replace(/"/g, '\\"');
    const content = `<html><body>
      <script>var q = "${escaped}";</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, rawPayload);
    expect(result).toBeNull();
  });

  it('returns null for Next.js __NEXT_DATA__ JSON (no breakout)', () => {
    const payload = '";alert("secbot-xss-51");//';
    const jsonEscaped = JSON.stringify(payload).slice(1, -1);
    const content = `<html><body>
      <script id="__NEXT_DATA__" type="application/json">{"props":{"q":"${jsonEscaped}"}}</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).toBeNull();
  });

  it('handles multiple script blocks — detects in any', () => {
    const payload = '";alert("secbot-xss-51");//';
    const content = `<html><body>
      <script>var a = "safe";</script>
      <script>var q = "${payload}";</script>
      <script>var b = "also safe";</script>
    </body></html>`;
    const result = checkJsStringBreakout(content, payload);
    expect(result).not.toBeNull();
  });
});

describe('DANGLING_MARKUP_PAYLOADS', () => {
  it('has at least 5 dangling markup payloads', () => {
    expect(DANGLING_MARKUP_PAYLOADS.length).toBeGreaterThanOrEqual(5);
  });

  it('all payloads have payload, marker, and type fields', () => {
    for (const p of DANGLING_MARKUP_PAYLOADS) {
      expect(p.payload).toBeTruthy();
      expect(p.marker).toBeTruthy();
      expect(p.type).toBe('reflected');
    }
  });

  it('all markers start with secbot-dm-', () => {
    for (const p of DANGLING_MARKUP_PAYLOADS) {
      expect(p.marker).toMatch(/^secbot-dm-\d+$/);
    }
  });

  it('includes unclosed img src exfiltration', () => {
    const img = DANGLING_MARKUP_PAYLOADS.filter(p => p.payload.includes('<img') && p.payload.includes('src='));
    expect(img.length).toBeGreaterThanOrEqual(1);
  });

  it('includes form action hijack', () => {
    const form = DANGLING_MARKUP_PAYLOADS.filter(p => p.payload.includes('<form') && p.payload.includes('action='));
    expect(form.length).toBeGreaterThanOrEqual(1);
  });

  it('includes base tag hijack', () => {
    const base = DANGLING_MARKUP_PAYLOADS.filter(p => p.payload.includes('<base'));
    expect(base.length).toBeGreaterThanOrEqual(1);
  });

  it('includes textarea capture', () => {
    const textarea = DANGLING_MARKUP_PAYLOADS.filter(p => p.payload.includes('<textarea'));
    expect(textarea.length).toBeGreaterThanOrEqual(1);
  });

  it('includes meta refresh exfiltration', () => {
    const meta = DANGLING_MARKUP_PAYLOADS.filter(p => p.payload.includes('<meta') && p.payload.includes('refresh'));
    expect(meta.length).toBeGreaterThanOrEqual(1);
  });

  it('all payloads start with attribute close', () => {
    for (const p of DANGLING_MARKUP_PAYLOADS) {
      expect(p.payload.startsWith('">')).toBe(true);
    }
  });

  it('markers are unique', () => {
    const markers = DANGLING_MARKUP_PAYLOADS.map(p => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });
});

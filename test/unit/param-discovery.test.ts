import { describe, it, expect } from 'vitest';
import {
  fingerprint,
  compareFingerprints,
  buildProbeUrl,
  discoveredParamsToUrls,
  COMMON_PARAMS,
} from '../../src/scanner/discovery/param-discovery.js';
import type { FastResponse } from '../../src/scanner/fast-engine.js';
import type { ResponseFingerprint, DiscoveredParam } from '../../src/scanner/discovery/param-discovery.js';

/** Helper to build a FastResponse for testing */
function makeResponse(overrides: Partial<FastResponse> = {}): FastResponse {
  return {
    url: 'https://example.com/',
    status: 200,
    headers: {
      'content-type': 'text/html',
      'x-powered-by': 'Express',
    },
    body: '<html><body>Hello World</body></html>',
    redirected: false,
    timeMs: 100,
    ...overrides,
  };
}

describe('param-discovery', () => {
  describe('COMMON_PARAMS', () => {
    it('contains a substantial number of params', () => {
      expect(COMMON_PARAMS.length).toBeGreaterThan(80);
    });

    it('includes critical debug/admin params', () => {
      expect(COMMON_PARAMS).toContain('debug');
      expect(COMMON_PARAMS).toContain('admin');
      expect(COMMON_PARAMS).toContain('verbose');
      expect(COMMON_PARAMS).toContain('test');
    });

    it('includes common injection target params', () => {
      expect(COMMON_PARAMS).toContain('id');
      expect(COMMON_PARAMS).toContain('q');
      expect(COMMON_PARAMS).toContain('search');
      expect(COMMON_PARAMS).toContain('url');
      expect(COMMON_PARAMS).toContain('redirect');
      expect(COMMON_PARAMS).toContain('file');
    });

    it('includes auth-related params', () => {
      expect(COMMON_PARAMS).toContain('token');
      expect(COMMON_PARAMS).toContain('api_key');
      expect(COMMON_PARAMS).toContain('role');
      expect(COMMON_PARAMS).toContain('access_token');
    });

    it('has no duplicates', () => {
      const unique = new Set(COMMON_PARAMS);
      expect(unique.size).toBe(COMMON_PARAMS.length);
    });
  });

  describe('fingerprint', () => {
    it('captures status, body length, and header info', () => {
      const resp = makeResponse();
      const fp = fingerprint(resp);
      expect(fp.status).toBe(200);
      expect(fp.bodyLength).toBe(resp.body.length);
      expect(fp.headerCount).toBe(2);
      expect(fp.headerNames).toEqual(['content-type', 'x-powered-by']);
    });

    it('sorts header names alphabetically', () => {
      const resp = makeResponse({
        headers: { 'z-header': '1', 'a-header': '2', 'm-header': '3' },
      });
      const fp = fingerprint(resp);
      expect(fp.headerNames).toEqual(['a-header', 'm-header', 'z-header']);
    });

    it('builds body sketch for short bodies', () => {
      const resp = makeResponse({ body: 'short' });
      const fp = fingerprint(resp);
      expect(fp.bodySketch).toBe('short');
    });

    it('builds body sketch from first+last 200 chars for long bodies', () => {
      const longBody = 'A'.repeat(200) + 'B'.repeat(200) + 'C'.repeat(200);
      const resp = makeResponse({ body: longBody });
      const fp = fingerprint(resp);
      // First 200 = AAAA..., Last 200 = BBBB...CCCC... (200 Bs + 200 Cs = last 200 is all Cs)
      expect(fp.bodySketch.length).toBe(400);
      expect(fp.bodySketch.startsWith('A'.repeat(200))).toBe(true);
      expect(fp.bodySketch.endsWith('C'.repeat(200))).toBe(true);
    });
  });

  describe('compareFingerprints', () => {
    const baseline: ResponseFingerprint = {
      status: 200,
      bodyLength: 1000,
      headerCount: 3,
      headerNames: ['content-type', 'server', 'x-request-id'],
      bodySketch: 'hello world',
    };

    it('returns null when fingerprints are identical', () => {
      const probe = { ...baseline };
      expect(compareFingerprints(baseline, probe)).toBeNull();
    });

    it('detects error-triggered when status goes from 2xx to 5xx', () => {
      const probe: ResponseFingerprint = { ...baseline, status: 500 };
      expect(compareFingerprints(baseline, probe)).toBe('error-triggered');
    });

    it('detects error-triggered when status goes from 2xx to 4xx', () => {
      const probe: ResponseFingerprint = { ...baseline, status: 400 };
      expect(compareFingerprints(baseline, probe)).toBe('error-triggered');
    });

    it('detects status-change for redirect (200 -> 302)', () => {
      const probe: ResponseFingerprint = { ...baseline, status: 302 };
      expect(compareFingerprints(baseline, probe)).toBe('status-change');
    });

    it('detects status-change when 404 -> 200', () => {
      const bl: ResponseFingerprint = { ...baseline, status: 404 };
      const probe: ResponseFingerprint = { ...baseline, status: 200 };
      expect(compareFingerprints(bl, probe)).toBe('status-change');
    });

    it('detects header-change when new headers appear', () => {
      const probe: ResponseFingerprint = {
        ...baseline,
        headerCount: 5,
        headerNames: ['content-type', 'server', 'x-debug', 'x-request-id', 'x-trace'],
      };
      expect(compareFingerprints(baseline, probe)).toBe('header-change');
    });

    it('does not flag header-change when headers are removed (fewer headers)', () => {
      const probe: ResponseFingerprint = {
        ...baseline,
        headerCount: 2,
        headerNames: ['content-type', 'server'],
      };
      expect(compareFingerprints(baseline, probe)).toBeNull();
    });

    it('detects body-change when body length differs >10%', () => {
      const probe: ResponseFingerprint = { ...baseline, bodyLength: 1200 };
      expect(compareFingerprints(baseline, probe)).toBe('body-change');
    });

    it('does not flag body-change for <10% difference', () => {
      const probe: ResponseFingerprint = { ...baseline, bodyLength: 1050 };
      expect(compareFingerprints(baseline, probe)).toBeNull();
    });

    it('detects body-change when baseline was empty and probe has content', () => {
      const emptyBaseline: ResponseFingerprint = { ...baseline, bodyLength: 0 };
      const probe: ResponseFingerprint = { ...baseline, bodyLength: 100 };
      expect(compareFingerprints(emptyBaseline, probe)).toBe('body-change');
    });

    it('does not flag body-change when baseline empty and probe has tiny body', () => {
      const emptyBaseline: ResponseFingerprint = { ...baseline, bodyLength: 0 };
      const probe: ResponseFingerprint = { ...baseline, bodyLength: 30 };
      expect(compareFingerprints(emptyBaseline, probe)).toBeNull();
    });

    it('prioritizes error-triggered over body-change', () => {
      // Status change AND body length change — status wins
      const probe: ResponseFingerprint = { ...baseline, status: 500, bodyLength: 5000 };
      expect(compareFingerprints(baseline, probe)).toBe('error-triggered');
    });

    it('prioritizes status-change over header-change', () => {
      const probe: ResponseFingerprint = {
        ...baseline,
        status: 301,
        headerCount: 5,
        headerNames: ['content-type', 'location', 'server', 'x-new', 'x-request-id'],
      };
      expect(compareFingerprints(baseline, probe)).toBe('status-change');
    });
  });

  describe('buildProbeUrl', () => {
    it('appends param to URL without existing query string', () => {
      const result = buildProbeUrl('https://example.com/page', 'debug', '1');
      expect(result).toBe('https://example.com/page?debug=1');
    });

    it('appends param to URL with existing query string', () => {
      const result = buildProbeUrl('https://example.com/page?existing=true', 'debug', '1');
      // URL constructor preserves existing params
      const u = new URL(result);
      expect(u.searchParams.get('existing')).toBe('true');
      expect(u.searchParams.get('debug')).toBe('1');
    });

    it('handles special characters in param value', () => {
      const result = buildProbeUrl('https://example.com/', 'q', 'hello world');
      const u = new URL(result);
      expect(u.searchParams.get('q')).toBe('hello world');
    });

    it('overwrites param if it already exists', () => {
      const result = buildProbeUrl('https://example.com/?debug=false', 'debug', 'true');
      const u = new URL(result);
      expect(u.searchParams.get('debug')).toBe('true');
    });
  });

  describe('discoveredParamsToUrls', () => {
    it('converts discovered params into URLs', () => {
      const params: DiscoveredParam[] = [
        {
          url: 'https://example.com/',
          param: 'debug',
          evidence: 'status-change',
          baselineStatus: 200,
          probeStatus: 500,
          bodyLengthDiff: 0,
        },
        {
          url: 'https://example.com/',
          param: 'admin',
          evidence: 'body-change',
          baselineStatus: 200,
          probeStatus: 200,
          bodyLengthDiff: 500,
        },
      ];

      const urls = discoveredParamsToUrls(params);
      expect(urls).toHaveLength(2);
      expect(urls.some(u => u.includes('debug=1'))).toBe(true);
      expect(urls.some(u => u.includes('admin=1'))).toBe(true);
    });

    it('deduplicates URLs', () => {
      const params: DiscoveredParam[] = [
        {
          url: 'https://example.com/',
          param: 'debug',
          evidence: 'status-change',
          baselineStatus: 200,
          probeStatus: 500,
          bodyLengthDiff: 0,
        },
        {
          url: 'https://example.com/',
          param: 'debug',
          evidence: 'body-change',
          baselineStatus: 200,
          probeStatus: 200,
          bodyLengthDiff: 100,
        },
      ];

      const urls = discoveredParamsToUrls(params);
      // Same url+param should produce single URL
      expect(urls).toHaveLength(1);
    });

    it('returns empty array for no params', () => {
      expect(discoveredParamsToUrls([])).toEqual([]);
    });

    it('handles params across multiple base URLs', () => {
      const params: DiscoveredParam[] = [
        {
          url: 'https://example.com/page1',
          param: 'debug',
          evidence: 'status-change',
          baselineStatus: 200,
          probeStatus: 500,
          bodyLengthDiff: 0,
        },
        {
          url: 'https://example.com/page2',
          param: 'debug',
          evidence: 'status-change',
          baselineStatus: 200,
          probeStatus: 500,
          bodyLengthDiff: 0,
        },
      ];

      const urls = discoveredParamsToUrls(params);
      expect(urls).toHaveLength(2);
      expect(urls.some(u => u.includes('/page1?'))).toBe(true);
      expect(urls.some(u => u.includes('/page2?'))).toBe(true);
    });
  });
});

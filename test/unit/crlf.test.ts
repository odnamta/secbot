import { describe, it, expect } from 'vitest';
import {
  CRLF_PAYLOADS,
  CRLF_SENTINEL_HEADER,
  CRLF_SENTINEL_VALUE,
  REDIRECT_PARAM_NAMES,
  detectInjectedHeader,
  detectResponseSplitting,
  generateCrlfTestUrls,
} from '../../src/scanner/active/crlf.js';

describe('CRLF Injection — Unit Tests', () => {
  describe('CRLF_PAYLOADS', () => {
    it('has at least 4 payload variants', () => {
      expect(CRLF_PAYLOADS.length).toBeGreaterThanOrEqual(4);
    });

    it('includes url-encoded CRLF payload', () => {
      const encoded = CRLF_PAYLOADS.find((p) => p.name === 'url-encoded-crlf');
      expect(encoded).toBeDefined();
      expect(encoded!.payload).toContain('%0d%0a');
      expect(encoded!.payload).toContain(CRLF_SENTINEL_HEADER);
      expect(encoded!.payload).toContain(CRLF_SENTINEL_VALUE);
    });

    it('includes LF-only payload', () => {
      const lfOnly = CRLF_PAYLOADS.find((p) => p.name === 'url-encoded-lf-only');
      expect(lfOnly).toBeDefined();
      expect(lfOnly!.payload).toContain('%0a');
      expect(lfOnly!.payload).not.toContain('%0d');
    });

    it('includes response-splitting payload', () => {
      const splitting = CRLF_PAYLOADS.find((p) => p.name === 'response-splitting');
      expect(splitting).toBeDefined();
      expect(splitting!.payload).toContain('%0d%0a%0d%0a');
      expect(splitting!.payload).toContain('<script>');
    });

    it('includes literal CRLF payload', () => {
      const literal = CRLF_PAYLOADS.find((p) => p.name === 'literal-crlf');
      expect(literal).toBeDefined();
      expect(literal!.payload).toContain('\r\n');
    });
  });

  describe('REDIRECT_PARAM_NAMES', () => {
    it('contains common redirect parameter names', () => {
      const expected = ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'callback', 'location', 'path'];
      for (const name of expected) {
        expect(REDIRECT_PARAM_NAMES).toContain(name);
      }
    });
  });

  describe('detectInjectedHeader()', () => {
    it('returns true when sentinel header is present', () => {
      const headers: Record<string, string> = {
        'content-type': 'text/html',
        'injected-header': 'secbot-test',
      };
      expect(detectInjectedHeader(headers)).toBe(true);
    });

    it('returns true regardless of header name casing', () => {
      const headers: Record<string, string> = {
        'Injected-Header': 'secbot-test',
      };
      expect(detectInjectedHeader(headers)).toBe(true);
    });

    it('returns false when sentinel header is absent', () => {
      const headers: Record<string, string> = {
        'content-type': 'text/html',
        'x-custom': 'other-value',
      };
      expect(detectInjectedHeader(headers)).toBe(false);
    });

    it('returns false when header name matches but value does not', () => {
      const headers: Record<string, string> = {
        'injected-header': 'wrong-value',
      };
      expect(detectInjectedHeader(headers)).toBe(false);
    });

    it('handles empty headers object', () => {
      expect(detectInjectedHeader({})).toBe(false);
    });

    it('trims whitespace from header value', () => {
      const headers: Record<string, string> = {
        'injected-header': ' secbot-test ',
      };
      expect(detectInjectedHeader(headers)).toBe(true);
    });
  });

  describe('detectResponseSplitting()', () => {
    it('returns true when script tag is in body', () => {
      const body = 'HTTP/1.1 200 OK\r\n\r\n<script>alert(1)</script>';
      expect(detectResponseSplitting(body)).toBe(true);
    });

    it('returns false when script tag is absent', () => {
      const body = '<html><body>Normal page</body></html>';
      expect(detectResponseSplitting(body)).toBe(false);
    });

    it('returns false for empty body', () => {
      expect(detectResponseSplitting('')).toBe(false);
    });
  });

  describe('generateCrlfTestUrls()', () => {
    it('generates test URLs for each CRLF payload', () => {
      const results = generateCrlfTestUrls('http://example.com/page?q=test', 'q');
      expect(results.length).toBe(CRLF_PAYLOADS.length);
    });

    it('appends payload after original parameter value', () => {
      const results = generateCrlfTestUrls('http://example.com/page?q=original', 'q');
      for (const { url } of results) {
        const parsed = new URL(url);
        const value = parsed.searchParams.get('q') || '';
        expect(value.startsWith('original')).toBe(true);
      }
    });

    it('handles empty original parameter value', () => {
      const results = generateCrlfTestUrls('http://example.com/page?q=', 'q');
      expect(results.length).toBe(CRLF_PAYLOADS.length);
      // Each should have the payload as the value
      for (const { url, payload } of results) {
        const parsed = new URL(url);
        const value = parsed.searchParams.get('q') || '';
        // URL might re-encode things, but it should contain parts of the payload
        expect(value.length).toBeGreaterThan(0);
      }
    });

    it('preserves other query parameters', () => {
      const results = generateCrlfTestUrls('http://example.com/page?q=test&lang=en', 'q');
      for (const { url } of results) {
        const parsed = new URL(url);
        expect(parsed.searchParams.get('lang')).toBe('en');
      }
    });

    it('each result contains the corresponding payload metadata', () => {
      const results = generateCrlfTestUrls('http://example.com/page?q=test', 'q');
      for (let i = 0; i < results.length; i++) {
        expect(results[i].payload).toBe(CRLF_PAYLOADS[i]);
      }
    });
  });
});

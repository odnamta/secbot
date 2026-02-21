import { describe, it, expect } from 'vitest';
import {
  duplicateParam,
  arrayNotation,
  jsonBodyInjection,
  generateHppVariants,
} from '../../src/utils/param-pollution.js';

describe('HTTP Parameter Pollution', () => {
  const baseUrl = 'https://example.com/search?q=hello&page=1';

  describe('duplicateParam()', () => {
    it('returns 3 URL variants', () => {
      const results = duplicateParam(baseUrl, 'q', 'payload');
      expect(results).toHaveLength(3);
    });

    it('all variants are valid URLs', () => {
      const results = duplicateParam(baseUrl, 'q', 'payload');
      for (const url of results) {
        expect(() => new URL(url)).not.toThrow();
      }
    });

    it('variant 1 appends payload as second occurrence', () => {
      const results = duplicateParam(baseUrl, 'q', 'payload');
      const parsed = new URL(results[0]);
      const values = parsed.searchParams.getAll('q');
      expect(values).toContain('hello');
      expect(values).toContain('payload');
      // Original comes first, payload appended
      expect(values[0]).toBe('hello');
      expect(values[1]).toBe('payload');
    });

    it('variant 2 prepends payload as first occurrence', () => {
      const results = duplicateParam(baseUrl, 'q', 'payload');
      const parsed = new URL(results[1]);
      const values = parsed.searchParams.getAll('q');
      expect(values).toContain('payload');
      expect(values).toContain('hello');
      // Payload comes first
      expect(values[0]).toBe('payload');
      expect(values[1]).toBe('hello');
    });

    it('variant 3 has both occurrences set to payload', () => {
      const results = duplicateParam(baseUrl, 'q', 'payload');
      const parsed = new URL(results[2]);
      const values = parsed.searchParams.getAll('q');
      expect(values).toEqual(['payload', 'payload']);
    });

    it('preserves other parameters', () => {
      const results = duplicateParam(baseUrl, 'q', 'payload');
      for (const url of results) {
        const parsed = new URL(url);
        expect(parsed.searchParams.get('page')).toBe('1');
      }
    });

    it('works when parameter does not exist in URL', () => {
      const results = duplicateParam(baseUrl, 'newparam', 'payload');
      expect(results).toHaveLength(3);
      for (const url of results) {
        expect(() => new URL(url)).not.toThrow();
      }
    });

    it('handles special characters in payload', () => {
      const results = duplicateParam(baseUrl, 'q', "' OR 1=1--");
      expect(results).toHaveLength(3);
      for (const url of results) {
        expect(() => new URL(url)).not.toThrow();
      }
    });
  });

  describe('arrayNotation()', () => {
    it('returns 3 URL variants', () => {
      const results = arrayNotation(baseUrl, 'q', 'payload');
      expect(results).toHaveLength(3);
    });

    it('all variants are valid URLs', () => {
      const results = arrayNotation(baseUrl, 'q', 'payload');
      for (const url of results) {
        expect(() => new URL(url)).not.toThrow();
      }
    });

    it('variant 1 uses bracket notation param[]', () => {
      const results = arrayNotation(baseUrl, 'q', 'payload');
      // URL encodes brackets, so check the decoded form
      const url = decodeURIComponent(results[0]);
      expect(url).toContain('q[]=payload');
    });

    it('variant 2 uses indexed notation param[0]', () => {
      const results = arrayNotation(baseUrl, 'q', 'payload');
      const url = decodeURIComponent(results[1]);
      expect(url).toContain('q[0]=payload');
    });

    it('variant 3 keeps original param alongside array notation', () => {
      const results = arrayNotation(baseUrl, 'q', 'payload');
      const parsed = new URL(results[2]);
      // Should have original 'q' AND 'q[]'
      expect(parsed.searchParams.get('q')).toBe('hello');
      expect(parsed.searchParams.get('q[]')).toBe('payload');
    });

    it('preserves other parameters', () => {
      const results = arrayNotation(baseUrl, 'q', 'payload');
      for (const url of results) {
        const parsed = new URL(url);
        expect(parsed.searchParams.get('page')).toBe('1');
      }
    });

    it('handles special characters in payload', () => {
      const results = arrayNotation(baseUrl, 'q', '<script>alert(1)</script>');
      expect(results).toHaveLength(3);
      for (const url of results) {
        expect(() => new URL(url)).not.toThrow();
      }
    });
  });

  describe('jsonBodyInjection()', () => {
    it('returns an object', () => {
      const result = jsonBodyInjection('username', 'admin');
      expect(typeof result).toBe('object');
      expect(result).not.toBeNull();
    });

    it('contains the param as a top-level key', () => {
      const result = jsonBodyInjection('username', 'admin') as Record<string, unknown>;
      expect(result['username']).toBe('admin');
    });

    it('contains a nested data object with the param', () => {
      const result = jsonBodyInjection('username', 'admin') as Record<string, unknown>;
      const data = result['data'] as Record<string, unknown>;
      expect(data).toBeDefined();
      expect(data['username']).toBe('admin');
    });

    it('contains array notation key', () => {
      const result = jsonBodyInjection('q', 'payload') as Record<string, unknown>;
      expect(result['q[]']).toBeDefined();
      expect(Array.isArray(result['q[]'])).toBe(true);
    });

    it('is JSON-serializable', () => {
      const result = jsonBodyInjection('test', "' OR 1=1--");
      expect(() => JSON.stringify(result)).not.toThrow();
    });

    it('preserves SQLi payload values', () => {
      const payload = "' UNION SELECT NULL--";
      const result = jsonBodyInjection('id', payload) as Record<string, unknown>;
      expect(result['id']).toBe(payload);
    });
  });

  describe('generateHppVariants()', () => {
    it('returns a non-empty array', () => {
      const results = generateHppVariants(baseUrl, 'q', 'payload');
      expect(results.length).toBeGreaterThan(0);
    });

    it('all results are valid URLs', () => {
      const results = generateHppVariants(baseUrl, 'q', 'payload');
      for (const url of results) {
        expect(() => new URL(url)).not.toThrow();
      }
    });

    it('has no duplicate URLs', () => {
      const results = generateHppVariants(baseUrl, 'q', 'payload');
      const unique = new Set(results);
      expect(results.length).toBe(unique.size);
    });

    it('includes variants from duplicateParam', () => {
      const hppVariants = generateHppVariants(baseUrl, 'q', 'payload');
      const dupVariants = duplicateParam(baseUrl, 'q', 'payload');
      // All duplicateParam variants should be in the result
      for (const v of dupVariants) {
        expect(hppVariants).toContain(v);
      }
    });

    it('includes variants from arrayNotation', () => {
      const hppVariants = generateHppVariants(baseUrl, 'q', 'payload');
      const arrVariants = arrayNotation(baseUrl, 'q', 'payload');
      // All arrayNotation variants should be in the result
      for (const v of arrVariants) {
        expect(hppVariants).toContain(v);
      }
    });

    it('combines both techniques into 6 variants', () => {
      const results = generateHppVariants(baseUrl, 'q', 'payload');
      // 3 from duplicateParam + 3 from arrayNotation = 6 (may be fewer if deduped)
      expect(results.length).toBeGreaterThanOrEqual(5);
      expect(results.length).toBeLessThanOrEqual(6);
    });
  });
});

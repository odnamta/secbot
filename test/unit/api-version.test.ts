import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  extractVersionInfo,
  generateOlderVersionUrls,
  apiVersionCheck,
} from '../../src/scanner/active/api-version.js';

// Mock the logger to suppress output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('API Version Discovery — Unit Tests', () => {
  describe('metadata', () => {
    it('has correct name', () => {
      expect(apiVersionCheck.name).toBe('api-version');
    });

    it('has correct category', () => {
      expect(apiVersionCheck.category).toBe('api-versioning');
    });

    it('has parallel set to true', () => {
      expect(apiVersionCheck.parallel).toBe(true);
    });
  });

  describe('extractVersionInfo()', () => {
    it('extracts version from /api/v2/users', () => {
      const result = extractVersionInfo('https://example.com/api/v2/users');
      expect(result).not.toBeNull();
      expect(result!.currentVersion).toBe(2);
      expect(result!.prefix).toBe('/api/v');
      expect(result!.suffix).toBe('/users');
    });

    it('extracts version from /v3/api/data', () => {
      const result = extractVersionInfo('https://example.com/v3/api/data');
      expect(result).not.toBeNull();
      expect(result!.currentVersion).toBe(3);
      expect(result!.prefix).toBe('/v');
      expect(result!.suffix).toBe('/api/data');
    });

    it('extracts version from /api/v10/resource', () => {
      const result = extractVersionInfo('https://example.com/api/v10/resource');
      expect(result).not.toBeNull();
      expect(result!.currentVersion).toBe(10);
    });

    it('returns null for v1 (nothing older to probe)', () => {
      const result = extractVersionInfo('https://example.com/api/v1/users');
      expect(result).toBeNull();
    });

    it('returns null for non-versioned URL', () => {
      const result = extractVersionInfo('https://example.com/api/users');
      expect(result).toBeNull();
    });

    it('returns null for URL without version pattern', () => {
      const result = extractVersionInfo('https://example.com/about');
      expect(result).toBeNull();
    });

    it('returns null for invalid URL', () => {
      const result = extractVersionInfo('not-a-url');
      expect(result).toBeNull();
    });

    it('handles version at end of path without trailing segment', () => {
      const result = extractVersionInfo('https://example.com/api/v2/');
      expect(result).not.toBeNull();
      expect(result!.currentVersion).toBe(2);
      expect(result!.suffix).toBe('/');
    });
  });

  describe('generateOlderVersionUrls()', () => {
    it('generates v1 from /api/v2/users', () => {
      const urls = generateOlderVersionUrls('https://example.com/api/v2/users');
      expect(urls).toHaveLength(1);
      expect(urls[0]).toBe('https://example.com/api/v1/users');
    });

    it('generates v2 and v1 from /api/v3/users', () => {
      const urls = generateOlderVersionUrls('https://example.com/api/v3/users');
      expect(urls).toHaveLength(2);
      expect(urls[0]).toBe('https://example.com/api/v2/users');
      expect(urls[1]).toBe('https://example.com/api/v1/users');
    });

    it('generates v3 and v2 from /v4/api/data', () => {
      const urls = generateOlderVersionUrls('https://example.com/v4/api/data');
      expect(urls).toHaveLength(2);
      expect(urls[0]).toBe('https://example.com/v3/api/data');
      expect(urls[1]).toBe('https://example.com/v2/api/data');
    });

    it('returns empty array for non-versioned URL', () => {
      const urls = generateOlderVersionUrls('https://example.com/api/users');
      expect(urls).toHaveLength(0);
    });

    it('returns empty array for v1 URL', () => {
      const urls = generateOlderVersionUrls('https://example.com/api/v1/users');
      expect(urls).toHaveLength(0);
    });

    it('preserves query parameters', () => {
      const urls = generateOlderVersionUrls('https://example.com/api/v2/users?page=1&limit=10');
      expect(urls).toHaveLength(1);
      expect(urls[0]).toContain('/api/v1/users');
      expect(urls[0]).toContain('page=1');
      expect(urls[0]).toContain('limit=10');
    });

    it('preserves hostname and protocol', () => {
      const urls = generateOlderVersionUrls('https://api.example.com/v2/items');
      expect(urls).toHaveLength(1);
      expect(urls[0]).toBe('https://api.example.com/v1/items');
    });

    it('limits depth to 2 versions back for high version numbers', () => {
      const urls = generateOlderVersionUrls('https://example.com/api/v8/data');
      expect(urls).toHaveLength(2);
      expect(urls[0]).toBe('https://example.com/api/v7/data');
      expect(urls[1]).toBe('https://example.com/api/v6/data');
    });
  });

  describe('run() — skips when no versioned URLs', () => {
    it('returns empty findings when no versioned URLs exist', async () => {
      const mockContext = {} as any;
      const targets = {
        pages: ['https://example.com/', 'https://example.com/about'],
        forms: [],
        urlsWithParams: [],
        apiEndpoints: ['https://example.com/api/users'],
        redirectUrls: [],
        fileParams: [],
      };
      const config = {
        targetUrl: 'https://example.com',
        requestDelay: 0,
      } as any;

      const findings = await apiVersionCheck.run(mockContext, targets, config);
      expect(findings).toHaveLength(0);
    });
  });
});

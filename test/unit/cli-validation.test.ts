import { describe, it, expect } from 'vitest';
import { validateCliOptions, VALID_PROFILES } from '../../src/utils/cli-validation.js';

// Stub file existence checker for testing
const fileExists = (path: string) => path === '/exists/auth.json' || path === '/exists/urls.txt';

describe('validateCliOptions', () => {
  // ─── Profile validation ────────────────────────────────────────

  describe('--profile', () => {
    it('accepts valid profiles', () => {
      for (const profile of VALID_PROFILES) {
        const errors = validateCliOptions({ profile }, fileExists);
        expect(errors.filter((e) => e.field === '--profile')).toEqual([]);
      }
    });

    it('rejects invalid profile', () => {
      const errors = validateCliOptions({ profile: 'turbo' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--profile');
      expect(errors[0].message).toContain('"turbo"');
      expect(errors[0].message).toContain('quick, standard, deep');
    });

    it('allows undefined profile (uses commander default)', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors.filter((e) => e.field === '--profile')).toEqual([]);
    });
  });

  // ─── Auth file validation ──────────────────────────────────────

  describe('--auth', () => {
    it('accepts existing auth file', () => {
      const errors = validateCliOptions({ auth: '/exists/auth.json' }, fileExists);
      expect(errors.filter((e) => e.field === '--auth')).toEqual([]);
    });

    it('rejects non-existent auth file', () => {
      const errors = validateCliOptions({ auth: '/missing/auth.json' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--auth');
      expect(errors[0].message).toContain('/missing/auth.json');
    });

    it('allows undefined auth (not provided)', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors.filter((e) => e.field === '--auth')).toEqual([]);
    });
  });

  // ─── URLs file validation ─────────────────────────────────────

  describe('--urls', () => {
    it('accepts existing urls file', () => {
      const errors = validateCliOptions({ urls: '/exists/urls.txt' }, fileExists);
      expect(errors.filter((e) => e.field === '--urls')).toEqual([]);
    });

    it('rejects non-existent urls file', () => {
      const errors = validateCliOptions({ urls: '/missing/urls.txt' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--urls');
      expect(errors[0].message).toContain('/missing/urls.txt');
    });

    it('allows undefined urls (not provided)', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors.filter((e) => e.field === '--urls')).toEqual([]);
    });
  });

  // ─── max-pages validation ─────────────────────────────────────

  describe('--max-pages', () => {
    it('accepts positive integers', () => {
      for (const val of ['1', '10', '100', '999']) {
        const errors = validateCliOptions({ maxPages: val }, fileExists);
        expect(errors.filter((e) => e.field === '--max-pages')).toEqual([]);
      }
    });

    it('rejects zero', () => {
      const errors = validateCliOptions({ maxPages: '0' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--max-pages');
    });

    it('rejects negative numbers', () => {
      const errors = validateCliOptions({ maxPages: '-5' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--max-pages');
    });

    it('rejects non-numeric strings', () => {
      const errors = validateCliOptions({ maxPages: 'abc' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--max-pages');
      expect(errors[0].message).toContain('"abc"');
    });

    it('rejects floating-point numbers', () => {
      const errors = validateCliOptions({ maxPages: '3.5' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--max-pages');
    });

    it('allows undefined (not provided)', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors.filter((e) => e.field === '--max-pages')).toEqual([]);
    });
  });

  // ─── timeout validation ───────────────────────────────────────

  describe('--timeout', () => {
    it('accepts positive integers', () => {
      for (const val of ['1000', '5000', '30000']) {
        const errors = validateCliOptions({ timeout: val }, fileExists);
        expect(errors.filter((e) => e.field === '--timeout')).toEqual([]);
      }
    });

    it('rejects zero', () => {
      const errors = validateCliOptions({ timeout: '0' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--timeout');
    });

    it('rejects negative numbers', () => {
      const errors = validateCliOptions({ timeout: '-1000' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--timeout');
    });

    it('rejects non-numeric strings', () => {
      const errors = validateCliOptions({ timeout: 'fast' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--timeout');
      expect(errors[0].message).toContain('"fast"');
    });

    it('rejects floating-point numbers', () => {
      const errors = validateCliOptions({ timeout: '1.5' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--timeout');
    });

    it('allows undefined (not provided)', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors.filter((e) => e.field === '--timeout')).toEqual([]);
    });
  });

  // ─── rate-limit validation ────────────────────────────────────

  describe('--rate-limit', () => {
    it('accepts positive integers', () => {
      for (const val of ['1', '5', '50']) {
        const errors = validateCliOptions({ rateLimit: val }, fileExists);
        expect(errors.filter((e) => e.field === '--rate-limit')).toEqual([]);
      }
    });

    it('rejects zero', () => {
      const errors = validateCliOptions({ rateLimit: '0' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--rate-limit');
    });

    it('rejects negative numbers', () => {
      const errors = validateCliOptions({ rateLimit: '-3' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--rate-limit');
    });

    it('rejects non-numeric strings', () => {
      const errors = validateCliOptions({ rateLimit: 'slow' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--rate-limit');
      expect(errors[0].message).toContain('"slow"');
    });

    it('rejects floating-point numbers', () => {
      const errors = validateCliOptions({ rateLimit: '2.5' }, fileExists);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('--rate-limit');
    });

    it('allows undefined (not provided)', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors.filter((e) => e.field === '--rate-limit')).toEqual([]);
    });
  });

  // ─── Multiple errors ──────────────────────────────────────────

  describe('multiple errors', () => {
    it('collects all errors when multiple options are invalid', () => {
      const errors = validateCliOptions(
        {
          profile: 'invalid',
          auth: '/missing/file.json',
          maxPages: '-1',
          timeout: 'abc',
          rateLimit: '0',
        },
        fileExists,
      );
      expect(errors).toHaveLength(5);
      const fields = errors.map((e) => e.field);
      expect(fields).toContain('--profile');
      expect(fields).toContain('--auth');
      expect(fields).toContain('--max-pages');
      expect(fields).toContain('--timeout');
      expect(fields).toContain('--rate-limit');
    });

    it('returns empty array when all options are valid', () => {
      const errors = validateCliOptions(
        {
          profile: 'deep',
          auth: '/exists/auth.json',
          urls: '/exists/urls.txt',
          maxPages: '50',
          timeout: '10000',
          rateLimit: '5',
        },
        fileExists,
      );
      expect(errors).toEqual([]);
    });

    it('returns empty array when no options are provided', () => {
      const errors = validateCliOptions({}, fileExists);
      expect(errors).toEqual([]);
    });
  });
});

import { describe, it, expect } from 'vitest';
import { getPolyglotXss, getPolyglotSqli } from '../../src/utils/polyglot-payloads.js';

describe('Polyglot Payloads', () => {
  describe('getPolyglotXss()', () => {
    it('returns a non-empty array', () => {
      const payloads = getPolyglotXss();
      expect(payloads.length).toBeGreaterThan(0);
    });

    it('returns only strings', () => {
      const payloads = getPolyglotXss();
      for (const p of payloads) {
        expect(typeof p).toBe('string');
      }
    });

    it('returns non-empty strings', () => {
      const payloads = getPolyglotXss();
      for (const p of payloads) {
        expect(p.length).toBeGreaterThan(0);
      }
    });

    it('has no duplicate payloads', () => {
      const payloads = getPolyglotXss();
      const unique = new Set(payloads);
      expect(payloads.length).toBe(unique.size);
    });

    it('returns a new array each time (defensive copy)', () => {
      const a = getPolyglotXss();
      const b = getPolyglotXss();
      expect(a).not.toBe(b);
      expect(a).toEqual(b);
    });

    it('includes payloads that break out of HTML attribute context', () => {
      const payloads = getPolyglotXss();
      // At least one payload should contain quote-breaking characters
      const hasAttributeBreak = payloads.some(
        (p) => p.includes('"') || p.includes("'"),
      );
      expect(hasAttributeBreak).toBe(true);
    });

    it('includes payloads with HTML tag injection', () => {
      const payloads = getPolyglotXss();
      const hasTagInjection = payloads.some(
        (p) => p.includes('<') && p.includes('>'),
      );
      expect(hasTagInjection).toBe(true);
    });

    it('includes payloads with event handler injection', () => {
      const payloads = getPolyglotXss();
      const hasEventHandler = payloads.some(
        (p) => /on\w+=/i.test(p),
      );
      expect(hasEventHandler).toBe(true);
    });

    it('includes payloads with javascript: protocol', () => {
      const payloads = getPolyglotXss();
      const hasJsProtocol = payloads.some(
        (p) => p.toLowerCase().includes('javascript:'),
      );
      expect(hasJsProtocol).toBe(true);
    });

    it('includes SVG-based payloads', () => {
      const payloads = getPolyglotXss();
      const hasSvg = payloads.some(
        (p) => p.toLowerCase().includes('<svg'),
      );
      expect(hasSvg).toBe(true);
    });
  });

  describe('getPolyglotSqli()', () => {
    it('returns a non-empty array', () => {
      const payloads = getPolyglotSqli();
      expect(payloads.length).toBeGreaterThan(0);
    });

    it('returns only strings', () => {
      const payloads = getPolyglotSqli();
      for (const p of payloads) {
        expect(typeof p).toBe('string');
      }
    });

    it('returns non-empty strings', () => {
      const payloads = getPolyglotSqli();
      for (const p of payloads) {
        expect(p.length).toBeGreaterThan(0);
      }
    });

    it('has no duplicate payloads', () => {
      const payloads = getPolyglotSqli();
      const unique = new Set(payloads);
      expect(payloads.length).toBe(unique.size);
    });

    it('returns a new array each time (defensive copy)', () => {
      const a = getPolyglotSqli();
      const b = getPolyglotSqli();
      expect(a).not.toBe(b);
      expect(a).toEqual(b);
    });

    it('includes single-quoted string context payloads', () => {
      const payloads = getPolyglotSqli();
      const hasSingleQuote = payloads.some(
        (p) => p.includes("'"),
      );
      expect(hasSingleQuote).toBe(true);
    });

    it('includes double-quoted context payloads', () => {
      const payloads = getPolyglotSqli();
      const hasDoubleQuote = payloads.some(
        (p) => p.includes('"'),
      );
      expect(hasDoubleQuote).toBe(true);
    });

    it('includes parenthesized context payloads', () => {
      const payloads = getPolyglotSqli();
      const hasParens = payloads.some(
        (p) => p.includes(')') || p.includes('('),
      );
      expect(hasParens).toBe(true);
    });

    it('includes OR-based payloads', () => {
      const payloads = getPolyglotSqli();
      const hasOr = payloads.some(
        (p) => p.toUpperCase().includes('OR'),
      );
      expect(hasOr).toBe(true);
    });

    it('includes comment-terminated payloads', () => {
      const payloads = getPolyglotSqli();
      const hasComment = payloads.some(
        (p) => p.includes('--') || p.includes('#'),
      );
      expect(hasComment).toBe(true);
    });

    it('includes UNION-based payloads', () => {
      const payloads = getPolyglotSqli();
      const hasUnion = payloads.some(
        (p) => p.toUpperCase().includes('UNION'),
      );
      expect(hasUnion).toBe(true);
    });

    it('includes numeric context payload (no quotes)', () => {
      const payloads = getPolyglotSqli();
      const hasNumeric = payloads.some(
        (p) => /^\d+\s+OR\s+/i.test(p),
      );
      expect(hasNumeric).toBe(true);
    });
  });
});

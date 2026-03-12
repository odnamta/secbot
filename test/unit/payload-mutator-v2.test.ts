import { describe, it, expect } from 'vitest';
import {
  fromCharCodeEncode,
  jsonUnicodeEncode,
  mutatePayload,
} from '../../src/utils/payload-mutator.js';

describe('Payload Mutator v2 — new encoding strategies', () => {
  describe('fromCharCodeEncode()', () => {
    it('converts alert(1) to String.fromCharCode(...) with correct char codes', () => {
      const result = fromCharCodeEncode('alert(1)');
      expect(result).toBe('String.fromCharCode(97,108,101,114,116,40,49,41)');
    });

    it('handles empty string → String.fromCharCode()', () => {
      const result = fromCharCodeEncode('');
      expect(result).toBe('String.fromCharCode()');
    });
  });

  describe('jsonUnicodeEncode()', () => {
    it('encodes angle brackets as \\u003c and \\u003e (no raw < or >)', () => {
      const result = jsonUnicodeEncode('<script>');
      expect(result).not.toContain('<');
      expect(result).not.toContain('>');
      expect(result).toContain('\\u003c');
      expect(result).toContain('\\u003e');
    });

    it('encodes double quotes as \\u0022', () => {
      const result = jsonUnicodeEncode('"hello"');
      expect(result).not.toContain('"');
      expect(result).toContain('\\u0022');
    });
  });

  describe('mutatePayload() with new strategies', () => {
    it('with from-char-code strategy includes String.fromCharCode variant', () => {
      const result = mutatePayload('alert(1)', ['from-char-code']);
      const variant = result.find((r) => r.startsWith('String.fromCharCode('));
      expect(variant).toBeDefined();
      expect(variant).toBe('String.fromCharCode(97,108,101,114,116,40,49,41)');
    });

    it('with json-unicode strategy includes \\u003c variant', () => {
      const result = mutatePayload('<script>', ['json-unicode']);
      const variant = result.find((r) => r.includes('\\u003c'));
      expect(variant).toBeDefined();
      expect(variant).not.toContain('<');
    });
  });
});

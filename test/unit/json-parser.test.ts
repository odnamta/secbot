import { describe, it, expect } from 'vitest';
import { parseJsonResponse } from '../../src/ai/client.js';

describe('parseJsonResponse', () => {
  it('parses plain JSON', () => {
    expect(parseJsonResponse('{"key": "value"}')).toEqual({ key: 'value' });
  });

  it('parses JSON in markdown code block', () => {
    const input = '```json\n{"key": "value"}\n```';
    expect(parseJsonResponse(input)).toEqual({ key: 'value' });
  });

  it('parses JSON in untagged markdown code block', () => {
    const input = '```\n{"key": "value"}\n```';
    expect(parseJsonResponse(input)).toEqual({ key: 'value' });
  });

  it('extracts JSON from surrounding text', () => {
    const input = 'Here is the result: {"key": "value"} Hope this helps!';
    expect(parseJsonResponse(input)).toEqual({ key: 'value' });
  });

  it('handles arrays', () => {
    expect(parseJsonResponse('[1, 2, 3]')).toEqual([1, 2, 3]);
  });

  it('extracts array from surrounding text', () => {
    const input = 'The list is: [1, 2, 3] as requested.';
    expect(parseJsonResponse(input)).toEqual([1, 2, 3]);
  });

  it('recovers truncated JSON (unclosed bracket)', () => {
    const input = '{"key": "value", "items": [1, 2';
    const result = parseJsonResponse(input);
    expect(result).not.toBeNull();
    expect((result as Record<string, unknown>).key).toBe('value');
  });

  it('recovers truncated JSON with trailing comma', () => {
    const input = '{"key": "value",';
    const result = parseJsonResponse(input);
    expect(result).not.toBeNull();
    expect((result as Record<string, unknown>).key).toBe('value');
  });

  it('recovers truncated JSON with unclosed string', () => {
    const input = '{"key": "value", "name": "trun';
    const result = parseJsonResponse(input);
    expect(result).not.toBeNull();
    expect((result as Record<string, unknown>).key).toBe('value');
  });

  it('handles nested objects', () => {
    const input = '{"outer": {"inner": "value"}}';
    const result = parseJsonResponse<{ outer: { inner: string } }>(input);
    expect(result).toEqual({ outer: { inner: 'value' } });
  });

  it('returns null for complete garbage', () => {
    expect(parseJsonResponse('not json at all')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(parseJsonResponse('')).toBeNull();
  });

  it('handles whitespace-only input', () => {
    expect(parseJsonResponse('   ')).toBeNull();
  });
});

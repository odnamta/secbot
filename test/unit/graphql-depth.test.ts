import { describe, it, expect } from 'vitest';
import {
  PROBE_FIELD_NAMES,
  extractSuggestions,
} from '../../src/scanner/active/graphql.js';

// ─── Field Suggestion Extraction ───────────────────────────────────────

describe('extractSuggestions', () => {
  it('extracts "Did you mean" suggestions with double quotes', () => {
    const body = '{"errors":[{"message":"Cannot query field \\"userZZZZZ\\". Did you mean \\"user\\" or \\"users\\"?"}]}';
    const suggestions = extractSuggestions(body);
    expect(suggestions).toContain('user');
    expect(suggestions).toContain('users');
  });

  it('extracts "Did you mean" suggestions with single quotes', () => {
    const body = "Cannot query field 'meZZZZZ'. Did you mean 'me'?";
    const suggestions = extractSuggestions(body);
    expect(suggestions).toContain('me');
  });

  it('extracts suggestions array format', () => {
    const body = '{"errors":[{"message":"Unknown field","suggestions":["admin","admins","account"]}]}';
    const suggestions = extractSuggestions(body);
    expect(suggestions).toContain('admin');
    expect(suggestions).toContain('admins');
    expect(suggestions).toContain('account');
  });

  it('deduplicates suggestions', () => {
    const body = 'Did you mean "user"? Did you mean "user"?';
    const suggestions = extractSuggestions(body);
    expect(suggestions.filter(s => s === 'user')).toHaveLength(1);
  });

  it('returns empty array for no suggestions', () => {
    const body = '{"errors":[{"message":"Syntax error"}]}';
    expect(extractSuggestions(body)).toHaveLength(0);
  });

  it('handles mixed formats in same response', () => {
    const body = 'Did you mean "user"? suggestions: ["viewer", "admin"]';
    const suggestions = extractSuggestions(body);
    expect(suggestions).toContain('user');
    expect(suggestions).toContain('viewer');
    expect(suggestions).toContain('admin');
  });
});

// ─── Probe Field Names ─────────────────────────────────────────────────

describe('PROBE_FIELD_NAMES', () => {
  it('has at least 30 field names', () => {
    expect(PROBE_FIELD_NAMES.length).toBeGreaterThanOrEqual(30);
  });

  it('includes common auth-related fields', () => {
    expect(PROBE_FIELD_NAMES).toContain('user');
    expect(PROBE_FIELD_NAMES).toContain('me');
    expect(PROBE_FIELD_NAMES).toContain('admin');
    expect(PROBE_FIELD_NAMES).toContain('token');
  });

  it('includes sensitive fields', () => {
    expect(PROBE_FIELD_NAMES).toContain('password');
    expect(PROBE_FIELD_NAMES).toContain('secret');
    expect(PROBE_FIELD_NAMES).toContain('apiKey');
  });

  it('includes privilege-related fields', () => {
    expect(PROBE_FIELD_NAMES).toContain('role');
    expect(PROBE_FIELD_NAMES).toContain('permissions');
    expect(PROBE_FIELD_NAMES).toContain('internal');
  });

  it('includes dangerous operation fields', () => {
    expect(PROBE_FIELD_NAMES).toContain('delete');
    expect(PROBE_FIELD_NAMES).toContain('destroy');
  });
});

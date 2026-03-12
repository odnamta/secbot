import { describe, it, expect, vi } from 'vitest';
import {
  extractQueryParamIds,
  generateAdjacentIds,
  extractIdPatterns,
} from '../../src/scanner/active/idor.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// ─── extractQueryParamIds ───────────────────────────────────────────────────

describe('extractQueryParamIds', () => {
  it('finds numeric IDs in query params (user_id=42)', () => {
    const results = extractQueryParamIds('https://example.com/profile?user_id=42');
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('user_id');
    expect(results[0].value).toBe('42');
    expect(results[0].type).toBe('numeric');
    expect(results[0].url).toBe('https://example.com/profile?user_id=42');
  });

  it('finds UUID IDs in query params', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const results = extractQueryParamIds(`https://example.com/doc?doc_id=${uuid}`);
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('doc_id');
    expect(results[0].value).toBe(uuid);
    expect(results[0].type).toBe('uuid');
  });

  it('ignores non-ID parameters (q, page, sort)', () => {
    const results = extractQueryParamIds(
      'https://example.com/search?q=hello&page=2&sort=asc&user_id=99',
    );
    // Only user_id should be detected — q, page, sort are not ID params
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('user_id');
  });

  it('detects multiple ID-like params (account_id, order_id)', () => {
    const results = extractQueryParamIds(
      'https://example.com/checkout?account_id=101&order_id=202&currency=USD',
    );
    expect(results).toHaveLength(2);
    const params = results.map((r) => r.param);
    expect(params).toContain('account_id');
    expect(params).toContain('order_id');
  });

  it('ignores numeric IDs outside the valid range (0, >999999)', () => {
    const results = extractQueryParamIds(
      'https://example.com/page?user_id=0&account_id=1000000&order_id=1',
    );
    // 0 and 1000000 should be ignored; order_id=1 should pass
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('order_id');
    expect(results[0].value).toBe('1');
  });

  it('returns empty array for a URL with no ID params', () => {
    const results = extractQueryParamIds('https://example.com/search?q=test&lang=en');
    expect(results).toHaveLength(0);
  });

  it('finds id param (plain "id")', () => {
    const results = extractQueryParamIds('https://example.com/item?id=7');
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('id');
    expect(results[0].type).toBe('numeric');
  });

  it('finds invoice_id param', () => {
    const results = extractQueryParamIds('https://example.com/invoice?invoice_id=500');
    expect(results).toHaveLength(1);
    expect(results[0].param).toBe('invoice_id');
  });
});

// ─── extractIdPatterns — UUID in path segments ──────────────────────────────

describe('extractIdPatterns', () => {
  it('detects sequential numeric ID in path segments (existing behaviour)', () => {
    const results = extractIdPatterns('https://example.com/users/123');
    expect(results).toHaveLength(1);
    expect(results[0].resource).toBe('users');
    expect(results[0].id).toBe(123);
  });

  it('detects UUID in path segments', () => {
    const uuid = 'a3bb189e-8bf9-3888-9912-ace4e6543002';
    const results = extractIdPatterns(`https://example.com/documents/${uuid}`);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const uuidResult = results.find((r) => r.id === uuid);
    expect(uuidResult).toBeDefined();
    expect(uuidResult!.resource).toBe('documents');
  });

  it('does not include api version segments as resources', () => {
    const results = extractIdPatterns('https://example.com/api/v1/orders/456');
    // v1 should be excluded as resource
    const versionResult = results.find((r) => r.resource === 'v1');
    expect(versionResult).toBeUndefined();
    // orders/456 should be found
    const ordersResult = results.find((r) => r.resource === 'orders');
    expect(ordersResult).toBeDefined();
    expect(ordersResult!.id).toBe(456);
  });
});

// ─── generateAdjacentIds ────────────────────────────────────────────────────

describe('generateAdjacentIds', () => {
  it('returns [value-1, value+1] for a numeric ID', () => {
    const result = generateAdjacentIds('42', 'numeric');
    expect(result).toEqual([41, 43]);
  });

  it('skips 0 when generating adjacent IDs for value=1', () => {
    const result = generateAdjacentIds('1', 'numeric');
    // value-1 = 0 should be skipped; only value+1 = 2
    expect(result).not.toContain(0);
    expect(result).toContain(2);
  });

  it('returns both neighbors for value=2', () => {
    const result = generateAdjacentIds('2', 'numeric');
    expect(result).toContain(1);
    expect(result).toContain(3);
  });

  it('returns empty array for UUID type (cannot enumerate)', () => {
    const result = generateAdjacentIds('550e8400-e29b-41d4-a716-446655440000', 'uuid');
    expect(result).toEqual([]);
  });
});

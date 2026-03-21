import { describe, it, expect } from 'vitest';
import {
  detectCaching,
  isCacheHit,
  WCD_SUFFIXES,
} from '../../src/scanner/active/cache-poisoning.js';

// ─── detectCaching ─────────────────────────────────────────────────────

describe('detectCaching', () => {
  it('detects x-cache header', () => {
    expect(detectCaching({ 'x-cache': 'HIT' })).toBe(true);
  });

  it('detects cf-cache-status header', () => {
    expect(detectCaching({ 'cf-cache-status': 'DYNAMIC' })).toBe(true);
  });

  it('detects age header', () => {
    expect(detectCaching({ 'age': '120' })).toBe(true);
  });

  it('detects x-varnish header', () => {
    expect(detectCaching({ 'x-varnish': '123456' })).toBe(true);
  });

  it('returns false when no cache headers', () => {
    expect(detectCaching({ 'content-type': 'text/html' })).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(detectCaching({ 'X-Cache': 'HIT' })).toBe(true);
    expect(detectCaching({ 'CF-Cache-Status': 'HIT' })).toBe(true);
  });
});

// ─── isCacheHit ────────────────────────────────────────────────────────

describe('isCacheHit', () => {
  it('detects x-cache: hit', () => {
    expect(isCacheHit({ 'x-cache': 'HIT' })).toBe(true);
  });

  it('detects cf-cache-status: hit', () => {
    expect(isCacheHit({ 'cf-cache-status': 'HIT' })).toBe(true);
  });

  it('detects x-cache-hit: true', () => {
    expect(isCacheHit({ 'x-cache-hit': 'true' })).toBe(true);
  });

  it('detects positive age header', () => {
    expect(isCacheHit({ 'age': '120' })).toBe(true);
  });

  it('returns false for miss', () => {
    expect(isCacheHit({ 'x-cache': 'MISS' })).toBe(false);
    expect(isCacheHit({ 'cf-cache-status': 'MISS' })).toBe(false);
  });

  it('returns false for age 0', () => {
    expect(isCacheHit({ 'age': '0' })).toBe(false);
  });
});

// ─── WCD Suffixes ──────────────────────────────────────────────────────

describe('WCD_SUFFIXES', () => {
  it('has at least 8 suffixes', () => {
    expect(WCD_SUFFIXES.length).toBeGreaterThanOrEqual(8);
  });

  it('includes static file extensions', () => {
    const joined = WCD_SUFFIXES.join(' ');
    expect(joined).toContain('.css');
    expect(joined).toContain('.js');
    expect(joined).toContain('.png');
  });

  it('includes path traversal variants', () => {
    const hasTraversal = WCD_SUFFIXES.some(s => s.includes('%2f') || s.includes('%2e'));
    expect(hasTraversal).toBe(true);
  });

  it('includes semicolon matrix param variant', () => {
    const hasSemicolon = WCD_SUFFIXES.some(s => s.includes(';'));
    expect(hasSemicolon).toBe(true);
  });
});

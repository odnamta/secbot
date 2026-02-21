import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AICache } from '../../src/utils/ai-cache.js';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

let tempDir: string;
let cache: AICache;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), 'secbot-cache-test-'));
  cache = new AICache({ cacheDir: tempDir, ttlMs: 60_000 });
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe('AICache', () => {
  describe('set/get round-trip', () => {
    it('returns the cached value after set', async () => {
      const key = cache.generateKey({ foo: 'bar' });
      await cache.set(key, 'hello world');
      const result = await cache.get(key);
      expect(result).toBe('hello world');
    });

    it('handles JSON content correctly', async () => {
      const key = cache.generateKey({ test: 'json' });
      const jsonValue = JSON.stringify({ recommendedChecks: [], reasoning: 'test', skipReasons: {} });
      await cache.set(key, jsonValue);
      const result = await cache.get(key);
      expect(result).toBe(jsonValue);
    });
  });

  describe('expiration', () => {
    it('returns null for expired entries', async () => {
      // Use a cache with 1ms TTL so entries expire immediately
      const shortCache = new AICache({ cacheDir: tempDir, ttlMs: 1 });
      const key = shortCache.generateKey({ expire: 'test' });
      await shortCache.set(key, 'should expire');

      // Wait enough for the entry to expire
      await new Promise((resolve) => setTimeout(resolve, 10));

      const result = await shortCache.get(key);
      expect(result).toBeNull();
    });

    it('deletes the expired cache file on read', async () => {
      const shortCache = new AICache({ cacheDir: tempDir, ttlMs: 1 });
      const key = shortCache.generateKey({ cleanup: 'test' });
      await shortCache.set(key, 'should be cleaned up');

      await new Promise((resolve) => setTimeout(resolve, 10));

      await shortCache.get(key);
      const filePath = join(tempDir, `${key}.json`);
      expect(existsSync(filePath)).toBe(false);
    });
  });

  describe('generateKey', () => {
    it('produces deterministic hashes for the same inputs', () => {
      const key1 = cache.generateKey({ a: 1, b: 'two' });
      const key2 = cache.generateKey({ a: 1, b: 'two' });
      expect(key1).toBe(key2);
    });

    it('produces the same hash regardless of key insertion order', () => {
      const key1 = cache.generateKey({ a: 1, b: 2 });
      const key2 = cache.generateKey({ b: 2, a: 1 });
      expect(key1).toBe(key2);
    });

    it('produces different hashes for different inputs', () => {
      const key1 = cache.generateKey({ a: 1 });
      const key2 = cache.generateKey({ a: 2 });
      expect(key1).not.toBe(key2);
    });

    it('returns a 64-character hex string (SHA-256)', () => {
      const key = cache.generateKey({ test: true });
      expect(key).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('cache miss', () => {
    it('returns null for a key that was never set', async () => {
      const result = await cache.get('nonexistent-key-abc123');
      expect(result).toBeNull();
    });

    it('returns null for a key that does not match any file', async () => {
      const key = cache.generateKey({ missing: true });
      const result = await cache.get(key);
      expect(result).toBeNull();
    });
  });

  describe('auto-creation of cache directory', () => {
    it('creates the cache directory if it does not exist', async () => {
      const nestedDir = join(tempDir, 'deep', 'nested', 'cache');
      const nestedCache = new AICache({ cacheDir: nestedDir });

      expect(existsSync(nestedDir)).toBe(false);

      const key = nestedCache.generateKey({ auto: 'create' });
      await nestedCache.set(key, 'should create dir');

      expect(existsSync(nestedDir)).toBe(true);
      const result = await nestedCache.get(key);
      expect(result).toBe('should create dir');
    });
  });
});

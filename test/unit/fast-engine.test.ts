import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FastEngine } from '../../src/scanner/fast-engine.js';
import type { FastResponse, FastEngineOptions } from '../../src/scanner/fast-engine.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// ─── Constructor ────────────────────────────────────────────────────

describe('FastEngine constructor', () => {
  it('creates instance with default options', () => {
    const engine = new FastEngine();
    expect(engine).toBeInstanceOf(FastEngine);
  });

  it('creates instance with custom options', () => {
    const engine = new FastEngine({
      concurrency: 10,
      requestDelay: 50,
      userAgent: 'CustomBot/1.0',
      proxy: 'http://proxy:8080',
      defaultHeaders: { 'X-Custom': 'test' },
      rateLimitRps: 20,
    });
    expect(engine).toBeInstanceOf(FastEngine);
  });

  it('accepts partial options without error', () => {
    const engine = new FastEngine({ concurrency: 5 });
    expect(engine).toBeInstanceOf(FastEngine);
  });

  it('accepts empty options object', () => {
    const engine = new FastEngine({});
    expect(engine).toBeInstanceOf(FastEngine);
  });
});

// ─── getStats ───────────────────────────────────────────────────────

describe('FastEngine.getStats()', () => {
  it('returns correct shape with zero values initially', () => {
    const engine = new FastEngine();
    const stats = engine.getStats();
    expect(stats).toEqual({
      total: 0,
      errors: 0,
      active: 0,
      rps: 0,
    });
  });

  it('returns numbers for all stat fields', () => {
    const engine = new FastEngine();
    const stats = engine.getStats();
    expect(typeof stats.total).toBe('number');
    expect(typeof stats.errors).toBe('number');
    expect(typeof stats.active).toBe('number');
    expect(typeof stats.rps).toBe('number');
  });
});

// ─── batch ──────────────────────────────────────────────────────────

describe('FastEngine.batch()', () => {
  let engine: FastEngine;

  beforeEach(() => {
    engine = new FastEngine({ concurrency: 5 });
  });

  it('returns array of same length as input URLs', async () => {
    // Mock global fetch to return fake responses
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map([['content-type', 'text/html']]),
      text: async () => '<html></html>',
    });
    vi.stubGlobal('fetch', mockFetch);

    const urls = [
      'http://a.example.com',
      'http://b.example.com',
      'http://c.example.com',
    ];
    const results = await engine.batch(urls);
    expect(results).toHaveLength(urls.length);

    vi.unstubAllGlobals();
  });

  it('returns null for failed requests', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    vi.stubGlobal('fetch', mockFetch);

    const results = await engine.batch(['http://dead.example.com']);
    expect(results).toHaveLength(1);
    expect(results[0]).toBeNull();

    vi.unstubAllGlobals();
  });

  it('returns empty array for empty input', async () => {
    const results = await engine.batch([]);
    expect(results).toHaveLength(0);
  });

  it('processes all URLs even when some fail', async () => {
    let callCount = 0;
    const mockFetch = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 2) {
        return Promise.reject(new Error('fail'));
      }
      return Promise.resolve({
        url: 'http://example.com',
        status: 200,
        redirected: false,
        headers: new Map([['content-type', 'text/html']]),
        text: async () => 'ok',
      });
    });
    vi.stubGlobal('fetch', mockFetch);

    const urls = ['http://a.com', 'http://b.com', 'http://c.com'];
    const results = await engine.batch(urls);
    expect(results).toHaveLength(3);
    expect(results[0]).not.toBeNull();
    expect(results[1]).toBeNull();
    expect(results[2]).not.toBeNull();

    vi.unstubAllGlobals();
  });
});

// ─── probe ──────────────────────────────────────────────────────────

describe('FastEngine.probe()', () => {
  let engine: FastEngine;

  beforeEach(() => {
    engine = new FastEngine({ concurrency: 5 });
  });

  it('filters by status code', async () => {
    let callIndex = 0;
    const statuses = [200, 404, 403, 500, 301];
    const mockFetch = vi.fn().mockImplementation(() => {
      const status = statuses[callIndex++];
      return Promise.resolve({
        url: `http://example.com/${status}`,
        status,
        redirected: false,
        headers: new Map(),
        text: async () => '',
      });
    });
    vi.stubGlobal('fetch', mockFetch);

    const urls = statuses.map(s => `http://example.com/${s}`);
    const results = await engine.probe(urls);

    // Default acceptStatuses = [200, 201, 301, 302, 403]
    // 200 -> accepted, 404 -> rejected, 403 -> accepted, 500 -> rejected, 301 -> accepted
    expect(results).toHaveLength(3);
    expect(results.map(r => r.status)).toEqual(
      expect.arrayContaining([200, 403, 301]),
    );

    vi.unstubAllGlobals();
  });

  it('accepts custom status codes', async () => {
    let callIndex = 0;
    const statuses = [200, 404, 500];
    const mockFetch = vi.fn().mockImplementation(() => {
      const status = statuses[callIndex++];
      return Promise.resolve({
        url: `http://example.com/${status}`,
        status,
        redirected: false,
        headers: new Map(),
        text: async () => '',
      });
    });
    vi.stubGlobal('fetch', mockFetch);

    const urls = statuses.map(s => `http://example.com/${s}`);
    const results = await engine.probe(urls, [404, 500]);

    expect(results).toHaveLength(2);
    expect(results.map(r => r.status)).toEqual(
      expect.arrayContaining([404, 500]),
    );

    vi.unstubAllGlobals();
  });

  it('returns empty array when no URLs match', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 500,
      redirected: false,
      headers: new Map(),
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    const results = await engine.probe(['http://example.com'], [200]);
    expect(results).toHaveLength(0);

    vi.unstubAllGlobals();
  });

  it('uses HEAD method by default', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map(),
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine.probe(['http://example.com']);
    expect(mockFetch).toHaveBeenCalledWith(
      'http://example.com',
      expect.objectContaining({ method: 'HEAD' }),
    );

    vi.unstubAllGlobals();
  });
});

// ─── request ────────────────────────────────────────────────────────

describe('FastEngine.request()', () => {
  let engine: FastEngine;

  beforeEach(() => {
    engine = new FastEngine();
  });

  it('defaults to GET method', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map([['content-type', 'text/html']]),
      text: async () => 'body',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine.request('http://example.com');
    expect(mockFetch).toHaveBeenCalledWith(
      'http://example.com',
      expect.objectContaining({ method: 'GET' }),
    );

    vi.unstubAllGlobals();
  });

  it('uses specified method', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map(),
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine.request('http://example.com', { method: 'POST', body: '{}' });
    expect(mockFetch).toHaveBeenCalledWith(
      'http://example.com',
      expect.objectContaining({ method: 'POST', body: '{}' }),
    );

    vi.unstubAllGlobals();
  });

  it('returns FastResponse with correct shape', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com/page',
      status: 201,
      redirected: true,
      headers: new Map([['x-custom', 'value']]),
      text: async () => 'response body',
    });
    vi.stubGlobal('fetch', mockFetch);

    const resp = await engine.request('http://example.com/page');
    expect(resp).toMatchObject({
      url: 'http://example.com/page',
      status: 201,
      redirected: true,
      body: 'response body',
    });
    expect(resp.headers).toEqual({ 'x-custom': 'value' });
    expect(typeof resp.timeMs).toBe('number');
    expect(resp.timeMs).toBeGreaterThanOrEqual(0);

    vi.unstubAllGlobals();
  });

  it('merges default headers with request headers', async () => {
    const engine2 = new FastEngine({
      defaultHeaders: { 'X-Base': 'yes' },
      userAgent: 'TestBot/1.0',
    });
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map(),
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine2.request('http://example.com', {
      headers: { 'X-Extra': 'true' },
    });

    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders['User-Agent']).toBe('TestBot/1.0');
    expect(callHeaders['X-Base']).toBe('yes');
    expect(callHeaders['X-Extra']).toBe('true');

    vi.unstubAllGlobals();
  });

  it('increments stats on success', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map(),
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine.request('http://example.com');
    const stats = engine.getStats();
    expect(stats.total).toBe(1);
    expect(stats.errors).toBe(0);

    vi.unstubAllGlobals();
  });

  it('increments error count on failure', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('network'));
    vi.stubGlobal('fetch', mockFetch);

    await expect(engine.request('http://bad.example.com')).rejects.toThrow('network');
    const stats = engine.getStats();
    expect(stats.total).toBe(1);
    expect(stats.errors).toBe(1);

    vi.unstubAllGlobals();
  });

  it('calls onResponse callback on success', async () => {
    const onResponse = vi.fn();
    const engine2 = new FastEngine({ onResponse });
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 200,
      redirected: false,
      headers: new Map(),
      text: async () => 'data',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine2.request('http://example.com');
    expect(onResponse).toHaveBeenCalledTimes(1);
    expect(onResponse).toHaveBeenCalledWith(
      expect.objectContaining({ status: 200, body: 'data' }),
    );

    vi.unstubAllGlobals();
  });

  it('uses manual redirect when followRedirects is false', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      url: 'http://example.com',
      status: 302,
      redirected: false,
      headers: new Map([['location', 'http://example.com/new']]),
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    await engine.request('http://example.com', { followRedirects: false });
    expect(mockFetch).toHaveBeenCalledWith(
      'http://example.com',
      expect.objectContaining({ redirect: 'manual' }),
    );

    vi.unstubAllGlobals();
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { websocketCheck, extractWsUrlsFromScript, normalizeWsUrl, extractWsUrlsFromCrawledPages } from '../../src/scanner/active/websocket.js';

// Mock the logger
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('WebSocket check: metadata', () => {
  it('has correct name', () => {
    expect(websocketCheck.name).toBe('websocket');
  });

  it('has correct category', () => {
    expect(websocketCheck.category).toBe('websocket');
  });

  it('does not have parallel flag', () => {
    expect(websocketCheck.parallel).toBeUndefined();
  });

  it('has a run function', () => {
    expect(typeof websocketCheck.run).toBe('function');
  });
});

describe('extractWsUrlsFromScript', () => {
  const origin = 'https://example.com';

  it('extracts ws:// URLs from script content', () => {
    const script = 'const socket = new WebSocket("ws://example.com/ws");';
    const urls = extractWsUrlsFromScript(script, origin);
    expect(urls).toContain('ws://example.com/ws');
  });

  it('extracts wss:// URLs from script content', () => {
    const script = 'var conn = new WebSocket("wss://api.example.com/live");';
    const urls = extractWsUrlsFromScript(script, origin);
    expect(urls).toContain('wss://api.example.com/live');
  });

  it('extracts URLs from ws:// patterns without constructor', () => {
    const script = '// connect to ws://example.com/stream for real-time data';
    const urls = extractWsUrlsFromScript(script, origin);
    expect(urls).toContain('ws://example.com/stream');
  });

  it('extracts wss:// URLs from inline patterns', () => {
    const script = 'const WS_URL = "wss://example.com/socket";';
    const urls = extractWsUrlsFromScript(script, origin);
    expect(urls).toContain('wss://example.com/socket');
  });

  it('deduplicates discovered URLs', () => {
    const script = `
      new WebSocket("wss://example.com/ws");
      new WebSocket("wss://example.com/ws");
      var url = "wss://example.com/ws";
    `;
    const urls = extractWsUrlsFromScript(script, origin);
    const wssUrls = urls.filter((u) => u === 'wss://example.com/ws');
    expect(wssUrls.length).toBe(1);
  });

  it('returns empty array for scripts with no WebSocket URLs', () => {
    const script = 'console.log("hello world"); fetch("/api/data");';
    const urls = extractWsUrlsFromScript(script, origin);
    expect(urls).toHaveLength(0);
  });
});

describe('normalizeWsUrl', () => {
  const origin = 'https://example.com';

  it('returns absolute ws:// URLs unchanged', () => {
    expect(normalizeWsUrl('ws://example.com/ws', origin)).toBe('ws://example.com/ws');
  });

  it('returns absolute wss:// URLs unchanged', () => {
    expect(normalizeWsUrl('wss://example.com/ws', origin)).toBe('wss://example.com/ws');
  });

  it('converts relative URLs to absolute with wss:// for https origins', () => {
    expect(normalizeWsUrl('/ws/chat', 'https://example.com')).toBe('wss://example.com/ws/chat');
  });

  it('converts relative URLs to absolute with ws:// for http origins', () => {
    expect(normalizeWsUrl('/ws/chat', 'http://example.com')).toBe('ws://example.com/ws/chat');
  });

  it('returns null for empty strings', () => {
    expect(normalizeWsUrl('', origin)).toBeNull();
  });

  it('returns null for template literals with ${} interpolation', () => {
    expect(normalizeWsUrl('wss://${host}/ws', origin)).toBeNull();
  });

  it('returns null for backtick template strings', () => {
    expect(normalizeWsUrl('`wss://host/ws`', origin)).toBeNull();
  });

  it('prepends wss:// for bare hostname:port patterns', () => {
    const result = normalizeWsUrl('example.com:8080/ws', origin);
    expect(result).toBe('wss://example.com:8080/ws');
  });

  it('preserves port numbers in absolute URLs', () => {
    expect(normalizeWsUrl('wss://example.com:9090/ws', origin)).toBe(
      'wss://example.com:9090/ws',
    );
  });
});

describe('extractWsUrlsFromCrawledPages', () => {
  it('extracts socket.io WebSocket URLs from polling endpoints', () => {
    const pages = [
      'http://localhost:3000/',
      'http://localhost:3000/socket.io?EIO=4&transport=polling&t=abc123',
      'http://localhost:3000/api/products',
    ];
    const urls = extractWsUrlsFromCrawledPages(pages);
    expect(urls).toContain('ws://localhost:3000/socket.io/');
  });

  it('uses wss:// for https socket.io endpoints', () => {
    const pages = [
      'https://example.com/socket.io?EIO=4&transport=polling',
    ];
    const urls = extractWsUrlsFromCrawledPages(pages);
    expect(urls).toContain('wss://example.com/socket.io/');
  });

  it('deduplicates multiple socket.io polling URLs', () => {
    const pages = [
      'http://localhost:3000/socket.io?EIO=4&transport=polling&t=abc',
      'http://localhost:3000/socket.io?EIO=4&transport=polling&t=def&sid=xyz',
      'http://localhost:3000/socket.io?EIO=4&transport=polling&t=ghi&sid=xyz',
    ];
    const urls = extractWsUrlsFromCrawledPages(pages);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toBe('ws://localhost:3000/socket.io/');
  });

  it('detects EIO parameter even without /socket.io path', () => {
    const pages = [
      'http://localhost:3000/realtime?EIO=4&transport=polling',
    ];
    const urls = extractWsUrlsFromCrawledPages(pages);
    // EIO param triggers detection, builds socket.io URL from host
    expect(urls).toHaveLength(1);
  });

  it('returns empty for pages without socket.io', () => {
    const pages = [
      'http://localhost:3000/',
      'http://localhost:3000/api/users',
    ];
    const urls = extractWsUrlsFromCrawledPages(pages);
    expect(urls).toHaveLength(0);
  });
});

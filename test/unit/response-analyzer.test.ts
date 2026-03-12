import { describe, it, expect, vi } from 'vitest';
import { selectInterestingResponses } from '../../src/ai/response-analyzer.js';
import type { CrawledPage, InterceptedRequest, InterceptedResponse } from '../../src/scanner/types.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock('../../src/ai/client.js', () => ({
  askClaude: vi.fn().mockResolvedValue(null),
  parseJsonResponse: vi.fn().mockReturnValue(null),
}));

vi.mock('../../src/ai/prompts.js', () => ({
  sanitizeForPrompt: vi.fn((s: string) => s.slice(0, 500)),
}));

const makePage = (url: string, status: number): CrawledPage => ({
  url,
  status,
  title: '',
  links: [],
  forms: [],
  scripts: [],
  cookies: [],
  headers: {},
});

const makeIntercepted = (
  url: string,
  method: string,
  status: number,
  body: string,
): { request: InterceptedRequest; response: InterceptedResponse } => ({
  request: { url, method, headers: {} },
  response: { url, status, headers: {}, body },
});

describe('selectInterestingResponses', () => {
  it('selects responses with error status codes', () => {
    const pages = [
      makePage('http://example.com/', 200),
      makePage('http://example.com/admin', 403),
      makePage('http://example.com/missing', 404),
    ];
    const result = selectInterestingResponses(pages);
    expect(result.length).toBe(2);
    expect(result.map((r) => r.status)).toContain(403);
    expect(result.map((r) => r.status)).toContain(404);
  });

  it('selects responses with security-relevant body patterns', () => {
    const intercepted = [
      makeIntercepted('http://example.com/api', 'GET', 200, '{"data": "normal"}'),
      makeIntercepted(
        'http://example.com/error',
        'GET',
        200,
        'Error: stack trace at Controller.index (app.js:42)',
      ),
      makeIntercepted(
        'http://example.com/debug',
        'GET',
        200,
        'DEBUG mode enabled: showing internal paths /var/www/app',
      ),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(2);
    expect(result.map((r) => r.url)).toContain('http://example.com/error');
    expect(result.map((r) => r.url)).toContain('http://example.com/debug');
  });

  it('selects 500 error responses', () => {
    const intercepted = [
      makeIntercepted(
        'http://example.com/crash',
        'POST',
        500,
        'Internal Server Error: database connection failed',
      ),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(1);
    expect(result[0].status).toBe(500);
  });

  it('detects password/secret patterns in response body', () => {
    const intercepted = [
      makeIntercepted(
        'http://example.com/config',
        'GET',
        200,
        '{"api_key": "sk_live_abc123", "secret": "xxx"}',
      ),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(1);
  });

  it('detects SQL/database patterns', () => {
    const intercepted = [
      makeIntercepted(
        'http://example.com/search',
        'GET',
        200,
        'ERROR: syntax error in SQL query near SELECT * FROM users',
      ),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(1);
  });

  it('deduplicates by URL + status', () => {
    const intercepted = [
      makeIntercepted('http://example.com/error', 'GET', 500, 'Internal Server Error'),
      makeIntercepted('http://example.com/error', 'POST', 500, 'Internal Server Error again'),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(1);
  });

  it('limits to MAX_RESPONSES (15)', () => {
    const intercepted = Array.from({ length: 20 }, (_, i) =>
      makeIntercepted(`http://example.com/error${i}`, 'GET', 500, 'Internal Server Error'),
    );
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(15);
  });

  it('skips responses without body', () => {
    const intercepted = [
      { request: { url: 'http://example.com/api', method: 'GET', headers: {} } as InterceptedRequest,
        response: { url: 'http://example.com/api', status: 500, headers: {} } as InterceptedResponse },
    ];
    const result = selectInterestingResponses([], intercepted);
    // No body to analyze from intercepted, but status 500 pages would come from crawl
    expect(result.length).toBe(0);
  });

  it('combines crawled pages and intercepted responses', () => {
    const pages = [makePage('http://example.com/notfound', 404)];
    const intercepted = [
      makeIntercepted('http://example.com/api', 'GET', 200, 'stack trace at main.go:12'),
    ];
    const result = selectInterestingResponses(pages, intercepted);
    expect(result.length).toBe(2);
  });

  it('returns empty for normal responses', () => {
    const pages = [makePage('http://example.com/', 200)];
    const intercepted = [
      makeIntercepted('http://example.com/api', 'GET', 200, '{"status":"ok"}'),
    ];
    const result = selectInterestingResponses(pages, intercepted);
    expect(result.length).toBe(0);
  });

  it('truncates body to MAX_BODY_LENGTH', () => {
    const longBody = 'stack trace ' + 'x'.repeat(2000);
    const intercepted = [
      makeIntercepted('http://example.com/error', 'GET', 200, longBody),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result[0].bodySnippet.length).toBeLessThanOrEqual(1000);
  });

  it('detects Swagger/OpenAPI patterns', () => {
    const intercepted = [
      makeIntercepted(
        'http://example.com/swagger',
        'GET',
        200,
        '{"swagger":"2.0","info":{"title":"API"}}',
      ),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(1);
  });

  it('detects private key patterns', () => {
    const intercepted = [
      makeIntercepted(
        'http://example.com/key',
        'GET',
        200,
        '-----BEGIN RSA PRIVATE KEY-----\nMIIE...',
      ),
    ];
    const result = selectInterestingResponses([], intercepted);
    expect(result.length).toBe(1);
  });
});

import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, unlinkSync, existsSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeHarExport, buildHarLog } from '../../src/reporter/har.js';
import type { RequestLogEntry } from '../../src/scanner/types.js';

function makeEntry(overrides: Partial<RequestLogEntry> = {}): RequestLogEntry {
  return {
    timestamp: '2026-02-21T10:00:00.000Z',
    method: 'GET',
    url: 'https://example.com/api/v1/users?id=1',
    headers: { 'User-Agent': 'SecBot/1.0', 'Accept': 'text/html' },
    responseStatus: 200,
    responseHeaders: { 'Content-Type': 'text/html', 'X-Frame-Options': 'DENY' },
    phase: 'active-xss',
    ...overrides,
  };
}

const tmpFiles: string[] = [];

function tmpPath(ext = '.har'): string {
  const dir = mkdtempSync(join(tmpdir(), 'secbot-har-test-'));
  const p = join(dir, `test-export${ext}`);
  tmpFiles.push(p);
  return p;
}

afterEach(() => {
  for (const f of tmpFiles) {
    if (existsSync(f)) unlinkSync(f);
  }
  tmpFiles.length = 0;
});

describe('HAR export', () => {
  describe('writeHarExport', () => {
    it('writes valid JSON to disk', () => {
      const outPath = tmpPath();
      writeHarExport([makeEntry()], outPath);
      expect(existsSync(outPath)).toBe(true);
      const content = readFileSync(outPath, 'utf-8');
      expect(() => JSON.parse(content)).not.toThrow();
    });

    it('creates parent directories if needed', () => {
      const deepPath = join(mkdtempSync(join(tmpdir(), 'secbot-har-deep-')), 'sub', 'dir', 'export.har');
      tmpFiles.push(deepPath);
      writeHarExport([], deepPath);
      expect(existsSync(deepPath)).toBe(true);
    });
  });

  describe('buildHarLog', () => {
    it('produces HAR 1.2 format with correct version', () => {
      const har = buildHarLog([makeEntry()]);
      expect(har.log.version).toBe('1.2');
    });

    it('includes SecBot as creator', () => {
      const har = buildHarLog([]);
      expect(har.log.creator.name).toBe('SecBot');
      expect(har.log.creator.version).toBeTruthy();
    });

    it('maps entries correctly', () => {
      const entries = [makeEntry()];
      const har = buildHarLog(entries);
      expect(har.log.entries).toHaveLength(1);

      const entry = har.log.entries[0];
      expect(entry.startedDateTime).toBe('2026-02-21T10:00:00.000Z');
      expect(entry.time).toBe(0);
    });

    it('maps request fields correctly', () => {
      const har = buildHarLog([makeEntry()]);
      const req = har.log.entries[0].request;

      expect(req.method).toBe('GET');
      expect(req.url).toBe('https://example.com/api/v1/users?id=1');
      expect(req.httpVersion).toBe('HTTP/1.1');
    });

    it('includes request headers as name-value pairs', () => {
      const har = buildHarLog([makeEntry()]);
      const headers = har.log.entries[0].request.headers;

      expect(headers).toEqual(expect.arrayContaining([
        { name: 'User-Agent', value: 'SecBot/1.0' },
        { name: 'Accept', value: 'text/html' },
      ]));
    });

    it('maps response fields correctly', () => {
      const har = buildHarLog([makeEntry()]);
      const res = har.log.entries[0].response;

      expect(res.status).toBe(200);
      expect(res.statusText).toBe('OK');
      expect(res.httpVersion).toBe('HTTP/1.1');
    });

    it('includes response headers as name-value pairs', () => {
      const har = buildHarLog([makeEntry()]);
      const headers = har.log.entries[0].response.headers;

      expect(headers).toEqual(expect.arrayContaining([
        { name: 'Content-Type', value: 'text/html' },
        { name: 'X-Frame-Options', value: 'DENY' },
      ]));
    });

    it('extracts query string parameters', () => {
      const har = buildHarLog([makeEntry()]);
      const qs = har.log.entries[0].request.queryString;

      expect(qs).toEqual([{ name: 'id', value: '1' }]);
    });

    it('includes multiple query parameters', () => {
      const entry = makeEntry({ url: 'https://example.com/search?q=test&page=2&sort=asc' });
      const har = buildHarLog([entry]);
      const qs = har.log.entries[0].request.queryString;

      expect(qs).toHaveLength(3);
      expect(qs).toEqual(expect.arrayContaining([
        { name: 'q', value: 'test' },
        { name: 'page', value: '2' },
        { name: 'sort', value: 'asc' },
      ]));
    });

    it('includes postData for POST requests', () => {
      const entry = makeEntry({
        method: 'POST',
        url: 'https://example.com/login',
        body: 'username=admin&password=test',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      const har = buildHarLog([entry]);
      const req = har.log.entries[0].request;

      expect(req.postData).toBeDefined();
      expect(req.postData!.text).toBe('username=admin&password=test');
      expect(req.postData!.mimeType).toBe('application/x-www-form-urlencoded');
    });

    it('omits postData when no body is present', () => {
      const har = buildHarLog([makeEntry()]);
      const req = har.log.entries[0].request;
      expect(req.postData).toBeUndefined();
    });

    it('includes cache and timings objects', () => {
      const har = buildHarLog([makeEntry()]);
      const entry = har.log.entries[0];

      expect(entry.cache).toEqual({});
      expect(entry.timings).toEqual({ send: 0, wait: 0, receive: 0 });
    });

    it('includes cookies as empty arrays', () => {
      const har = buildHarLog([makeEntry()]);
      const entry = har.log.entries[0];

      expect(entry.request.cookies).toEqual([]);
      expect(entry.response.cookies).toEqual([]);
    });

    it('handles multiple entries', () => {
      const entries = [
        makeEntry({ url: 'https://example.com/page1' }),
        makeEntry({ url: 'https://example.com/page2', method: 'POST', body: 'data=1' }),
        makeEntry({ url: 'https://example.com/page3', responseStatus: 404 }),
      ];
      const har = buildHarLog(entries);
      expect(har.log.entries).toHaveLength(3);
    });

    it('produces valid HAR with 0 entries', () => {
      const har = buildHarLog([]);
      expect(har.log.version).toBe('1.2');
      expect(har.log.creator.name).toBe('SecBot');
      expect(har.log.entries).toHaveLength(0);
    });

    it('handles missing response status', () => {
      const entry = makeEntry({ responseStatus: undefined });
      const har = buildHarLog([entry]);
      expect(har.log.entries[0].response.status).toBe(0);
      expect(har.log.entries[0].response.statusText).toBe('Unknown');
    });

    it('handles missing headers', () => {
      const entry = makeEntry({ headers: undefined, responseHeaders: undefined });
      const har = buildHarLog([entry]);
      expect(har.log.entries[0].request.headers).toEqual([]);
      expect(har.log.entries[0].response.headers).toEqual([]);
    });

    it('sets content mimeType from response Content-Type', () => {
      const entry = makeEntry({
        responseHeaders: { 'Content-Type': 'application/json' },
      });
      const har = buildHarLog([entry]);
      expect(har.log.entries[0].response.content.mimeType).toBe('application/json');
    });

    it('defaults content mimeType to text/plain when no Content-Type', () => {
      const entry = makeEntry({ responseHeaders: {} });
      const har = buildHarLog([entry]);
      expect(har.log.entries[0].response.content.mimeType).toBe('text/plain');
    });

    it('computes bodySize for POST requests', () => {
      const entry = makeEntry({
        method: 'POST',
        body: 'hello',
      });
      const har = buildHarLog([entry]);
      expect(har.log.entries[0].request.bodySize).toBe(5);
    });

    it('sets bodySize to 0 for GET requests', () => {
      const har = buildHarLog([makeEntry()]);
      expect(har.log.entries[0].request.bodySize).toBe(0);
    });

    it('includes response redirectURL as empty string', () => {
      const har = buildHarLog([makeEntry()]);
      expect(har.log.entries[0].response.redirectURL).toBe('');
    });

    it('maps common status codes to correct statusText', () => {
      const statusCodes: Array<[number, string]> = [
        [200, 'OK'],
        [301, 'Moved Permanently'],
        [302, 'Found'],
        [400, 'Bad Request'],
        [401, 'Unauthorized'],
        [403, 'Forbidden'],
        [404, 'Not Found'],
        [500, 'Internal Server Error'],
      ];

      for (const [code, text] of statusCodes) {
        const entry = makeEntry({ responseStatus: code });
        const har = buildHarLog([entry]);
        expect(har.log.entries[0].response.statusText).toBe(text);
      }
    });

    it('writes well-formatted JSON when using writeHarExport', () => {
      const outPath = tmpPath();
      writeHarExport([makeEntry()], outPath);
      const content = readFileSync(outPath, 'utf-8');
      // Should be pretty-printed (indented)
      expect(content).toContain('\n  ');
      const parsed = JSON.parse(content);
      expect(parsed.log).toBeDefined();
      expect(parsed.log.version).toBe('1.2');
    });
  });
});

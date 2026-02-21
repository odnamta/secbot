import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, unlinkSync, existsSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeBurpExport, buildBurpXml } from '../../src/reporter/burp-xml.js';
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

function tmpPath(ext = '.xml'): string {
  const dir = mkdtempSync(join(tmpdir(), 'secbot-burp-test-'));
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

describe('Burp XML export', () => {
  describe('writeBurpExport', () => {
    it('writes a file to disk', () => {
      const outPath = tmpPath();
      writeBurpExport([makeEntry()], outPath);
      expect(existsSync(outPath)).toBe(true);
    });

    it('creates parent directories if needed', () => {
      const deepPath = join(mkdtempSync(join(tmpdir(), 'secbot-burp-deep-')), 'sub', 'dir', 'export.xml');
      tmpFiles.push(deepPath);
      writeBurpExport([], deepPath);
      expect(existsSync(deepPath)).toBe(true);
    });

    it('produces valid XML with XML declaration', () => {
      const outPath = tmpPath();
      writeBurpExport([makeEntry()], outPath);
      const content = readFileSync(outPath, 'utf-8');
      expect(content).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    });
  });

  describe('buildBurpXml', () => {
    it('produces valid XML structure with items root element', () => {
      const xml = buildBurpXml([makeEntry()]);
      expect(xml).toContain('<items burpVersion="0.0"');
      expect(xml).toContain('exportTime="');
      expect(xml).toContain('</items>');
    });

    it('generates correct item elements', () => {
      const xml = buildBurpXml([makeEntry()]);
      expect(xml).toContain('<item>');
      expect(xml).toContain('</item>');
      expect(xml).toContain('<url>https://example.com/api/v1/users?id=1</url>');
      expect(xml).toContain('<host ip="">example.com</host>');
      expect(xml).toContain('<port>443</port>');
      expect(xml).toContain('<protocol>https</protocol>');
      expect(xml).toContain('<method>GET</method>');
      expect(xml).toContain('<path>/api/v1/users?id=1</path>');
      expect(xml).toContain('<status>200</status>');
    });

    it('base64-encodes request and response', () => {
      const xml = buildBurpXml([makeEntry()]);
      expect(xml).toContain('<request base64="true">');
      expect(xml).toContain('<response base64="true">');

      // Extract and decode request
      const reqMatch = xml.match(/<request base64="true">(.*?)<\/request>/);
      expect(reqMatch).not.toBeNull();
      const decodedReq = Buffer.from(reqMatch![1], 'base64').toString('utf-8');
      expect(decodedReq).toContain('GET /api/v1/users?id=1 HTTP/1.1');
      expect(decodedReq).toContain('Host: example.com');
      expect(decodedReq).toContain('User-Agent: SecBot/1.0');

      // Extract and decode response
      const resMatch = xml.match(/<response base64="true">(.*?)<\/response>/);
      expect(resMatch).not.toBeNull();
      const decodedRes = Buffer.from(resMatch![1], 'base64').toString('utf-8');
      expect(decodedRes).toContain('HTTP/1.1 200 OK');
      expect(decodedRes).toContain('Content-Type: text/html');
    });

    it('handles POST requests with body', () => {
      const entry = makeEntry({
        method: 'POST',
        url: 'https://example.com/login',
        body: 'username=admin&password=test',
      });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('<method>POST</method>');

      const reqMatch = xml.match(/<request base64="true">(.*?)<\/request>/);
      const decoded = Buffer.from(reqMatch![1], 'base64').toString('utf-8');
      expect(decoded).toContain('POST /login HTTP/1.1');
      expect(decoded).toContain('username=admin&password=test');
    });

    it('uses port 80 for http URLs', () => {
      const entry = makeEntry({ url: 'http://example.com/page' });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('<port>80</port>');
      expect(xml).toContain('<protocol>http</protocol>');
    });

    it('uses explicit port when specified in URL', () => {
      const entry = makeEntry({ url: 'https://example.com:8443/api' });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('<port>8443</port>');
    });

    it('handles multiple entries', () => {
      const entries = [
        makeEntry({ url: 'https://example.com/page1', method: 'GET' }),
        makeEntry({ url: 'https://example.com/page2', method: 'POST', body: 'data=test' }),
        makeEntry({ url: 'https://example.com/page3', method: 'PUT' }),
      ];
      const xml = buildBurpXml(entries);
      const itemCount = (xml.match(/<item>/g) || []).length;
      expect(itemCount).toBe(3);
    });

    it('produces valid XML with 0 entries', () => {
      const xml = buildBurpXml([]);
      expect(xml).toContain('<?xml version="1.0"');
      expect(xml).toContain('<items burpVersion="0.0"');
      expect(xml).toContain('</items>');
      expect(xml).not.toContain('<item>');
    });

    it('escapes XML special characters in URLs', () => {
      const entry = makeEntry({ url: 'https://example.com/search?q=foo&bar=baz' });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('&amp;bar=baz');
    });

    it('includes timestamp in item', () => {
      const entry = makeEntry({ timestamp: '2026-02-21T15:30:00.000Z' });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('<time>2026-02-21T15:30:00.000Z</time>');
    });

    it('includes responselength element', () => {
      const xml = buildBurpXml([makeEntry()]);
      expect(xml).toContain('<responselength>');
      // responselength should be a number
      const match = xml.match(/<responselength>(\d+)<\/responselength>/);
      expect(match).not.toBeNull();
      expect(parseInt(match![1], 10)).toBeGreaterThan(0);
    });

    it('skips entries with invalid URLs', () => {
      const entries = [
        makeEntry({ url: 'not-a-valid-url' }),
        makeEntry({ url: 'https://example.com/valid' }),
      ];
      const xml = buildBurpXml(entries);
      const itemCount = (xml.match(/<item>/g) || []).length;
      expect(itemCount).toBe(1);
    });

    it('handles missing response status', () => {
      const entry = makeEntry({ responseStatus: undefined });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('<status>0</status>');
    });

    it('handles entries without headers', () => {
      const entry = makeEntry({ headers: undefined, responseHeaders: undefined });
      const xml = buildBurpXml([entry]);
      expect(xml).toContain('<request base64="true">');
      expect(xml).toContain('<response base64="true">');
    });
  });
});

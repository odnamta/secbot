import { describe, it, expect } from 'vitest';
import {
  XXE_PAYLOADS,
  XML_CONTENT_TYPES,
  XML_ENDPOINT_PATTERNS,
  detectXmlParsing,
  detectXxeSuccess,
} from '../../src/scanner/active/xxe.js';

describe('XXE Payloads', () => {
  it('has at least 6 XXE payloads', () => {
    expect(XXE_PAYLOADS.length).toBeGreaterThanOrEqual(6);
  });

  it('includes classic file read payload', () => {
    const classic = XXE_PAYLOADS.filter(p => p.name === 'classic-file-read');
    expect(classic.length).toBe(1);
    expect(classic[0].payload).toContain('/etc/passwd');
    expect(classic[0].payload).toContain('ENTITY');
  });

  it('includes parameter entity payload', () => {
    const param = XXE_PAYLOADS.filter(p => p.name === 'parameter-entity');
    expect(param.length).toBe(1);
    expect(param[0].payload).toContain('%xxe');
  });

  it('includes Windows file read payload', () => {
    const win = XXE_PAYLOADS.filter(p => p.name === 'windows-file-read');
    expect(win.length).toBe(1);
    expect(win[0].payload).toContain('win.ini');
  });

  it('includes PHP filter payload', () => {
    const php = XXE_PAYLOADS.filter(p => p.name === 'php-filter');
    expect(php.length).toBe(1);
    expect(php[0].payload).toContain('php://filter');
  });

  it('includes error-based payload', () => {
    const error = XXE_PAYLOADS.filter(p => p.name === 'error-based');
    expect(error.length).toBe(1);
  });

  it('includes XInclude payload', () => {
    const xi = XXE_PAYLOADS.filter(p => p.name === 'xinclude');
    expect(xi.length).toBe(1);
    expect(xi[0].payload).toContain('xi:include');
  });

  it('all payloads have name, payload, indicator, and description', () => {
    for (const p of XXE_PAYLOADS) {
      expect(p.name).toBeTruthy();
      expect(p.payload).toBeTruthy();
      expect(p.indicator).toBeInstanceOf(RegExp);
      expect(p.description).toBeTruthy();
    }
  });

  it('all payloads contain XML markers', () => {
    for (const p of XXE_PAYLOADS) {
      // All should be valid XML-like structures
      expect(p.payload).toMatch(/<|xml|DOCTYPE|xi:include/i);
    }
  });
});

describe('XML Content Types', () => {
  it('includes standard XML content types', () => {
    expect(XML_CONTENT_TYPES).toContain('application/xml');
    expect(XML_CONTENT_TYPES).toContain('text/xml');
  });

  it('includes SOAP content type', () => {
    expect(XML_CONTENT_TYPES).toContain('application/soap+xml');
  });

  it('has at least 4 content types', () => {
    expect(XML_CONTENT_TYPES.length).toBeGreaterThanOrEqual(4);
  });
});

describe('XML Endpoint Patterns', () => {
  it('matches SOAP endpoints', () => {
    expect(XML_ENDPOINT_PATTERNS.some(p => p.test('/api/soap/service'))).toBe(true);
  });

  it('matches XML-RPC endpoints', () => {
    expect(XML_ENDPOINT_PATTERNS.some(p => p.test('/xmlrpc.php'))).toBe(true);
  });

  it('matches RSS/Atom endpoints', () => {
    expect(XML_ENDPOINT_PATTERNS.some(p => p.test('/feed/rss'))).toBe(true);
    expect(XML_ENDPOINT_PATTERNS.some(p => p.test('/atom.xml'))).toBe(true);
  });

  it('has at least 10 patterns', () => {
    expect(XML_ENDPOINT_PATTERNS.length).toBeGreaterThanOrEqual(10);
  });
});

describe('detectXmlParsing()', () => {
  it('detects XML parsing error messages', () => {
    expect(detectXmlParsing('XML parsing error: no root element', {}, 400)).toBe(true);
    expect(detectXmlParsing('SAXParseException: Content is not allowed', {}, 400)).toBe(true);
    expect(detectXmlParsing('DOCTYPE is not allowed', {}, 403)).toBe(true);
  });

  it('detects XML content type in response', () => {
    expect(detectXmlParsing('some body', { 'content-type': 'application/xml' }, 200)).toBe(true);
    expect(detectXmlParsing('some body', { 'content-type': 'text/xml; charset=utf-8' }, 200)).toBe(true);
  });

  it('detects entity-related error messages', () => {
    expect(detectXmlParsing('entity "xxe" is not allowed', {}, 500)).toBe(true);
    expect(detectXmlParsing('DTD is prohibited', {}, 400)).toBe(true);
  });

  it('does not flag normal JSON responses', () => {
    expect(detectXmlParsing('{"error":"invalid"}', { 'content-type': 'application/json' }, 400)).toBe(false);
  });

  it('does not flag 415 Unsupported Media Type', () => {
    // 415 means the server rejected XML outright — not parsing
    expect(detectXmlParsing('Unsupported Media Type', {}, 415)).toBe(false);
  });

  it('does not flag empty response', () => {
    expect(detectXmlParsing('', {}, 200)).toBe(false);
  });
});

describe('detectXxeSuccess()', () => {
  it('detects /etc/passwd content in response', () => {
    const body = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin';
    const result = detectXxeSuccess(body, XXE_PAYLOADS[0]); // classic-file-read
    expect(result.success).toBe(true);
    expect(result.evidence).toContain('classic-file-read');
  });

  it('detects win.ini content in response', () => {
    const body = '[fonts]\n[extensions]\n[mci extensions]';
    const result = detectXxeSuccess(body, XXE_PAYLOADS[2]); // windows-file-read
    expect(result.success).toBe(true);
  });

  it('detects base64-encoded content from PHP filter', () => {
    const body = 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo='; // base64 of root:x:0:0:root:/root:/bin/bash
    const result = detectXxeSuccess(body, XXE_PAYLOADS[3]); // php-filter
    expect(result.success).toBe(true);
  });

  it('does not flag normal response', () => {
    const body = '{"status":"ok","message":"received"}';
    const result = detectXxeSuccess(body, XXE_PAYLOADS[0]);
    expect(result.success).toBe(false);
  });

  it('detects error-based XXE with file path in error', () => {
    const body = 'Error: failed to load external entity "file:///nonexistent/test"';
    const result = detectXxeSuccess(body, XXE_PAYLOADS[4]); // error-based
    expect(result.success).toBe(true);
  });
});

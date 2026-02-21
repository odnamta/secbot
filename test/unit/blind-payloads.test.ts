import { describe, it, expect } from 'vitest';
import {
  generateBlindXssPayloads,
  generateBlindSsrfPayloads,
  generateBlindSqliPayloads,
} from '../../src/scanner/oob/blind-payloads.js';

describe('Blind XSS Payloads', () => {
  const callbackUrl = 'http://127.0.0.1:9999';

  it('generates multiple payloads', () => {
    const payloads = generateBlindXssPayloads(callbackUrl);
    expect(payloads.length).toBeGreaterThanOrEqual(5);
  });

  it('all payloads contain the callback URL', () => {
    const payloads = generateBlindXssPayloads(callbackUrl);
    for (const p of payloads) {
      expect(p).toContain('127.0.0.1:9999');
    }
  });

  it('includes a <script>fetch() payload', () => {
    const payloads = generateBlindXssPayloads(callbackUrl);
    const scriptFetch = payloads.filter((p) => p.includes('<script>') && p.includes('fetch('));
    expect(scriptFetch.length).toBeGreaterThanOrEqual(1);
  });

  it('includes an img onerror payload', () => {
    const payloads = generateBlindXssPayloads(callbackUrl);
    const imgPayloads = payloads.filter((p) => p.includes('<img') && p.includes('onerror'));
    expect(imgPayloads.length).toBeGreaterThanOrEqual(1);
  });

  it('includes an Image().src beacon payload', () => {
    const payloads = generateBlindXssPayloads(callbackUrl);
    const imageBeacon = payloads.filter((p) => p.includes('new Image().src'));
    expect(imageBeacon.length).toBeGreaterThanOrEqual(1);
  });

  it('each payload has a unique bxss- UUID', () => {
    const payloads = generateBlindXssPayloads(callbackUrl);
    const uuids = payloads
      .map((p) => {
        const m = p.match(/bxss-[0-9a-f-]{36}/);
        return m ? m[0] : null;
      })
      .filter(Boolean);
    expect(new Set(uuids).size).toBe(uuids.length);
  });

  it('strips trailing slashes from callback URL', () => {
    const payloads = generateBlindXssPayloads('http://127.0.0.1:9999///');
    for (const p of payloads) {
      expect(p).not.toContain('9999///');
    }
  });

  it('generates different UUIDs on each call', () => {
    const payloads1 = generateBlindXssPayloads(callbackUrl);
    const payloads2 = generateBlindXssPayloads(callbackUrl);
    // Same structure, different UUIDs
    expect(payloads1).not.toEqual(payloads2);
  });
});

describe('Blind SSRF Payloads', () => {
  const callbackUrl = 'http://callback.test:8080';

  it('generates multiple payloads', () => {
    const payloads = generateBlindSsrfPayloads(callbackUrl);
    expect(payloads.length).toBeGreaterThanOrEqual(5);
  });

  it('all payloads reference the callback host', () => {
    const payloads = generateBlindSsrfPayloads(callbackUrl);
    for (const p of payloads) {
      expect(p).toContain('callback.test');
    }
  });

  it('includes a direct URL payload', () => {
    const payloads = generateBlindSsrfPayloads(callbackUrl);
    const direct = payloads.filter((p) => p.startsWith('http://callback.test:8080/cb/bssrf-'));
    expect(direct.length).toBeGreaterThanOrEqual(1);
  });

  it('each payload has a unique bssrf- UUID', () => {
    const payloads = generateBlindSsrfPayloads(callbackUrl);
    const uuids = payloads
      .map((p) => {
        const m = p.match(/bssrf-[0-9a-f-]{36}/);
        return m ? m[0] : null;
      })
      .filter(Boolean);
    // At least most payloads should have unique IDs
    expect(new Set(uuids).size).toBe(uuids.length);
  });

  it('includes a protocol-relative payload', () => {
    const payloads = generateBlindSsrfPayloads(callbackUrl);
    const protoRelative = payloads.filter((p) => p.startsWith('//'));
    expect(protoRelative.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Blind SQLi Payloads', () => {
  const callbackUrl = 'http://oob.attacker.com:4444';

  it('generates multiple payloads', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    expect(payloads.length).toBeGreaterThanOrEqual(8);
  });

  it('includes MySQL-specific payloads', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    const mysql = payloads.filter((p) => p.includes('LOAD_FILE') || p.includes('OUTFILE'));
    expect(mysql.length).toBeGreaterThanOrEqual(1);
  });

  it('includes PostgreSQL-specific payloads', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    const pg = payloads.filter((p) => p.includes('COPY') || p.includes('dblink'));
    expect(pg.length).toBeGreaterThanOrEqual(1);
  });

  it('includes MSSQL-specific payloads', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    const mssql = payloads.filter((p) => p.includes('xp_cmdshell') || p.includes('OPENROWSET'));
    expect(mssql.length).toBeGreaterThanOrEqual(1);
  });

  it('includes Oracle-specific payloads', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    const oracle = payloads.filter((p) => p.includes('UTL_HTTP') || p.includes('UTL_INADDR'));
    expect(oracle.length).toBeGreaterThanOrEqual(1);
  });

  it('most payloads reference the callback host', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    const withHost = payloads.filter((p) => p.includes('oob.attacker.com'));
    // At least 80% should reference the callback host (some may be generic time-based)
    expect(withHost.length).toBeGreaterThanOrEqual(Math.floor(payloads.length * 0.8));
  });

  it('payloads contain SQL comment terminators', () => {
    const payloads = generateBlindSqliPayloads(callbackUrl);
    const withComment = payloads.filter((p) => p.includes('-- -'));
    // Most SQLi payloads should have comment terminators
    expect(withComment.length).toBeGreaterThanOrEqual(5);
  });
});

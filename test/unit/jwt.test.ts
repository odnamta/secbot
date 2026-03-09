import { describe, it, expect } from 'vitest';
import {
  parseJwt,
  base64UrlDecode,
  buildNoneAlgToken,
  buildNoneAlgVariants,
  extractJwts,
  analyzeJwtSecurity,
  verifyHs256,
  jwtCheck,
  WEAK_SECRETS,
} from '../../src/scanner/active/jwt.js';

// ─── Helper: create a valid HS256 JWT ───────────────────────────────

function createTestJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature = 'test-signature',
): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const s = Buffer.from(signature).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${h}.${p}.${s}`;
}

// ─── JWT Parsing ────────────────────────────────────────────────────

describe('parseJwt', () => {
  it('parses a valid JWT', () => {
    const token = createTestJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: '1234', name: 'Test User', exp: 9999999999 },
    );
    const parsed = parseJwt(token);
    expect(parsed).not.toBeNull();
    expect(parsed!.header.alg).toBe('HS256');
    expect(parsed!.payload.sub).toBe('1234');
    expect(parsed!.payload.name).toBe('Test User');
  });

  it('returns null for malformed tokens', () => {
    expect(parseJwt('not-a-jwt')).toBeNull();
    expect(parseJwt('only.two')).toBeNull();
    expect(parseJwt('')).toBeNull();
  });

  it('handles tokens with empty signature', () => {
    const token = createTestJwt({ alg: 'none' }, { sub: '1' }, '');
    // Remove the trailing signature part — just header.payload.
    const parts = token.split('.');
    const noneToken = `${parts[0]}.${parts[1]}.`;
    const parsed = parseJwt(noneToken);
    expect(parsed).not.toBeNull();
    expect(parsed!.header.alg).toBe('none');
    expect(parsed!.signature).toBe('');
  });
});

// ─── base64UrlDecode ────────────────────────────────────────────────

describe('base64UrlDecode', () => {
  it('decodes base64url strings', () => {
    const encoded = Buffer.from('{"alg":"HS256"}').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toBe('{"alg":"HS256"}');
  });
});

// ─── None Algorithm ─────────────────────────────────────────────────

describe('buildNoneAlgToken', () => {
  it('builds a token with alg=none and empty signature', () => {
    const token = buildNoneAlgToken({ sub: '1234', role: 'admin' });
    expect(token.endsWith('.')).toBe(true);

    const parsed = parseJwt(token);
    expect(parsed).not.toBeNull();
    expect(parsed!.header.alg).toBe('none');
    expect(parsed!.payload.sub).toBe('1234');
    expect(parsed!.payload.role).toBe('admin');
    expect(parsed!.signature).toBe('');
  });
});

describe('buildNoneAlgVariants', () => {
  it('produces 4 case variants', () => {
    const variants = buildNoneAlgVariants({ sub: '1' });
    expect(variants).toHaveLength(4);

    const algs = variants.map((t) => parseJwt(t)!.header.alg);
    expect(algs).toContain('none');
    expect(algs).toContain('None');
    expect(algs).toContain('NONE');
    expect(algs).toContain('nOnE');
  });
});

// ─── JWT Extraction ─────────────────────────────────────────────────

describe('extractJwts', () => {
  const sampleJwt = createTestJwt({ alg: 'HS256' }, { sub: '1' });

  it('extracts from Authorization header', () => {
    const results = extractJwts({ authorization: `Bearer ${sampleJwt}` });
    expect(results).toHaveLength(1);
    expect(results[0].source).toBe('Authorization header');
  });

  it('extracts from Set-Cookie header', () => {
    const results = extractJwts({ 'set-cookie': `token=${sampleJwt}; Path=/; HttpOnly` });
    expect(results).toHaveLength(1);
    expect(results[0].source).toBe('Set-Cookie header');
  });

  it('extracts from response body', () => {
    const body = JSON.stringify({ access_token: sampleJwt });
    const results = extractJwts({}, body);
    expect(results).toHaveLength(1);
    expect(results[0].source).toBe('Response body');
  });

  it('extracts from cookies array', () => {
    const results = extractJwts({}, undefined, [{ name: 'auth', value: sampleJwt }]);
    expect(results).toHaveLength(1);
    expect(results[0].source).toBe('Cookie: auth');
  });

  it('deduplicates same token from multiple sources', () => {
    const results = extractJwts(
      { authorization: `Bearer ${sampleJwt}` },
      JSON.stringify({ token: sampleJwt }),
    );
    expect(results).toHaveLength(1);
  });

  it('returns empty for no JWTs', () => {
    const results = extractJwts({ 'content-type': 'text/html' }, '<html></html>');
    expect(results).toHaveLength(0);
  });
});

// ─── Security Analysis ──────────────────────────────────────────────

describe('analyzeJwtSecurity', () => {
  it('flags "none" algorithm', () => {
    const token = buildNoneAlgToken({ sub: '1' });
    const parsed = parseJwt(token)!;
    const issues = analyzeJwtSecurity(parsed, token);
    expect(issues.some((i) => i.issue.includes('"none" algorithm'))).toBe(true);
    expect(issues.find((i) => i.issue.includes('"none"'))!.severity).toBe('critical');
  });

  it('flags missing expiry', () => {
    const token = createTestJwt({ alg: 'HS256' }, { sub: '1' });
    const parsed = parseJwt(token)!;
    const issues = analyzeJwtSecurity(parsed, token);
    expect(issues.some((i) => i.issue.includes('no expiry'))).toBe(true);
  });

  it('flags excessively long expiry', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 86400 * 365; // 1 year
    const token = createTestJwt({ alg: 'HS256' }, { sub: '1', exp: futureExp });
    const parsed = parseJwt(token)!;
    const issues = analyzeJwtSecurity(parsed, token);
    expect(issues.some((i) => i.issue.includes('long expiry'))).toBe(true);
  });

  it('does NOT flag reasonable expiry', () => {
    const reasonableExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour
    const token = createTestJwt({ alg: 'HS256' }, { sub: '1', exp: reasonableExp });
    const parsed = parseJwt(token)!;
    const issues = analyzeJwtSecurity(parsed, token);
    expect(issues.some((i) => i.issue.includes('long expiry'))).toBe(false);
  });

  it('flags sensitive data in payload', () => {
    const token = createTestJwt({ alg: 'HS256' }, { sub: '1', password: 'hunter2' });
    const parsed = parseJwt(token)!;
    const issues = analyzeJwtSecurity(parsed, token);
    expect(issues.some((i) => i.issue.includes('sensitive field: password'))).toBe(true);
  });

  it('flags empty signature with signing algorithm', () => {
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const p = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const token = `${h}.${p}.`;
    const parsed = parseJwt(token)!;
    const issues = analyzeJwtSecurity(parsed, token);
    expect(issues.some((i) => i.issue.includes('empty signature'))).toBe(true);
  });
});

// ─── Weak Secret Detection ──────────────────────────────────────────

describe('verifyHs256', () => {
  it('returns true for correct secret', async () => {
    // Manually create a proper HS256 JWT with known secret
    const { createHmac } = await import('node:crypto');
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const sig = createHmac('sha256', 'secret')
      .update(`${header}.${payload}`)
      .digest()
      .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const token = `${header}.${payload}.${sig}`;

    expect(verifyHs256(token, 'secret')).toBe(true);
    expect(verifyHs256(token, 'wrong-secret')).toBe(false);
  });
});

// ─── Check Metadata ─────────────────────────────────────────────────

describe('jwtCheck metadata', () => {
  it('has correct name and category', () => {
    expect(jwtCheck.name).toBe('jwt');
    expect(jwtCheck.category).toBe('jwt');
  });
});

// ─── Weak Secrets List ──────────────────────────────────────────────

describe('WEAK_SECRETS', () => {
  it('contains common weak secrets', () => {
    expect(WEAK_SECRETS).toContain('secret');
    expect(WEAK_SECRETS).toContain('password');
    expect(WEAK_SECRETS).toContain('your-256-bit-secret');
    expect(WEAK_SECRETS).toContain('changeme');
  });

  it('has at least 20 entries', () => {
    expect(WEAK_SECRETS.length).toBeGreaterThanOrEqual(20);
  });
});

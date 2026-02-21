import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestServer, stopTestServer, getTestUrl } from '../setup.js';

describe('Vulnerable Test Server', () => {
  beforeAll(async () => { await startTestServer(); });
  afterAll(async () => { await stopTestServer(); });

  it('starts and responds on root', async () => {
    const res = await fetch(getTestUrl());
    expect(res.status).toBe(200);
  });

  it('has missing security headers', async () => {
    const res = await fetch(getTestUrl());
    expect(res.headers.get('content-security-policy')).toBeNull();
    expect(res.headers.get('strict-transport-security')).toBeNull();
    expect(res.headers.get('x-frame-options')).toBeNull();
    expect(res.headers.get('x-content-type-options')).toBeNull();
    expect(res.headers.get('referrer-policy')).toBeNull();
  });

  it('reflects XSS in search', async () => {
    const res = await fetch(`${getTestUrl()}/search?q=<script>alert(1)</script>`);
    const body = await res.text();
    expect(body).toContain('<script>alert(1)</script>');
  });

  it('has open redirect', async () => {
    const res = await fetch(`${getTestUrl()}/redirect?url=https://evil.com`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://evil.com');
  });

  it('reflects SQL errors', async () => {
    const res = await fetch(`${getTestUrl()}/api/v1/data?query='`);
    const body = await res.text();
    expect(body.toLowerCase()).toContain('sql');
  });

  it('has CORS misconfiguration', async () => {
    const res = await fetch(`${getTestUrl()}/cors-api`);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-credentials')).toBe('true');
  });

  it('safe page has security headers', async () => {
    const res = await fetch(`${getTestUrl()}/safe`);
    expect(res.headers.get('content-security-policy')).not.toBeNull();
    expect(res.headers.get('x-frame-options')).toBe('DENY');
  });

  it('has SSRF endpoint', async () => {
    const res = await fetch(`${getTestUrl()}/fetch?url=http://127.0.0.1`);
    expect(res.status).toBe(200);
  });

  it('has directory traversal endpoint', async () => {
    const res = await fetch(`${getTestUrl()}/files?path=../../etc/passwd`);
    const body = await res.text();
    expect(body).toContain('../../etc/passwd');
  });

  it('has command injection endpoint', async () => {
    const res = await fetch(`${getTestUrl()}/exec?cmd=whoami`);
    const body = await res.text();
    expect(body).toContain('whoami');
    expect(body).toContain('[CMD_START]');
    expect(body).toContain('[CMD_END]');
  });

  it('has SSTI endpoint', async () => {
    const res = await fetch(`${getTestUrl()}/template?name={{7*7}}`);
    const body = await res.text();
    expect(body).toContain('49');
  });

  it('serves forms on login page', async () => {
    const res = await fetch(`${getTestUrl()}/login`);
    const body = await res.text();
    expect(body).toContain('<form');
    expect(body).toContain('password');
  });

  it('has sequential user IDs', async () => {
    const res1 = await fetch(`${getTestUrl()}/api/v1/users/1`);
    const res2 = await fetch(`${getTestUrl()}/api/v1/users/2`);
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
  });

  it('sets cookies without proper flags', async () => {
    const res = await fetch(getTestUrl());
    const cookies = res.headers.getSetCookie();
    expect(cookies.length).toBeGreaterThan(0);
    // At least one cookie should lack HttpOnly
    const hasNonHttpOnly = cookies.some(c => !c.toLowerCase().includes('httponly'));
    expect(hasNonHttpOnly).toBe(true);
    // session cookie should lack Secure flag
    const sessionCookie = cookies.find(c => c.startsWith('session='));
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie!.toLowerCase()).not.toContain('secure');
  });
});

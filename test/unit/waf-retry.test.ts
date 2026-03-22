import { describe, it, expect } from 'vitest';
import { isWafBlock } from '../../src/utils/waf-retry.js';

describe('isWafBlock', () => {
  it('detects 403 + "Access Denied" as WAF block', () => {
    expect(isWafBlock(403, '<html><body>Access Denied</body></html>')).toBe(true);
  });

  it('detects 403 + "Forbidden" as WAF block', () => {
    expect(isWafBlock(403, 'Request Forbidden by security policy')).toBe(true);
  });

  it('detects 403 + "Blocked" as WAF block', () => {
    expect(isWafBlock(403, 'Your request has been blocked')).toBe(true);
  });

  it('detects 403 + Cloudflare page as WAF block', () => {
    expect(isWafBlock(403, '<title>Attention Required! | Cloudflare</title>')).toBe(true);
  });

  it('detects 403 + Akamai as WAF block', () => {
    expect(isWafBlock(403, 'This request was blocked by Akamai WAF')).toBe(true);
  });

  it('detects 403 + Incapsula as WAF block', () => {
    expect(isWafBlock(403, 'Powered by Incapsula')).toBe(true);
  });

  it('detects 403 + "Web Application Firewall" as WAF block', () => {
    expect(isWafBlock(403, 'Blocked by Web Application Firewall')).toBe(true);
  });

  it('detects 403 + "security policy" as WAF block', () => {
    expect(isWafBlock(403, 'Denied by security policy')).toBe(true);
  });

  it('returns false for 200 responses', () => {
    expect(isWafBlock(200, 'Access Denied')).toBe(false);
  });

  it('returns false for 404 responses', () => {
    expect(isWafBlock(404, 'Forbidden path not found')).toBe(false);
  });

  it('returns false for 500 responses with block-like text', () => {
    expect(isWafBlock(500, 'Internal error: access denied')).toBe(false);
  });

  it('returns false for 403 without block patterns', () => {
    expect(isWafBlock(403, 'You do not have permission to view this directory')).toBe(false);
  });

  it('returns false for 403 with empty body', () => {
    expect(isWafBlock(403, '')).toBe(false);
  });

  it('returns false for 403 with generic HTML', () => {
    expect(isWafBlock(403, '<html><body><h1>403</h1></body></html>')).toBe(false);
  });

  it('is case-insensitive for pattern matching', () => {
    expect(isWafBlock(403, 'ACCESS DENIED')).toBe(true);
    expect(isWafBlock(403, 'access denied')).toBe(true);
    expect(isWafBlock(403, 'Access Denied')).toBe(true);
  });
});

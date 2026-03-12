import { describe, it, expect } from 'vitest';
import { oauthCheck, findOAuthEndpoints } from '../../src/scanner/active/oauth.js';

describe('findOAuthEndpoints', () => {
  it('detects /oauth/ URLs', () => {
    const pages = ['https://example.com/oauth/authorize', 'https://example.com/home'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toContain('https://example.com/oauth/authorize');
    expect(result).not.toContain('https://example.com/home');
  });

  it('detects /authorize URLs', () => {
    const pages = ['https://example.com/authorize?response_type=code', 'https://example.com/'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(1);
    expect(result[0]).toContain('/authorize');
  });

  it('detects /auth/callback URLs', () => {
    const pages = ['https://example.com/auth/callback'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(1);
  });

  it('detects /api/auth URLs', () => {
    const apiEndpoints = ['https://example.com/api/auth/signin', 'https://example.com/api/users'];
    const result = findOAuthEndpoints([], apiEndpoints);
    expect(result).toContain('https://example.com/api/auth/signin');
    expect(result).not.toContain('https://example.com/api/users');
  });

  it('detects /login/oauth URLs', () => {
    const pages = ['https://example.com/login/oauth/authorize'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(1);
  });

  it('detects /connect/authorize URLs', () => {
    const pages = ['https://example.com/connect/authorize'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(1);
  });

  it('detects .well-known/openid URLs', () => {
    const pages = ['https://example.com/.well-known/openid-configuration'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(1);
  });

  it('detects /oauth2/ URLs', () => {
    const pages = ['https://example.com/oauth2/token'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(1);
  });

  it('returns empty array when no OAuth endpoints present', () => {
    const pages = ['https://example.com/', 'https://example.com/about', 'https://example.com/api/users'];
    const result = findOAuthEndpoints(pages, []);
    expect(result).toHaveLength(0);
  });

  it('combines pages and apiEndpoints for detection', () => {
    const pages = ['https://example.com/home'];
    const apiEndpoints = ['https://example.com/oauth2/authorize'];
    const result = findOAuthEndpoints(pages, apiEndpoints);
    expect(result).toHaveLength(1);
    expect(result[0]).toContain('/oauth2/');
  });
});

describe('oauthCheck', () => {
  it('has correct name', () => {
    expect(oauthCheck.name).toBe('oauth');
  });

  it('has correct category', () => {
    expect(oauthCheck.category).toBe('oauth');
  });

  it('is marked as parallel', () => {
    expect(oauthCheck.parallel).toBe(true);
  });

  it('has a run function', () => {
    expect(typeof oauthCheck.run).toBe('function');
  });

  it('returns empty array when no pages or endpoints', async () => {
    const mockContext = {} as import('playwright').BrowserContext;
    const targets = {
      pages: [],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };
    const config = {
      targetUrl: 'https://example.com',
      profile: 'standard' as const,
      timeout: 5000,
    } as import('../../src/scanner/types.js').ScanConfig;

    const findings = await oauthCheck.run(mockContext, targets, config);
    expect(findings).toEqual([]);
  });

  it('returns empty array when pages have no OAuth endpoints or exposed tokens', async () => {
    const mockContext = {} as import('playwright').BrowserContext;
    const targets = {
      pages: ['https://example.com/', 'https://example.com/about'],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [],
      redirectUrls: [],
      fileParams: [],
    };
    const config = {
      targetUrl: 'https://example.com',
      profile: 'standard' as const,
      timeout: 1000,
    } as import('../../src/scanner/types.js').ScanConfig;

    const findings = await oauthCheck.run(mockContext, targets, config);
    expect(findings).toEqual([]);
  });
});

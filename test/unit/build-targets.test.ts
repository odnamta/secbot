import { describe, it, expect } from 'vitest';
import { buildTargets } from '../../src/scanner/active/index.js';
import type { CrawledPage } from '../../src/scanner/types.js';

function makePage(url: string, links: string[] = []): CrawledPage {
  return {
    url,
    status: 200,
    headers: {},
    title: 'Test',
    forms: [],
    links,
    scripts: [],
    cookies: [],
  };
}

describe('buildTargets', () => {
  it('discovers API endpoints from page URLs', () => {
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/api/v1/users'),
    ];
    const targets = buildTargets(pages, 'https://example.com');
    expect(targets.apiEndpoints).toContain('https://example.com/api/v1/users');
  });

  it('discovers URLs with query parameters from page URLs', () => {
    const pages = [
      makePage('https://example.com/search?q=test'),
    ];
    const targets = buildTargets(pages, 'https://example.com');
    expect(targets.urlsWithParams).toContain('https://example.com/search?q=test');
  });

  it('extracts API endpoints from intercepted network responses', () => {
    const pages = [makePage('https://example.com/')];
    const responses = [
      { url: 'https://example.com/api/v2/config', status: 200, headers: { 'content-type': 'application/json' } },
      { url: 'https://example.com/graphql', status: 200, headers: { 'content-type': 'application/json' } },
      { url: 'https://example.com/rest/users', status: 200, headers: { 'content-type': 'application/json' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    expect(targets.apiEndpoints).toContain('https://example.com/api/v2/config');
    expect(targets.apiEndpoints).toContain('https://example.com/graphql');
    expect(targets.apiEndpoints).toContain('https://example.com/rest/users');
  });

  it('extracts parameterized URLs from network responses', () => {
    const pages = [makePage('https://example.com/')];
    const responses = [
      { url: 'https://example.com/search?q=hello&page=1', status: 200, headers: { 'content-type': 'text/html' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    expect(targets.urlsWithParams).toContain('https://example.com/search?q=hello&page=1');
  });

  it('discovers JSON API endpoints by content-type even without /api/ in URL', () => {
    const pages = [makePage('https://example.com/')];
    const responses = [
      { url: 'https://example.com/data/users', status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    expect(targets.apiEndpoints).toContain('https://example.com/data/users');
  });

  it('excludes static assets from API endpoint discovery', () => {
    const pages = [makePage('https://example.com/')];
    const responses = [
      { url: 'https://example.com/app.js', status: 200, headers: { 'content-type': 'application/javascript' } },
      { url: 'https://example.com/style.css', status: 200, headers: { 'content-type': 'text/css' } },
      { url: 'https://example.com/logo.png', status: 200, headers: { 'content-type': 'image/png' } },
      { url: 'https://example.com/font.woff2', status: 200, headers: { 'content-type': 'font/woff2' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    expect(targets.apiEndpoints).toEqual([]);
  });

  it('respects scope when extracting from network traffic', () => {
    const pages = [makePage('https://example.com/')];
    const responses = [
      { url: 'https://analytics.other.com/api/track', status: 200, headers: { 'content-type': 'application/json' } },
      { url: 'https://example.com/api/v1/data', status: 200, headers: { 'content-type': 'application/json' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    expect(targets.apiEndpoints).toContain('https://example.com/api/v1/data');
    expect(targets.apiEndpoints).not.toContain('https://analytics.other.com/api/track');
  });

  it('strips query params from API endpoint base URLs', () => {
    const pages = [makePage('https://example.com/')];
    const responses = [
      { url: 'https://example.com/api/v1/search?q=test&limit=10', status: 200, headers: { 'content-type': 'application/json' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    // Base URL without params should be in apiEndpoints
    expect(targets.apiEndpoints).toContain('https://example.com/api/v1/search');
    // Full URL with params should be in urlsWithParams
    expect(targets.urlsWithParams).toContain('https://example.com/api/v1/search?q=test&limit=10');
  });

  it('deduplicates endpoints from pages and network traffic', () => {
    const pages = [
      makePage('https://example.com/'),
      makePage('https://example.com/api/v1/users'),
    ];
    const responses = [
      { url: 'https://example.com/api/v1/users', status: 200, headers: { 'content-type': 'application/json' } },
    ];
    const targets = buildTargets(pages, 'https://example.com', undefined, responses);
    const userApiCount = targets.apiEndpoints.filter(u => u === 'https://example.com/api/v1/users').length;
    expect(userApiCount).toBe(1);
  });
});

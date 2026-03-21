import { describe, it, expect } from 'vitest';
import { determineRelevantChecks, buildDefaultPlan } from '../../src/ai/planner.js';
import type { CrawledPage, ReconResult } from '../../src/scanner/types.js';

function makeRecon(overrides: Partial<ReconResult> = {}): ReconResult {
  return {
    techStack: { detected: [], raw: [] },
    waf: { detected: false, name: null, confidence: 0 },
    framework: null,
    endpoints: { pages: [], apiRoutes: [], graphql: [] },
    ...overrides,
  } as ReconResult;
}

function makePage(url: string, overrides: Partial<CrawledPage> = {}): CrawledPage {
  return {
    url,
    title: 'Test',
    links: [],
    forms: [],
    cookies: [],
    scripts: [],
    meta: {},
    headers: {},
    ...overrides,
  } as CrawledPage;
}

describe('determineRelevantChecks', () => {
  it('should always include cors, host-header, info-disclosure, sri, subdomain-takeover', () => {
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [makePage('https://example.com')]);
    expect(checks).toContain('cors');
    expect(checks).toContain('host-header');
    expect(checks).toContain('info-disclosure');
    expect(checks).toContain('subdomain-takeover');
  });

  it('should include xss when pages exist (even without forms or params)', () => {
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [makePage('https://example.com')]);
    expect(checks).toContain('xss');
  });

  it('should include xss and sqli when forms exist', () => {
    const page = makePage('https://example.com', {
      forms: [{
        pageUrl: 'https://example.com',
        action: '/search',
        method: 'GET',
        inputs: [{ name: 'q', type: 'text', value: '' }],
      }],
    });
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('xss');
    expect(checks).toContain('sqli');
  });

  it('should include csrf when POST forms exist', () => {
    const page = makePage('https://example.com', {
      forms: [{
        pageUrl: 'https://example.com',
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'email', type: 'text', value: '' }],
      }],
    });
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('csrf');
  });

  it('should NOT include csrf when only GET forms exist', () => {
    const page = makePage('https://example.com', {
      forms: [{
        pageUrl: 'https://example.com',
        action: '/search',
        method: 'GET',
        inputs: [{ name: 'q', type: 'text', value: '' }],
      }],
    });
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).not.toContain('csrf');
  });

  it('should include ssti when template-suggestive URL params exist', () => {
    const page = makePage('https://example.com/page?template=home');
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('ssti');
  });

  it('should include ssti when template engine detected', () => {
    const recon = makeRecon({ techStack: { detected: ['jinja2'], raw: ['jinja2'] } });
    const checks = determineRelevantChecks('https://example.com', recon, [makePage('https://example.com')]);
    expect(checks).toContain('ssti');
  });

  it('should include ssti for name/view/render URL params', () => {
    for (const param of ['name', 'view', 'render', 'layout', 'theme']) {
      const page = makePage(`https://example.com/test?${param}=hello`);
      const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
      expect(checks).toContain('ssti');
    }
  });

  it('should include tls for HTTPS targets', () => {
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [makePage('https://example.com')]);
    expect(checks).toContain('tls');
  });

  it('should NOT include tls for HTTP targets', () => {
    const checks = determineRelevantChecks('http://example.com', makeRecon(), [makePage('http://example.com')]);
    expect(checks).not.toContain('tls');
  });

  it('should include xss/sqli when network traffic reveals parameterized URLs', () => {
    const intercepted = [
      { url: 'https://example.com/api/search?q=test', status: 200, headers: { 'content-type': 'application/json' } },
    ];
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [makePage('https://example.com')], intercepted);
    expect(checks).toContain('xss');
    expect(checks).toContain('sqli');
  });

  it('should include cmdi when URLs have query params', () => {
    const page = makePage('https://example.com/exec?cmd=test');
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('cmdi');
  });

  it('should include graphql when graphql endpoints exist', () => {
    const recon = makeRecon({ endpoints: { pages: [], apiRoutes: [], graphql: ['/graphql'] } });
    const checks = determineRelevantChecks('https://example.com', recon, [makePage('https://example.com')]);
    expect(checks).toContain('graphql');
  });

  it('should include oauth when oauth URLs detected', () => {
    const page = makePage('https://example.com', {
      links: ['https://example.com/oauth/authorize'],
    });
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('oauth');
  });

  it('should include csrf when API endpoints exist (even without POST forms)', () => {
    const intercepted = [
      { url: 'https://example.com/api/users', status: 200, headers: { 'content-type': 'application/json' } },
    ];
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [makePage('https://example.com')], intercepted);
    expect(checks).toContain('csrf');
  });

  it('should NOT include csrf when no POST forms and no API endpoints', () => {
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [makePage('https://example.com')]);
    expect(checks).not.toContain('csrf');
  });

  it('should include websocket when socket.io script found', () => {
    const page = makePage('https://example.com', {
      scripts: ['https://cdn.socket.io/socket.io.js'],
    });
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('websocket');
  });

  it('should include websocket when wss:// link found', () => {
    const page = makePage('https://example.com', {
      links: ['wss://example.com/ws'],
    });
    const checks = determineRelevantChecks('https://example.com', makeRecon(), [page]);
    expect(checks).toContain('websocket');
  });
});

describe('buildDefaultPlan', () => {
  it('should include ssti when template-suggestive URL params exist', () => {
    const page = makePage('https://example.com/page?template=home');
    const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).toContain('ssti');
  });

  it('should include ssti for view/render/layout params', () => {
    for (const param of ['view', 'render', 'layout']) {
      const page = makePage(`https://example.com/test?${param}=hello`);
      const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
      const checkNames = plan.recommendedChecks.map((c) => c.name);
      expect(checkNames).toContain('ssti');
    }
  });

  it('should include websocket when socket.io script found', () => {
    const page = makePage('https://example.com', {
      scripts: ['https://cdn.socket.io/socket.io.js'],
    });
    const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).toContain('websocket');
  });

  it('should NOT include websocket when no socket references', () => {
    const plan = buildDefaultPlan(makeRecon(), [makePage('https://example.com')], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).not.toContain('websocket');
  });

  it('should include traversal when file-like paths exist', () => {
    const page = makePage('https://example.com/files/document.pdf');
    const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).toContain('traversal');
  });

  it('should include traversal when /uploads/ path exists', () => {
    const page = makePage('https://example.com/uploads/avatar.png');
    const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).toContain('traversal');
  });

  it('should include csrf when POST forms exist (buildDefaultPlan)', () => {
    const page = makePage('https://example.com', {
      forms: [{
        pageUrl: 'https://example.com',
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'email', type: 'text', value: '' }],
      }],
    });
    const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).toContain('csrf');
  });

  it('should include csrf when API endpoints exist (buildDefaultPlan)', () => {
    const page = makePage('https://example.com/api/users');
    const plan = buildDefaultPlan(makeRecon(), [page], 'standard');
    const checkNames = plan.recommendedChecks.map((c) => c.name);
    expect(checkNames).toContain('csrf');
  });
});

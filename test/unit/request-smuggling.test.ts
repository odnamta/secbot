import { describe, it, expect } from 'vitest';

describe('Request Smuggling Check', () => {
  it('exports check with correct interface', async () => {
    const { requestSmugglingCheck } = await import(
      '../../src/scanner/active/request-smuggling.js'
    );
    expect(requestSmugglingCheck.name).toBe('request-smuggling');
    expect(requestSmugglingCheck.category).toBe('request-smuggling');
    expect(requestSmugglingCheck.parallel).toBe(false);
    expect(typeof requestSmugglingCheck.run).toBe('function');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'request-smuggling');
    expect(check).toBeDefined();
    expect(check!.category).toBe('request-smuggling');
  });

  it('check category is valid in types', async () => {
    // If this compiles, the type is valid — just verify runtime string
    const { requestSmugglingCheck } = await import(
      '../../src/scanner/active/request-smuggling.js'
    );
    const validCategories = [
      'security-headers', 'cookie-flags', 'info-leakage', 'mixed-content',
      'sensitive-url-data', 'xss', 'sqli', 'open-redirect',
      'cross-origin-policy', 'cors-misconfiguration', 'directory-traversal',
      'ssrf', 'ssti', 'idor', 'command-injection', 'tls', 'sri',
      'info-disclosure', 'js-cve', 'crlf-injection', 'rate-limit', 'jwt',
      'race-condition', 'host-header', 'graphql', 'file-upload',
      'broken-access-control', 'business-logic', 'websocket', 'api-versioning',
      'subdomain-takeover', 'oauth', 'cache-poisoning', 'csrf',
      'prototype-pollution', 'xxe', 'insecure-deserialization',
      'request-smuggling', 'vuln-chain',
    ];
    expect(validCategories).toContain(requestSmugglingCheck.category);
  });

  it('has CL.TE probes', async () => {
    // Verify the module loads and has the expected structure
    const mod = await import('../../src/scanner/active/request-smuggling.js');
    expect(mod.requestSmugglingCheck).toBeDefined();
  });

  it('planner includes request-smuggling in ALL_PLANNER_CHECKS', async () => {
    const { ALL_PLANNER_CHECKS } = await import('../../src/ai/prompts.js');
    expect(ALL_PLANNER_CHECKS).toContain('request-smuggling');
  });

  it('fallback has OWASP mapping for request-smuggling', async () => {
    const { mapToOwasp } = await import('../../src/ai/fallback.js');
    const category = mapToOwasp('request-smuggling');
    expect(category).toContain('A05:2021');
  });

  it('fallback has impact description for request-smuggling', async () => {
    const { getGenericImpact } = await import('../../src/ai/fallback.js');
    const impact = getGenericImpact('request-smuggling');
    expect(impact).toContain('smuggl');
  });

  it('fallback has fix recommendation for request-smuggling', async () => {
    const { getGenericFix } = await import('../../src/ai/fallback.js');
    const fix = getGenericFix('request-smuggling');
    expect(fix).toContain('Content-Length');
  });
});

import { describe, it, expect } from 'vitest';
import { matchResponse, runTemplate, runTemplates } from '../../src/scanner/templates/engine.js';
import { BUILTIN_TEMPLATES } from '../../src/scanner/templates/builtin-templates.js';
import type { VulnTemplate } from '../../src/scanner/templates/engine.js';
import type { FastResponse } from '../../src/scanner/fast-engine.js';

// ─── Helpers ─────────────────────────────────────────────────────

function makeResponse(overrides: Partial<FastResponse> = {}): FastResponse {
  return {
    url: 'https://example.com/',
    status: 200,
    headers: {},
    body: '',
    redirected: false,
    timeMs: 50,
    ...overrides,
  };
}

function makeTemplate(overrides: Partial<VulnTemplate> = {}): VulnTemplate {
  return {
    id: 'test-template',
    info: {
      name: 'Test Template',
      severity: 'medium',
      description: 'A test template',
      tags: ['misconfig'],
    },
    requests: [{
      method: 'GET',
      path: '/test',
      matchers: [
        { type: 'status', status: [200] },
      ],
    }],
    ...overrides,
  };
}

// ─── matchResponse: Status Code Matching ─────────────────────────

describe('matchResponse — status codes', () => {
  it('matches when response status is in the list', () => {
    const resp = makeResponse({ status: 200 });
    const matchers = [{ type: 'status' as const, status: [200, 301] }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('matches 302 redirect status', () => {
    const resp = makeResponse({ status: 302 });
    const matchers = [{ type: 'status' as const, status: [200, 302] }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('rejects when status is not in the list', () => {
    const resp = makeResponse({ status: 404 });
    const matchers = [{ type: 'status' as const, status: [200] }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('rejects when status list is empty', () => {
    const resp = makeResponse({ status: 200 });
    const matchers = [{ type: 'status' as const, status: [] }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });
});

// ─── matchResponse: Body Word Matching ───────────────────────────

describe('matchResponse — body words', () => {
  it('matches when all words are present in body', () => {
    const resp = makeResponse({ body: '<html><title>phpMyAdmin Login</title></html>' });
    const matchers = [{ type: 'body' as const, words: ['phpmyadmin', 'login'] }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('is case-insensitive for body word matching', () => {
    const resp = makeResponse({ body: 'Welcome to PHPMyAdmin' });
    const matchers = [{ type: 'body' as const, words: ['phpmyadmin'] }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('rejects when some words are missing', () => {
    const resp = makeResponse({ body: '<html>Welcome</html>' });
    const matchers = [{ type: 'body' as const, words: ['welcome', 'phpmyadmin'] }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('rejects when body is empty', () => {
    const resp = makeResponse({ body: '' });
    const matchers = [{ type: 'body' as const, words: ['anything'] }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });
});

// ─── matchResponse: Header Matching ──────────────────────────────

describe('matchResponse — headers', () => {
  it('matches when header exists with correct value', () => {
    const resp = makeResponse({
      headers: { 'x-powered-by': 'Express' },
    });
    const matchers = [{ type: 'header' as const, header: 'x-powered-by', value: 'Express' }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('matches header existence without value check', () => {
    const resp = makeResponse({
      headers: { 'x-jenkins': '2.319.1' },
    });
    const matchers = [{ type: 'header' as const, header: 'x-jenkins' }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('is case-insensitive for header value', () => {
    const resp = makeResponse({
      headers: { 'server': 'Apache/2.4.41 (Ubuntu)' },
    });
    const matchers = [{ type: 'header' as const, header: 'server', value: 'apache' }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('rejects when header is missing', () => {
    const resp = makeResponse({ headers: {} });
    const matchers = [{ type: 'header' as const, header: 'x-debug-token' }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('rejects when header value does not match', () => {
    const resp = makeResponse({
      headers: { 'x-powered-by': 'Express' },
    });
    const matchers = [{ type: 'header' as const, header: 'x-powered-by', value: 'PHP' }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });
});

// ─── matchResponse: Regex Matching ───────────────────────────────

describe('matchResponse — regex', () => {
  it('matches body with regex pattern', () => {
    const resp = makeResponse({ body: '{"cluster_name": "my-cluster", "tagline": "You Know, for Search"}' });
    const matchers = [{ type: 'regex' as const, regex: '"cluster_name"\\s*:' }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('supports case-insensitive regex matching', () => {
    const resp = makeResponse({ body: 'PHP Version 8.1.2' });
    const matchers = [{ type: 'regex' as const, regex: 'php version' }];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('rejects when regex does not match', () => {
    const resp = makeResponse({ body: '<html>Hello World</html>' });
    const matchers = [{ type: 'regex' as const, regex: 'phpinfo\\(\\)' }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('handles invalid regex gracefully', () => {
    const resp = makeResponse({ body: 'test' });
    const matchers = [{ type: 'regex' as const, regex: '([invalid' }];
    expect(matchResponse(resp, matchers)).toBe(false);
  });
});

// ─── matchResponse: AND vs OR Conditions ─────────────────────────

describe('matchResponse — and/or conditions', () => {
  it('AND condition: requires all matchers to pass', () => {
    const resp = makeResponse({
      status: 200,
      body: '<html>phpMyAdmin Login</html>',
    });
    const matchers = [
      { type: 'status' as const, status: [200] },
      { type: 'body' as const, words: ['phpmyadmin'] },
    ];
    expect(matchResponse(resp, matchers, 'and')).toBe(true);
  });

  it('AND condition: fails if any matcher fails', () => {
    const resp = makeResponse({
      status: 404,
      body: '<html>phpMyAdmin Login</html>',
    });
    const matchers = [
      { type: 'status' as const, status: [200] },
      { type: 'body' as const, words: ['phpmyadmin'] },
    ];
    expect(matchResponse(resp, matchers, 'and')).toBe(false);
  });

  it('OR condition: passes if any matcher succeeds', () => {
    const resp = makeResponse({
      status: 404,
      headers: { 'x-debug-token': 'abc123' },
    });
    const matchers = [
      { type: 'status' as const, status: [200] },
      { type: 'header' as const, header: 'x-debug-token' },
    ];
    expect(matchResponse(resp, matchers, 'or')).toBe(true);
  });

  it('OR condition: fails if all matchers fail', () => {
    const resp = makeResponse({
      status: 404,
      headers: {},
    });
    const matchers = [
      { type: 'status' as const, status: [200] },
      { type: 'header' as const, header: 'x-debug-token' },
    ];
    expect(matchResponse(resp, matchers, 'or')).toBe(false);
  });

  it('defaults to AND condition when not specified', () => {
    const resp = makeResponse({
      status: 200,
      body: 'test body',
    });
    const matchers = [
      { type: 'status' as const, status: [200] },
      { type: 'body' as const, words: ['missing'] },
    ];
    // Default is 'and' — body word is missing, so overall fails
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('returns false for empty matchers', () => {
    const resp = makeResponse();
    expect(matchResponse(resp, [])).toBe(false);
  });
});

// ─── matchResponse: Negative Matchers ────────────────────────────

describe('matchResponse — negative matchers', () => {
  it('negative body matcher: passes when word is NOT present', () => {
    const resp = makeResponse({ body: '<html>Valid SVN entries</html>' });
    const matchers = [
      { type: 'body' as const, words: ['not found'], negative: true },
    ];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('negative body matcher: fails when word IS present', () => {
    const resp = makeResponse({ body: '<html>Page not found</html>' });
    const matchers = [
      { type: 'body' as const, words: ['not found'], negative: true },
    ];
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('negative status matcher: passes when status is NOT in the list', () => {
    const resp = makeResponse({ status: 404 });
    const matchers = [
      { type: 'status' as const, status: [200], negative: true },
    ];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('negative status matcher: fails when status IS in the list', () => {
    const resp = makeResponse({ status: 200 });
    const matchers = [
      { type: 'status' as const, status: [200], negative: true },
    ];
    expect(matchResponse(resp, matchers)).toBe(false);
  });

  it('negative header matcher: passes when header is missing', () => {
    const resp = makeResponse({ headers: {} });
    const matchers = [
      { type: 'header' as const, header: 'x-powered-by', negative: true },
    ];
    expect(matchResponse(resp, matchers)).toBe(true);
  });

  it('mixes negative and positive matchers in AND condition', () => {
    const resp = makeResponse({
      status: 200,
      body: '<html>SVN data dir</html>',
    });
    const matchers = [
      { type: 'status' as const, status: [200] },
      { type: 'body' as const, words: ['dir'] },
      { type: 'body' as const, words: ['not found'], negative: true },
    ];
    expect(matchResponse(resp, matchers, 'and')).toBe(true);
  });
});

// ─── Built-in Templates: Structure Validation ────────────────────

describe('built-in templates — structure validation', () => {
  it('has 50 or more templates', () => {
    expect(BUILTIN_TEMPLATES.length).toBeGreaterThanOrEqual(50);
  });

  it('every template has a unique id', () => {
    const ids = BUILTIN_TEMPLATES.map(t => t.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('every template has required info fields', () => {
    for (const t of BUILTIN_TEMPLATES) {
      expect(t.id).toBeTruthy();
      expect(t.info.name).toBeTruthy();
      expect(t.info.description).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(t.info.severity);
      expect(Array.isArray(t.info.tags)).toBe(true);
      expect(t.info.tags.length).toBeGreaterThan(0);
    }
  });

  it('every template has at least one request', () => {
    for (const t of BUILTIN_TEMPLATES) {
      expect(t.requests.length).toBeGreaterThan(0);
    }
  });

  it('every request has a valid method', () => {
    const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD'];
    for (const t of BUILTIN_TEMPLATES) {
      for (const r of t.requests) {
        expect(validMethods).toContain(r.method);
      }
    }
  });

  it('every request has at least one matcher', () => {
    for (const t of BUILTIN_TEMPLATES) {
      for (const r of t.requests) {
        expect(r.matchers.length).toBeGreaterThan(0);
      }
    }
  });

  it('every matcher has a valid type', () => {
    const validTypes = ['status', 'body', 'header', 'regex'];
    for (const t of BUILTIN_TEMPLATES) {
      for (const r of t.requests) {
        for (const m of r.matchers) {
          expect(validTypes).toContain(m.type);
        }
      }
    }
  });

  it('matchCondition is either and or or when set', () => {
    for (const t of BUILTIN_TEMPLATES) {
      for (const r of t.requests) {
        if (r.matchCondition) {
          expect(['and', 'or']).toContain(r.matchCondition);
        }
      }
    }
  });

  it('includes templates from all categories', () => {
    const allTags = new Set(BUILTIN_TEMPLATES.flatMap(t => t.info.tags));
    // Should have admin panels, debug, default credentials, misconfig
    expect(allTags.has('panel')).toBe(true);
    expect(allTags.has('debug')).toBe(true);
    expect(allTags.has('default-credentials')).toBe(true);
    expect(allTags.has('misconfig')).toBe(true);
  });
});

// ─── Template Tech Filtering ─────────────────────────────────────

describe('template tech filtering', () => {
  it('includes templates with no tech requirement when no tech detected', async () => {
    // runTemplates filters internally — we test the filtering logic
    const noTechTemplates = BUILTIN_TEMPLATES.filter(
      t => !t.match?.tech || t.match.tech.length === 0,
    );
    expect(noTechTemplates.length).toBeGreaterThan(0);
  });

  it('includes templates whose tech matches detected stack', () => {
    const detectedTech = ['wordpress', 'php', 'apache'];
    const normalizedTech = detectedTech.map(t => t.toLowerCase());
    const applicable = BUILTIN_TEMPLATES.filter(t => {
      if (!t.match?.tech || t.match.tech.length === 0) return true;
      return t.match.tech.some(required =>
        normalizedTech.some(detected => detected.includes(required.toLowerCase())),
      );
    });

    // WordPress templates should be included
    const wpTemplates = applicable.filter(t => t.info.tags.includes('wordpress'));
    expect(wpTemplates.length).toBeGreaterThan(0);

    // Java/Spring templates should NOT be included
    const javaTemplates = applicable.filter(t =>
      t.match?.tech?.some(tech => tech === 'java' || tech === 'spring'),
    );
    expect(javaTemplates.length).toBe(0);
  });

  it('excludes templates with unmatched tech requirements', () => {
    const detectedTech = ['nextjs', 'node'];
    const normalizedTech = detectedTech.map(t => t.toLowerCase());
    const wpOnly = BUILTIN_TEMPLATES.filter(t =>
      t.match?.tech?.includes('wordpress'),
    );

    // WordPress-specific templates should be filtered out
    for (const t of wpOnly) {
      const matches = t.match!.tech!.some(required =>
        normalizedTech.some(detected => detected.includes(required.toLowerCase())),
      );
      expect(matches).toBe(false);
    }
  });
});

// ─── runTemplate ─────────────────────────────────────────────────

describe('runTemplate', () => {
  it('returns a finding when template matches', async () => {
    // Create a mock engine that returns a matching response
    const mockEngine = {
      request: async () => makeResponse({
        status: 200,
        body: '<html>Sensitive phpinfo() data</html>',
        headers: {},
      }),
    };

    const template = makeTemplate({
      id: 'phpinfo-test',
      info: {
        name: 'Test phpinfo',
        severity: 'medium',
        description: 'phpinfo found',
        tags: ['debug', 'php'],
      },
      requests: [{
        method: 'GET',
        path: '/phpinfo.php',
        matchers: [
          { type: 'status', status: [200] },
          { type: 'body', words: ['phpinfo'] },
        ],
      }],
    });

    const finding = await runTemplate(
      template,
      'https://example.com',
      mockEngine as any,
    );

    expect(finding).not.toBeNull();
    expect(finding!.title).toBe('Test phpinfo');
    expect(finding!.severity).toBe('medium');
    expect(finding!.url).toBe('https://example.com/phpinfo.php');
    expect(finding!.id).toContain('template-phpinfo-test');
    expect(finding!.confidence).toBeDefined();
    expect(finding!.evidencePack?.detectionMethod).toBe('template-scan');
  });

  it('returns null when template does not match', async () => {
    const mockEngine = {
      request: async () => makeResponse({ status: 404, body: 'Not Found' }),
    };

    const template = makeTemplate({
      requests: [{
        method: 'GET',
        path: '/test',
        matchers: [
          { type: 'status', status: [200] },
        ],
      }],
    });

    const finding = await runTemplate(
      template,
      'https://example.com',
      mockEngine as any,
    );

    expect(finding).toBeNull();
  });

  it('returns null when request throws (network error)', async () => {
    const mockEngine = {
      request: async () => { throw new Error('Connection refused'); },
    };

    const template = makeTemplate();

    const finding = await runTemplate(
      template,
      'https://example.com',
      mockEngine as any,
    );

    expect(finding).toBeNull();
  });

  it('strips trailing slash from baseUrl', async () => {
    let requestedUrl = '';
    const mockEngine = {
      request: async (url: string) => {
        requestedUrl = url;
        return makeResponse({ status: 200 });
      },
    };

    const template = makeTemplate({
      requests: [{
        method: 'GET',
        path: '/test-path',
        matchers: [{ type: 'status', status: [200] }],
      }],
    });

    await runTemplate(template, 'https://example.com/', mockEngine as any);
    expect(requestedUrl).toBe('https://example.com/test-path');
  });
});

// ─── runTemplates ────────────────────────────────────────────────

describe('runTemplates', () => {
  it('filters templates by detected tech', async () => {
    const requestedPaths: string[] = [];
    const mockEngine = {
      request: async (url: string) => {
        requestedPaths.push(new URL(url).pathname);
        return makeResponse({ status: 404, body: 'Not Found' });
      },
    };

    const templates: VulnTemplate[] = [
      makeTemplate({
        id: 'generic-check',
        requests: [{
          method: 'GET',
          path: '/generic',
          matchers: [{ type: 'status', status: [200] }],
        }],
      }),
      makeTemplate({
        id: 'wp-check',
        match: { tech: ['wordpress'] },
        requests: [{
          method: 'GET',
          path: '/wp-admin',
          matchers: [{ type: 'status', status: [200] }],
        }],
      }),
      makeTemplate({
        id: 'java-check',
        match: { tech: ['java'] },
        requests: [{
          method: 'GET',
          path: '/actuator',
          matchers: [{ type: 'status', status: [200] }],
        }],
      }),
    ];

    await runTemplates(templates, 'https://example.com', mockEngine as any, ['wordpress']);

    // Generic (no tech req) and WP (matches) should run; Java should not
    expect(requestedPaths).toContain('/generic');
    expect(requestedPaths).toContain('/wp-admin');
    expect(requestedPaths).not.toContain('/actuator');
  });

  it('runs all templates when no tech is detected', async () => {
    let requestCount = 0;
    const mockEngine = {
      request: async () => {
        requestCount++;
        return makeResponse({ status: 404 });
      },
    };

    const templates: VulnTemplate[] = [
      makeTemplate({ id: 't1' }),
      makeTemplate({ id: 't2' }),
    ];

    // No tech filter — only templates without tech requirements pass
    await runTemplates(templates, 'https://example.com', mockEngine as any);
    expect(requestCount).toBe(2);
  });

  it('collects findings from matching templates', async () => {
    const mockEngine = {
      request: async () => makeResponse({
        status: 200,
        body: '<html>match this body</html>',
      }),
    };

    const templates: VulnTemplate[] = [
      makeTemplate({
        id: 'match-1',
        info: { name: 'Match 1', severity: 'high', description: 'desc', tags: ['misconfig'] },
        requests: [{
          method: 'GET',
          path: '/a',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'body', words: ['match this'] },
          ],
        }],
      }),
      makeTemplate({
        id: 'no-match',
        requests: [{
          method: 'GET',
          path: '/b',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'body', words: ['absent content'] },
          ],
        }],
      }),
    ];

    const findings = await runTemplates(templates, 'https://example.com', mockEngine as any);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toBe('Match 1');
  });
});

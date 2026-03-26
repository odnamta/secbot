import { describe, it, expect } from 'vitest';
import { parseNucleiTemplate, extractMatchers, extractField } from '../../src/scanner/templates/yaml-loader.js';
import { loadTemplatesFromDir } from '../../src/scanner/templates/yaml-loader.js';

const SAMPLE_TEMPLATE = `
id: exposed-git-config
info:
  name: Exposed Git Configuration
  severity: medium
  description: Git configuration file is publicly accessible.
  tags: exposure,config
  reference:
    - "https://owasp.org/www-project-web-security-testing-guide/"
  cwe: CWE-200

http:
  - method: GET
    path:
      - "/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "[core]"
          - "[remote"
`;

describe('parseNucleiTemplate', () => {
  it('parses a simple Nuclei-format template', () => {
    const result = parseNucleiTemplate(SAMPLE_TEMPLATE);

    expect(result).not.toBeNull();
    expect(result!.id).toBe('exposed-git-config');
    expect(result!.info.name).toBe('Exposed Git Configuration');
    expect(result!.info.severity).toBe('medium');
    expect(result!.info.description).toBe('Git configuration file is publicly accessible.');
    expect(result!.info.tags).toEqual(['exposure', 'config']);
    expect(result!.requests).toHaveLength(1);
    expect(result!.requests[0].method).toBe('GET');
    expect(result!.requests[0].path).toBe('/.git/config');
    expect(result!.requests[0].matchers.length).toBeGreaterThanOrEqual(1);
  });

  it('returns null for empty input', () => {
    expect(parseNucleiTemplate('')).toBeNull();
  });

  it('returns null when missing required fields (id)', () => {
    const noId = `
info:
  name: Test
  severity: high
http:
  - method: GET
    path:
      - "/test"
`;
    expect(parseNucleiTemplate(noId)).toBeNull();
  });

  it('returns null when missing required fields (name)', () => {
    const noName = `
id: test-template
info:
  severity: high
http:
  - method: GET
    path:
      - "/test"
`;
    expect(parseNucleiTemplate(noName)).toBeNull();
  });

  it('returns null when missing required fields (severity)', () => {
    const noSev = `
id: test-template
info:
  name: Test Template
http:
  - method: GET
    path:
      - "/test"
`;
    expect(parseNucleiTemplate(noSev)).toBeNull();
  });

  it('returns null when missing path', () => {
    const noPath = `
id: test-no-path
info:
  name: Test No Path
  severity: low
`;
    expect(parseNucleiTemplate(noPath)).toBeNull();
  });

  it('defaults method to GET when not specified', () => {
    const template = `
id: default-method
info:
  name: Default Method Test
  severity: info
  tags: test
path: /probe
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.requests[0].method).toBe('GET');
  });

  it('parses POST method and body', () => {
    const template = `
id: post-test
info:
  name: POST Test
  severity: high
  tags: test
method: POST
path: /api/test
body: {"key":"value"}
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.requests[0].method).toBe('POST');
    expect(result!.requests[0].body).toBe('{"key":"value"}');
  });

  it('parses CWE and reference fields', () => {
    const result = parseNucleiTemplate(SAMPLE_TEMPLATE);
    expect(result).not.toBeNull();
    expect(result!.info.cwe).toBe('CWE-200');
  });
});

describe('extractField', () => {
  it('extracts a simple field value', () => {
    expect(extractField('id: my-template', 'id')).toBe('my-template');
  });

  it('strips surrounding quotes', () => {
    expect(extractField('name: "Quoted Value"', 'name')).toBe('Quoted Value');
    expect(extractField("name: 'Single Quoted'", 'name')).toBe('Single Quoted');
  });

  it('returns undefined for missing field', () => {
    expect(extractField('id: test', 'missing')).toBeUndefined();
  });

  it('handles indented fields', () => {
    expect(extractField('    severity: high', 'severity')).toBe('high');
  });
});

describe('extractMatchers', () => {
  it('finds status matchers', () => {
    const yaml = `
    matchers:
      - type: status
        status: [200, 301]
`;
    const matchers = extractMatchers(yaml);
    expect(matchers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'status', status: [200, 301] }),
      ]),
    );
  });

  it('finds word matchers', () => {
    const yaml = `
    matchers:
      - type: word
        words:
          - "admin"
          - "dashboard"
`;
    const matchers = extractMatchers(yaml);
    expect(matchers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'body', words: ['admin', 'dashboard'] }),
      ]),
    );
  });

  it('finds both status and word matchers together', () => {
    const yaml = `
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "[core]"
`;
    const matchers = extractMatchers(yaml);
    const statusMatcher = matchers.find(m => m.type === 'status');
    const wordMatcher = matchers.find(m => m.type === 'body');
    expect(statusMatcher).toBeDefined();
    expect(statusMatcher!.status).toEqual([200]);
    expect(wordMatcher).toBeDefined();
    expect(wordMatcher!.words).toEqual(['[core]']);
  });

  it('finds regex matchers', () => {
    const yaml = `
    matchers:
      - type: regex
        regex:
          - "error[0-9]+"
`;
    const matchers = extractMatchers(yaml);
    expect(matchers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'regex', regex: 'error[0-9]+' }),
      ]),
    );
  });

  it('defaults to status 200 when no matchers found', () => {
    const yaml = 'id: empty\ninfo:\n  name: test';
    const matchers = extractMatchers(yaml);
    expect(matchers).toEqual([{ type: 'status', status: [200] }]);
  });
});

describe('loadTemplatesFromDir', () => {
  it('returns empty array for non-existent directory', () => {
    const result = loadTemplatesFromDir('/non/existent/path/that/does/not/exist');
    expect(result).toEqual([]);
  });

  it('returns empty array for directory with no YAML files', () => {
    // Use a directory that exists but has no yaml files (e.g., src/utils)
    const result = loadTemplatesFromDir(new URL('../../src/utils', import.meta.url).pathname);
    expect(result).toEqual([]);
  });
});

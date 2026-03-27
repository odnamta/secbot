import { describe, it, expect } from 'vitest';
import { parseNucleiTemplate, extractMatchers, extractField } from '../../src/scanner/templates/yaml-loader.js';
import { loadTemplatesFromDir, loadTemplatesFromDirRecursive, loadTemplatesFiltered } from '../../src/scanner/templates/yaml-loader.js';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

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

  // ─── Nuclei-specific format tests ────────────────────────────

  it('strips {{BaseURL}} from path', () => {
    const template = `
id: baseurl-test
info:
  name: BaseURL Test
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.requests[0].path).toBe('/admin');
  });

  it('parses matchers-condition: or', () => {
    const template = `
id: or-condition-test
info:
  name: OR Condition
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "swagger"
        condition: or
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.requests[0].matchCondition).toBe('or');
  });

  it('parses status codes in YAML list format', () => {
    const template = `
id: status-list-test
info:
  name: Status List
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
          - 301
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    const statusMatcher = result!.requests[0].matchers.find(m => m.type === 'status');
    expect(statusMatcher).toBeDefined();
    expect(statusMatcher!.status).toEqual([200, 301]);
  });

  it('parses single-quoted words', () => {
    const template = `
id: single-quote-test
info:
  name: Single Quote Test
  severity: medium
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        part: body
        words:
          - 'DB_NAME'
          - 'DB_PASSWORD'
        condition: and
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    const wordMatcher = result!.requests[0].matchers.find(m => m.type === 'body');
    expect(wordMatcher).toBeDefined();
    expect(wordMatcher!.words).toEqual(['DB_NAME', 'DB_PASSWORD']);
  });

  it('parses negative matchers', () => {
    const template = `
id: negative-test
info:
  name: Negative Matcher Test
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "/install/index.php"
        negative: true
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    const headerMatcher = result!.requests[0].matchers.find(m => m.type === 'header');
    expect(headerMatcher).toBeDefined();
    expect(headerMatcher!.negative).toBe(true);
  });

  it('parses raw request blocks', () => {
    const template = `
id: raw-request-test
info:
  name: Raw Request Test
  severity: high
  tags: rce,test
http:
  - raw:
      - |
        POST /admin/exec HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        cmd=id

    matchers:
      - type: regex
        regex:
          - "uid=[0-9]+"
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.requests[0].method).toBe('POST');
    expect(result!.requests[0].path).toBe('/admin/exec');
    expect(result!.requests[0].body).toBe('cmd=id');
  });

  it('parses multiline description', () => {
    const template = `
id: multiline-desc
info:
  name: Multiline Desc Test
  severity: medium
  description: |
    This is a multiline
    description field.
  tags: test
http:
  - method: GET
    path:
      - "/test"
    matchers:
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.info.description).toContain('multiline');
  });

  it('parses cwe-id from classification block', () => {
    const template = `
id: cwe-classification
info:
  name: CWE Classification Test
  severity: high
  tags: test
  classification:
    cve-id: CVE-2024-1234
    cwe-id: CWE-89
http:
  - method: GET
    path:
      - "/test"
    matchers:
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.info.cwe).toBe('CWE-89');
  });

  it('infers tech match from tags', () => {
    const template = `
id: wp-tech-test
info:
  name: WordPress Tech Test
  severity: medium
  tags: cve,wordpress,wp-plugin,sqli
http:
  - method: GET
    path:
      - "/wp-admin"
    matchers:
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.match?.tech).toBeDefined();
    expect(result!.match!.tech).toContain('wordpress');
  });

  it('skips code: block templates', () => {
    const template = `
id: code-template
info:
  name: Code Template
  severity: critical
  tags: test
code:
  - engine:
      - rb
    source: |
      puts "hello"
    matchers:
      - type: dsl
        dsl:
          - "true"
`;
    expect(parseNucleiTemplate(template)).toBeNull();
  });

  it('handles path with payload variable expansion', () => {
    const template = `
id: payload-path-test
info:
  name: Payload Path Test
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}{{paths}}"

    payloads:
      paths:
        - "/v2/api-docs"
        - "/swagger.json"

    matchers:
      - type: word
        words:
          - "swagger"
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    expect(result!.requests[0].path).toBe('/v2/api-docs');
  });

  it('parses part: header word matcher', () => {
    const template = `
id: header-word-test
info:
  name: Header Word Test
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "Server: Burp Collaborator"
      - type: status
        status:
          - 200
`;
    const result = parseNucleiTemplate(template);
    expect(result).not.toBeNull();
    const headerMatcher = result!.requests[0].matchers.find(m => m.type === 'header');
    expect(headerMatcher).toBeDefined();
    expect(headerMatcher!.words).toContain('Server: Burp Collaborator');
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

  it('returns undefined for pipe block indicators', () => {
    expect(extractField('  description: |', 'description')).toBeUndefined();
  });
});

describe('extractMatchers', () => {
  it('finds status matchers (inline array)', () => {
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

  it('finds status matchers (YAML list)', () => {
    const yaml = `
    matchers:
      - type: status
        status:
          - 200
          - 403
`;
    const matchers = extractMatchers(yaml);
    const statusMatcher = matchers.find(m => m.type === 'status');
    expect(statusMatcher).toBeDefined();
    expect(statusMatcher!.status).toEqual([200, 403]);
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

  it('handles negative matchers', () => {
    const yaml = `
    matchers:
      - type: word
        part: header
        words:
          - "/install/index.php"
        negative: true
`;
    const matchers = extractMatchers(yaml);
    const negativeMatcher = matchers.find(m => m.negative === true);
    expect(negativeMatcher).toBeDefined();
  });

  it('handles single-quoted words', () => {
    const yaml = `
    matchers:
      - type: word
        words:
          - 'Search Customers'
          - 'Administrate'
`;
    const matchers = extractMatchers(yaml);
    const wordMatcher = matchers.find(m => m.type === 'body');
    expect(wordMatcher).toBeDefined();
    expect(wordMatcher!.words).toContain('Search Customers');
    expect(wordMatcher!.words).toContain('Administrate');
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

// ─── Real Nuclei Template Tests ─────────────────────────────────

const NUCLEI_DIR = join(process.cwd(), 'config', 'templates', 'nuclei');
const hasNucleiTemplates = existsSync(NUCLEI_DIR);

describe.skipIf(!hasNucleiTemplates)('parses real Nuclei template files', () => {
  const knownTemplates = [
    { path: 'exposures/apis/swagger-api.yaml', id: 'swagger-api', method: 'GET' },
    { path: 'cves/2013/CVE-2013-7240.yaml', id: 'CVE-2013-7240', method: 'GET' },
    { path: 'misconfiguration/administrate-dashboard.yaml', id: 'administrate-dashboard', method: 'GET' },
    { path: 'technologies/springboot-actuator.yaml', id: 'springboot-actuator', method: 'GET' },
    { path: 'technologies/wordpress-detect.yaml', id: 'wordpress-detect', method: 'GET' },
    { path: 'cves/2000/CVE-2000-0114.yaml', id: 'CVE-2000-0114', method: 'POST' },
    { path: 'cves/2009/CVE-2009-1151.yaml', id: 'CVE-2009-1151', method: 'POST' },
    { path: 'technologies/burp-collaborator-detect.yaml', id: 'burp-collaborator-detect', method: 'GET' },
    { path: 'misconfiguration/cakephp-debugkit-exposure.yaml', id: 'cakephp-debugkit-exposure', method: 'GET' },
    { path: 'technologies/avideo-detect.yaml', id: 'avideo-detect', method: 'GET' },
  ];

  for (const { path: relPath, id, method } of knownTemplates) {
    it(`parses ${id}`, () => {
      const fullPath = join(NUCLEI_DIR, relPath);
      if (!existsSync(fullPath)) return; // skip if template not available
      const content = readFileSync(fullPath, 'utf-8');
      const result = parseNucleiTemplate(content);

      expect(result).not.toBeNull();
      expect(result!.id).toBe(id);
      expect(result!.requests[0].method).toBe(method);
      expect(result!.info.name).toBeTruthy();
      expect(result!.info.severity).toBeTruthy();
      expect(result!.info.tags.length).toBeGreaterThan(0);
      expect(result!.requests[0].matchers.length).toBeGreaterThan(0);
      expect(result!.requests[0].path).toBeTruthy();
    });
  }

  it('has at least 99% parse rate across all templates', () => {
    let total = 0;
    let success = 0;

    function walk(dir: string): void {
      for (const entry of readdirSync(dir)) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (entry.endsWith('.yaml')) {
          total++;
          const content = readFileSync(fullPath, 'utf-8');
          if (parseNucleiTemplate(content)) success++;
        }
      }
    }

    walk(NUCLEI_DIR);

    const parseRate = success / total;
    expect(parseRate).toBeGreaterThanOrEqual(0.99);
    expect(total).toBeGreaterThanOrEqual(7000); // sanity check: templates exist
  });
});

describe.skipIf(!hasNucleiTemplates)('loadTemplatesFiltered', () => {
  it('loads only universal directories when no tech detected', () => {
    const templates = loadTemplatesFiltered(NUCLEI_DIR);
    // Should have exposures + misconfiguration + technologies but NOT cves/vulnerabilities
    expect(templates.length).toBeGreaterThan(2000);
    expect(templates.length).toBeLessThan(4000);
  });

  it('loads more templates when tech is detected', () => {
    const noTech = loadTemplatesFiltered(NUCLEI_DIR);
    const withTech = loadTemplatesFiltered(NUCLEI_DIR, ['wordpress', 'php']);
    expect(withTech.length).toBeGreaterThan(noTech.length);
  });

  it('filters CVE/vuln templates by tech tags', () => {
    const wp = loadTemplatesFiltered(NUCLEI_DIR, ['wordpress']);
    // Should include wordpress-tagged CVEs
    const wpCves = wp.filter(t => t.info.tags.some(tag =>
      ['wordpress', 'wp', 'wp-plugin'].includes(tag.toLowerCase()),
    ));
    expect(wpCves.length).toBeGreaterThan(100); // WordPress has many CVEs
  });
});

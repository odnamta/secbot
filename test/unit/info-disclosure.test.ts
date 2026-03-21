import { describe, it, expect } from 'vitest';
import {
  infoDisclosureCheck,
  parseSensitiveRobotsPaths,
  matchesEnvFile,
  matchesGitConfig,
  matchesGitHead,
  isValidSourceMap,
  matchesSqlDump,
  matchesDirectoryListing,
  matchesApiDocumentation,
  matchesSwaggerSpec,
  matchesGraphQLIntrospection,
  matchesDSStore,
  matchesDebugEndpoint,
  matchesActuatorEndpoint,
  scanJsForSecrets,
  extractSourceMappingURLs,
  analyzeSourceMapContent,
} from '../../src/scanner/active/info-disclosure.js';

describe('Info disclosure check: metadata', () => {
  it('has correct name and category', () => {
    expect(infoDisclosureCheck.name).toBe('info-disclosure');
    expect(infoDisclosureCheck.category).toBe('info-disclosure');
  });
});

describe('matchesGitConfig', () => {
  it('detects [core] section', () => {
    expect(matchesGitConfig('[core]\n\trepositoryformatversion = 0')).toBe(true);
  });

  it('detects [remote section', () => {
    expect(matchesGitConfig('[remote "origin"]\n\turl = git@github.com:user/repo.git')).toBe(true);
  });

  it('rejects unrelated content', () => {
    expect(matchesGitConfig('<html><body>Not Found</body></html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesGitConfig('')).toBe(false);
  });
});

describe('matchesGitHead', () => {
  it('detects standard HEAD ref', () => {
    expect(matchesGitHead('ref: refs/heads/main')).toBe(true);
  });

  it('detects HEAD ref with whitespace', () => {
    expect(matchesGitHead('  ref: refs/heads/develop  ')).toBe(true);
  });

  it('rejects non-ref content', () => {
    expect(matchesGitHead('404 Not Found')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesGitHead('')).toBe(false);
  });

  it('rejects partial match not at start', () => {
    expect(matchesGitHead('some text ref: refs/heads/main')).toBe(false);
  });
});

describe('matchesEnvFile', () => {
  it('detects env file with 2+ key=value lines', () => {
    const body = 'DB_HOST=localhost\nDB_PORT=5432\nDB_NAME=mydb';
    expect(matchesEnvFile(body)).toBe(true);
  });

  it('rejects single key=value line', () => {
    const body = 'DB_HOST=localhost\nsome random text';
    expect(matchesEnvFile(body)).toBe(false);
  });

  it('rejects HTML content', () => {
    const body = '<html><body>Not Found</body></html>';
    expect(matchesEnvFile(body)).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesEnvFile('')).toBe(false);
  });

  it('handles comments and blank lines', () => {
    const body = '# Database config\nDB_HOST=localhost\n\nDB_PORT=5432\n# End';
    expect(matchesEnvFile(body)).toBe(true);
  });

  it('matches keys with underscores and numbers', () => {
    const body = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG';
    expect(matchesEnvFile(body)).toBe(true);
  });
});

describe('isValidSourceMap', () => {
  it('detects valid source map JSON', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/index.ts', 'src/utils.ts'],
      mappings: 'AAAA',
    });
    expect(isValidSourceMap(body)).toBe(true);
  });

  it('rejects JSON without sources key', () => {
    const body = JSON.stringify({ version: 3, mappings: 'AAAA' });
    expect(isValidSourceMap(body)).toBe(false);
  });

  it('rejects non-JSON content', () => {
    expect(isValidSourceMap('<html>Not Found</html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isValidSourceMap('')).toBe(false);
  });

  it('rejects JSON array', () => {
    expect(isValidSourceMap('[1, 2, 3]')).toBe(false);
  });

  it('rejects JSON null', () => {
    expect(isValidSourceMap('null')).toBe(false);
  });
});

describe('matchesSqlDump', () => {
  it('detects SQL comment header', () => {
    expect(matchesSqlDump('-- MySQL dump 10.13\nCREATE TABLE users')).toBe(true);
  });

  it('detects CREATE statement', () => {
    expect(matchesSqlDump('CREATE TABLE users (id INT);')).toBe(true);
  });

  it('detects INSERT statement', () => {
    expect(matchesSqlDump("INSERT INTO users VALUES (1, 'admin');")).toBe(true);
  });

  it('detects DROP statement', () => {
    expect(matchesSqlDump('DROP TABLE IF EXISTS users;')).toBe(true);
  });

  it('rejects HTML content', () => {
    expect(matchesSqlDump('<html>Not Found</html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesSqlDump('')).toBe(false);
  });
});

describe('parseSensitiveRobotsPaths', () => {
  it('finds admin paths', () => {
    const body = 'User-agent: *\nDisallow: /admin\nDisallow: /public';
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual(['/admin']);
  });

  it('finds multiple sensitive paths', () => {
    const body = [
      'User-agent: *',
      'Disallow: /admin/panel',
      'Disallow: /api/v1',
      'Disallow: /internal/tools',
      'Disallow: /dashboard',
      'Disallow: /images',
    ].join('\n');
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual(['/admin/panel', '/api/v1', '/internal/tools', '/dashboard']);
  });

  it('detects all sensitive keywords', () => {
    const keywords = ['admin', 'api', 'internal', 'dashboard', 'secret', 'private', 'debug', 'staging'];
    for (const keyword of keywords) {
      const body = `Disallow: /${keyword}/path`;
      const result = parseSensitiveRobotsPaths(body);
      expect(result.length).toBe(1);
    }
  });

  it('is case insensitive for keywords', () => {
    const body = 'Disallow: /Admin/Panel\nDisallow: /API/v2';
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual(['/Admin/Panel', '/API/v2']);
  });

  it('ignores Allow directives', () => {
    const body = 'Allow: /admin\nDisallow: /secret';
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual(['/secret']);
  });

  it('returns empty array for no sensitive paths', () => {
    const body = 'User-agent: *\nDisallow: /images\nDisallow: /css\nDisallow: /js';
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual([]);
  });

  it('returns empty array for empty input', () => {
    expect(parseSensitiveRobotsPaths('')).toEqual([]);
  });

  it('handles Disallow with no path', () => {
    const body = 'Disallow:\nDisallow: /admin';
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual(['/admin']);
  });

  it('handles case-insensitive Disallow directive', () => {
    const body = 'disallow: /admin\nDISALLOW: /api';
    const result = parseSensitiveRobotsPaths(body);
    expect(result).toEqual(['/admin', '/api']);
  });
});

describe('matchesDirectoryListing', () => {
  it('detects "Index of" pattern', () => {
    expect(matchesDirectoryListing('<html><body><h1>Index of /ftp</h1></body></html>')).toBe(true);
  });

  it('detects "Parent Directory" link', () => {
    expect(matchesDirectoryListing('<a href="../">Parent Directory</a><a href="file1.txt">file1.txt</a>')).toBe(true);
  });

  it('detects multiple file links with table/pre', () => {
    const body = '<pre><a href="file1.txt">file1.txt</a>\n<a href="file2.zip">file2.zip</a>\n<a href="backup.sql">backup.sql</a></pre>';
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects Juice Shop FTP listing', () => {
    const body = '<html><body><h1>Index of /ftp</h1><table><a href="acquisitions.md">acquisitions.md</a><a href="legal.md">legal.md</a><a href="package.json.bak">package.json.bak</a></table></body></html>';
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects Nginx autoindex listing', () => {
    const body = '<html><head><title>Directory listing for /ftp/</title></head><body><ul><li><a href="file1.txt">file1.txt</a></li></ul></body></html>';
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects IIS directory browsing', () => {
    const body = '<html><head><title>/ftp - Directory Listing</title></head><body><table></table></body></html>';
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects file extension links (download listing)', () => {
    const body = '<div><a href="backup.sql">backup.sql</a> <a href="dump.zip">dump.zip</a> <a href="data.csv">data.csv</a></div>';
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects links with file size indicators', () => {
    const body = '<a href="f1.txt">f1.txt</a> 12 KB\n<a href="f2.txt">f2.txt</a> 3.5 MB\n<a href="f3.txt">f3.txt</a> 100 bytes';
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects JSON array directory listing with name field', () => {
    const body = JSON.stringify([
      { name: 'file1.txt', size: 1024 },
      { name: 'file2.txt', size: 2048 },
      { name: 'dir/', size: 0 },
    ]);
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('detects JSON array of filenames', () => {
    const body = JSON.stringify(['file1.txt', 'file2.txt', 'file3.txt']);
    expect(matchesDirectoryListing(body)).toBe(true);
  });

  it('rejects normal HTML page', () => {
    expect(matchesDirectoryListing('<html><body><h1>Welcome</h1><p>Hello world</p></body></html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesDirectoryListing('')).toBe(false);
  });

  it('rejects page with only 2 links and no listing container', () => {
    expect(matchesDirectoryListing('<a href="a">a</a><a href="b">b</a>')).toBe(false);
  });

  it('rejects JSON object (not array)', () => {
    expect(matchesDirectoryListing('{"status":"ok","data":[]}')).toBe(false);
  });

  it('rejects short JSON array', () => {
    expect(matchesDirectoryListing('["a","b"]')).toBe(false);
  });
});

describe('matchesApiDocumentation', () => {
  it('detects JSON with "endpoints" key', () => {
    const body = JSON.stringify({ endpoints: ['/api/users', '/api/posts'] });
    expect(matchesApiDocumentation(body)).toBe(true);
  });

  it('detects JSON with "routes" key', () => {
    const body = JSON.stringify({ routes: { get: ['/users'], post: ['/users'] } });
    expect(matchesApiDocumentation(body)).toBe(true);
  });

  it('detects JSON with "swagger" key', () => {
    const body = JSON.stringify({ swagger: '2.0', info: { title: 'API' } });
    expect(matchesApiDocumentation(body)).toBe(true);
  });

  it('detects JSON with "paths" key', () => {
    const body = JSON.stringify({ paths: { '/users': {} } });
    expect(matchesApiDocumentation(body)).toBe(true);
  });

  it('detects HTML API documentation page', () => {
    const body = '<html><body><h1>API Documentation</h1><p>Available endpoints:</p></body></html>';
    expect(matchesApiDocumentation(body)).toBe(true);
  });

  it('rejects generic HTML page', () => {
    expect(matchesApiDocumentation('<html><body><h1>Welcome</h1></body></html>')).toBe(false);
  });

  it('rejects empty JSON object', () => {
    expect(matchesApiDocumentation('{}')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesApiDocumentation('')).toBe(false);
  });
});

describe('matchesSwaggerSpec', () => {
  it('detects OpenAPI 3.x spec', () => {
    const body = JSON.stringify({ openapi: '3.0.0', info: { title: 'API' }, paths: {} });
    expect(matchesSwaggerSpec(body)).toBe(true);
  });

  it('detects Swagger 2.0 spec', () => {
    const body = JSON.stringify({ swagger: '2.0', info: { title: 'API' }, paths: {} });
    expect(matchesSwaggerSpec(body)).toBe(true);
  });

  it('rejects JSON without swagger/openapi key', () => {
    const body = JSON.stringify({ version: '1.0', endpoints: [] });
    expect(matchesSwaggerSpec(body)).toBe(false);
  });

  it('rejects non-JSON content', () => {
    expect(matchesSwaggerSpec('<html>Not Found</html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesSwaggerSpec('')).toBe(false);
  });
});

describe('matchesGraphQLIntrospection', () => {
  it('detects standard introspection response', () => {
    const body = JSON.stringify({
      data: {
        __schema: {
          types: [{ name: 'Query' }, { name: 'Mutation' }],
        },
      },
    });
    expect(matchesGraphQLIntrospection(body)).toBe(true);
  });

  it('rejects GraphQL error response', () => {
    const body = JSON.stringify({ errors: [{ message: 'Introspection is disabled' }] });
    expect(matchesGraphQLIntrospection(body)).toBe(false);
  });

  it('rejects response without __schema', () => {
    const body = JSON.stringify({ data: { users: [] } });
    expect(matchesGraphQLIntrospection(body)).toBe(false);
  });

  it('rejects non-JSON content', () => {
    expect(matchesGraphQLIntrospection('<html>Not Found</html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesGraphQLIntrospection('')).toBe(false);
  });
});

describe('matchesDSStore', () => {
  it('detects DS_Store magic bytes', () => {
    // The Bud1 marker appears in .DS_Store binary files
    expect(matchesDSStore('\x00\x00\x00\x01Bud1\x00\x00')).toBe(true);
  });

  it('rejects HTML content', () => {
    expect(matchesDSStore('<html><body>Not Found</body></html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesDSStore('')).toBe(false);
  });

  it('rejects random binary-looking content', () => {
    expect(matchesDSStore('\x00\x00\x00\x01ABCD\x00\x00')).toBe(false);
  });
});

describe('matchesDebugEndpoint', () => {
  it('detects Go expvar output with memstats', () => {
    const body = JSON.stringify({ memstats: { Alloc: 1234 }, cmdline: ['/app'] });
    expect(matchesDebugEndpoint(body)).toBe(true);
  });

  it('detects debug info with goroutines', () => {
    const body = JSON.stringify({ goroutines: 42, version: 'go1.21' });
    expect(matchesDebugEndpoint(body)).toBe(true);
  });

  it('detects HTML debug page with stack trace', () => {
    expect(matchesDebugEndpoint('<html><body><h1>Debug Info</h1><pre>Stack Trace:\n at main()</pre></body></html>')).toBe(true);
  });

  it('detects page with environment variables', () => {
    expect(matchesDebugEndpoint('<div>environment variables: DB_HOST=localhost</div>')).toBe(true);
  });

  it('rejects generic HTML page', () => {
    expect(matchesDebugEndpoint('<html><body><h1>Welcome</h1></body></html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesDebugEndpoint('')).toBe(false);
  });

  it('rejects generic JSON', () => {
    expect(matchesDebugEndpoint('{"name":"app","version":"1.0"}')).toBe(false);
  });
});

describe('matchesActuatorEndpoint', () => {
  it('detects actuator health response', () => {
    const body = JSON.stringify({ status: 'UP' });
    expect(matchesActuatorEndpoint(body)).toBe(true);
  });

  it('detects actuator root with _links', () => {
    const body = JSON.stringify({
      _links: {
        health: { href: '/actuator/health' },
        info: { href: '/actuator/info' },
      },
    });
    expect(matchesActuatorEndpoint(body)).toBe(true);
  });

  it('detects actuator health with details', () => {
    const body = JSON.stringify({
      status: 'UP',
      components: { db: { status: 'UP' }, diskSpace: { status: 'UP' } },
    });
    expect(matchesActuatorEndpoint(body)).toBe(true);
  });

  it('rejects non-JSON content', () => {
    expect(matchesActuatorEndpoint('<html>Not Found</html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesActuatorEndpoint('')).toBe(false);
  });

  it('rejects JSON without status or _links', () => {
    expect(matchesActuatorEndpoint('{"name":"app"}')).toBe(false);
  });
});

describe('scanJsForSecrets', () => {
  const URL = 'https://example.com/app.js';

  it('finds AWS access key', () => {
    const content = 'var key = "AKIAIOSFODNN7EXAMPLE";';
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('AWS Access Key');
    expect(results[0].severity).toBe('high');
    expect(results[0].match).toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('finds Google API key', () => {
    // AIza prefix + exactly 35 alphanumeric chars = 39-char total key
    const key = 'AIza0123456789ABCDEFabcdefghijklmnopqrs';
    const content = `const apiKey = "${key}";`;
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('Google API Key');
    expect(results[0].severity).toBe('medium');
    expect(results[0].match).toBe(key);
  });

  it('finds Stripe secret key', () => {
    // Build key dynamically to avoid GitHub push protection false positive
    const prefix = 'sk' + '_' + 'live' + '_';
    const content = `stripe.init("${prefix}abcdefghijklmnopqrstuvwx");`;
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('Stripe Secret Key');
    expect(results[0].severity).toBe('high');
    expect(results[0].match).toContain(prefix);
  });

  it('finds GitHub token', () => {
    const content = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";';
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('GitHub Token');
    expect(results[0].severity).toBe('high');
    expect(results[0].match).toContain('ghp_');
  });

  it('finds private key PEM header', () => {
    const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...';
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('Private Key (PEM)');
    expect(results[0].severity).toBe('high');
    expect(results[0].match).toContain('-----BEGIN RSA PRIVATE KEY-----');
  });

  it('finds internal IP address in URL', () => {
    const content = 'fetch("http://192.168.1.100:8080/api/data")';
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('Internal IP Address');
    expect(results[0].severity).toBe('medium');
    expect(results[0].match).toContain('192.168.1.100');
  });

  it('finds hardcoded Bearer token', () => {
    const content = 'headers: { Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc" }';
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].name).toBe('Hardcoded Bearer Token');
    expect(results[0].severity).toBe('high');
    expect(results[0].match).toContain('Bearer ');
  });

  it('returns empty array for clean JS content', () => {
    const content = [
      'function add(a, b) { return a + b; }',
      'const config = { debug: false, version: "1.0.0" };',
      'export default function App() { return null; }',
    ].join('\n');
    expect(scanJsForSecrets(content, URL)).toEqual([]);
  });

  it('deduplicates the same secret appearing multiple times', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const content = `var a = "${secret}"; var b = "${secret}";`;
    const results = scanJsForSecrets(content, URL);
    expect(results.length).toBe(1);
    expect(results[0].match).toContain(secret);
  });

  it('does not match Stripe publishable key (pk_live_)', () => {
    // pk_live_ keys are intentionally public and should NOT trigger a finding
    const content = 'stripe.init("pk_live_abcdefghijklmnopqrstuvwx");';
    const results = scanJsForSecrets(content, URL);
    expect(results).toEqual([]);
  });
});

describe('extractSourceMappingURLs', () => {
  const BASE = 'https://example.com/assets/app.js';

  it('extracts relative sourceMappingURL', () => {
    const js = 'var x=1;\n//# sourceMappingURL=app.js.map';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual(['https://example.com/assets/app.js.map']);
  });

  it('extracts absolute sourceMappingURL', () => {
    const js = 'var x=1;\n//# sourceMappingURL=https://cdn.example.com/maps/app.js.map';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual(['https://cdn.example.com/maps/app.js.map']);
  });

  it('extracts legacy //@ sourceMappingURL', () => {
    const js = 'var x=1;\n//@ sourceMappingURL=legacy.map';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual(['https://example.com/assets/legacy.map']);
  });

  it('skips data: URI source maps', () => {
    const js = 'var x=1;\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual([]);
  });

  it('extracts multiple sourceMappingURL references', () => {
    // Unusual but possible if multiple scripts are concatenated
    const js = '//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual([
      'https://example.com/assets/a.map',
      'https://example.com/assets/b.map',
    ]);
  });

  it('returns empty array for JS without sourceMappingURL', () => {
    const js = 'function add(a,b){return a+b}';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual([]);
  });

  it('handles sourceMappingURL with path traversal', () => {
    const js = '//# sourceMappingURL=../maps/app.js.map';
    const urls = extractSourceMappingURLs(js, BASE);
    expect(urls).toEqual(['https://example.com/maps/app.js.map']);
  });
});

describe('analyzeSourceMapContent', () => {
  it('returns valid=true for source map with sources', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/index.ts', 'src/utils.ts'],
      mappings: 'AAAA',
    });
    const result = analyzeSourceMapContent(body);
    expect(result.valid).toBe(true);
    expect(result.sourceCount).toBe(2);
    expect(result.hasSourcesContent).toBe(false);
    expect(result.secretsFound).toEqual([]);
  });

  it('detects sourcesContent presence', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/app.ts'],
      sourcesContent: ['export function main() { return 42; }'],
      mappings: 'AAAA',
    });
    const result = analyzeSourceMapContent(body);
    expect(result.valid).toBe(true);
    expect(result.sourceCount).toBe(1);
    expect(result.hasSourcesContent).toBe(true);
    expect(result.secretsFound).toEqual([]);
  });

  it('detects secrets in sourcesContent', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/config.ts'],
      sourcesContent: ['const key = "AKIAIOSFODNN7EXAMPLE1";'],
      mappings: 'AAAA',
    });
    const result = analyzeSourceMapContent(body);
    expect(result.valid).toBe(true);
    expect(result.hasSourcesContent).toBe(true);
    expect(result.secretsFound).toContain('AWS Access Key');
  });

  it('detects multiple secret types in sourcesContent', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/config.ts'],
      sourcesContent: [
        'const aws = "AKIAIOSFODNN7EXAMPLE1";\nconst gh = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";',
      ],
      mappings: 'AAAA',
    });
    const result = analyzeSourceMapContent(body);
    expect(result.secretsFound).toContain('AWS Access Key');
    expect(result.secretsFound).toContain('GitHub Token');
  });

  it('ignores empty sourcesContent entries', () => {
    const body = JSON.stringify({
      version: 3,
      sources: ['src/a.ts', 'src/b.ts'],
      sourcesContent: [null, ''],
      mappings: 'AAAA',
    });
    const result = analyzeSourceMapContent(body);
    expect(result.valid).toBe(true);
    expect(result.hasSourcesContent).toBe(false);
  });

  it('returns valid=false for non-JSON content', () => {
    const result = analyzeSourceMapContent('<html>Not Found</html>');
    expect(result.valid).toBe(false);
  });

  it('returns valid=false for JSON without sources key', () => {
    const body = JSON.stringify({ version: 3, mappings: 'AAAA' });
    const result = analyzeSourceMapContent(body);
    expect(result.valid).toBe(false);
  });

  it('returns valid=false for empty string', () => {
    const result = analyzeSourceMapContent('');
    expect(result.valid).toBe(false);
  });
});

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

  it('rejects normal HTML page', () => {
    expect(matchesDirectoryListing('<html><body><h1>Welcome</h1><p>Hello world</p></body></html>')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(matchesDirectoryListing('')).toBe(false);
  });

  it('rejects page with only 2 links and no listing container', () => {
    expect(matchesDirectoryListing('<a href="a">a</a><a href="b">b</a>')).toBe(false);
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

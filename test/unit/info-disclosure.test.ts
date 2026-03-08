import { describe, it, expect } from 'vitest';
import {
  infoDisclosureCheck,
  parseSensitiveRobotsPaths,
  matchesEnvFile,
  matchesGitConfig,
  matchesGitHead,
  isValidSourceMap,
  matchesSqlDump,
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

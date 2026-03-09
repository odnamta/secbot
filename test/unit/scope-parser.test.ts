import { describe, it, expect } from 'vitest';
import { parseScopeFile, scopeToScanConfig } from '../../src/utils/scope-parser.js';

describe('parseScopeFile', () => {
  it('parses simple domain patterns', () => {
    const content = `example.com
api.example.com
*.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['example.com', 'api.example.com', '*.example.com']);
    expect(result.outOfScope).toEqual([]);
  });

  it('parses URL patterns with wildcards', () => {
    const content = `https://example.com/*
https://api.example.com/v1/*
https://*.example.com/`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual([
      'https://example.com/*',
      'https://api.example.com/v1/*',
      'https://*.example.com/',
    ]);
  });

  it('detects out-of-scope lines with - prefix', () => {
    const content = `*.example.com
- admin.example.com
- staging.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['*.example.com']);
    expect(result.outOfScope).toEqual(['admin.example.com', 'staging.example.com']);
  });

  it('handles Out of Scope section header', () => {
    const content = `*.example.com
api.example.com

Out of Scope
admin.example.com
staging.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['*.example.com', 'api.example.com']);
    expect(result.outOfScope).toEqual(['admin.example.com', 'staging.example.com']);
  });

  it('handles case-insensitive Out of Scope header', () => {
    const content = `*.example.com

OUT OF SCOPE
admin.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['*.example.com']);
    expect(result.outOfScope).toEqual(['admin.example.com']);
  });

  it('handles out-of-scope with hyphen variant', () => {
    const content = `*.example.com

out-of-scope
admin.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['*.example.com']);
    expect(result.outOfScope).toEqual(['admin.example.com']);
  });

  it('handles In Scope section resetting back from out-of-scope', () => {
    const content = `Out of Scope
admin.example.com

In Scope
api.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['api.example.com']);
    expect(result.outOfScope).toEqual(['admin.example.com']);
  });

  it('skips comment lines starting with #', () => {
    const content = `# This is a comment
example.com
# Another comment
api.example.com`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['example.com', 'api.example.com']);
    expect(result.outOfScope).toEqual([]);
  });

  it('extracts program name from # Program: header', () => {
    const content = `# Program: HackerOne Bug Bounty
*.example.com`;
    const result = parseScopeFile(content);
    expect(result.programName).toBe('HackerOne Bug Bounty');
    expect(result.inScope).toEqual(['*.example.com']);
  });

  it('uses first Program: comment only', () => {
    const content = `# Program: First Program
# Program: Second Program
*.example.com`;
    const result = parseScopeFile(content);
    expect(result.programName).toBe('First Program');
  });

  it('skips empty lines', () => {
    const content = `
example.com

api.example.com

`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['example.com', 'api.example.com']);
  });

  it('handles empty content', () => {
    const result = parseScopeFile('');
    expect(result.inScope).toEqual([]);
    expect(result.outOfScope).toEqual([]);
    expect(result.programName).toBeUndefined();
  });

  it('handles - prefix with no content after', () => {
    const content = `example.com
-`;
    const result = parseScopeFile(content);
    expect(result.inScope).toEqual(['example.com']);
    expect(result.outOfScope).toEqual([]);
  });

  it('handles full HackerOne-style scope file', () => {
    const content = `# Program: Example Corp Bug Bounty
# Last updated: 2026-03-01

# In-scope domains
*.example.com
api.example.com
https://www.example.com/*

Out of Scope
admin.example.com
- staging.example.com
internal.example.com`;
    const result = parseScopeFile(content);
    expect(result.programName).toBe('Example Corp Bug Bounty');
    expect(result.inScope).toEqual(['*.example.com', 'api.example.com', 'https://www.example.com/*']);
    expect(result.outOfScope).toEqual(['admin.example.com', 'staging.example.com', 'internal.example.com']);
  });
});

describe('scopeToScanConfig', () => {
  it('converts domain patterns to include/exclude', () => {
    const scope = parseScopeFile(`*.example.com
- admin.example.com`);
    const config = scopeToScanConfig(scope);
    expect(config.includePatterns).toEqual(['*.example.com']);
    expect(config.excludePatterns).toEqual(['admin.example.com']);
  });

  it('normalizes URL patterns to hostname patterns', () => {
    const scope = parseScopeFile(`https://example.com/*
https://api.example.com/v1/*`);
    const config = scopeToScanConfig(scope);
    expect(config.includePatterns).toEqual(['example.com', 'api.example.com']);
  });

  it('normalizes wildcard URL patterns', () => {
    const scope = parseScopeFile(`https://*.example.com/`);
    const config = scopeToScanConfig(scope);
    expect(config.includePatterns).toEqual(['*.example.com']);
  });

  it('deduplicates patterns', () => {
    const scope = parseScopeFile(`example.com
https://example.com/*
example.com`);
    const config = scopeToScanConfig(scope);
    expect(config.includePatterns).toEqual(['example.com']);
  });

  it('handles mixed domain and URL patterns', () => {
    const scope = parseScopeFile(`*.example.com
https://api.example.com/v1/*

Out of Scope
- staging.example.com
https://admin.example.com/*`);
    const config = scopeToScanConfig(scope);
    expect(config.includePatterns).toEqual(['*.example.com', 'api.example.com']);
    expect(config.excludePatterns).toEqual(['staging.example.com', 'admin.example.com']);
  });

  it('handles empty scope', () => {
    const scope = parseScopeFile('');
    const config = scopeToScanConfig(scope);
    expect(config.includePatterns).toEqual([]);
    expect(config.excludePatterns).toEqual([]);
  });
});

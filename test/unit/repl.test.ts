import { describe, it, expect } from 'vitest';
import { parseCommand, formatHelp, formatFindingsSummary, REPL_COMMANDS } from '../../src/interactive/repl.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    category: 'xss',
    severity: 'high',
    title: 'Reflected XSS',
    description: 'User input reflected in response',
    url: 'https://example.com/search?q=test',
    evidence: '<script>alert(1)</script>',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('REPL', () => {
  describe('parseCommand', () => {
    it('parses a simple command with no args', () => {
      const result = parseCommand('scan');
      expect(result).toEqual({ command: 'scan', args: '' });
    });

    it('parses a command with args', () => {
      const result = parseCommand('check xss');
      expect(result).toEqual({ command: 'check', args: 'xss' });
    });

    it('parses a command with URL args', () => {
      const result = parseCommand('screenshot https://example.com/page');
      expect(result).toEqual({ command: 'screenshot', args: 'https://example.com/page' });
    });

    it('normalizes command to lowercase', () => {
      const result = parseCommand('SCAN');
      expect(result).toEqual({ command: 'scan', args: '' });
    });

    it('trims whitespace', () => {
      const result = parseCommand('  scan  ');
      expect(result).toEqual({ command: 'scan', args: '' });
    });

    it('handles empty input', () => {
      const result = parseCommand('');
      expect(result).toEqual({ command: '', args: '' });
    });

    it('handles whitespace-only input', () => {
      const result = parseCommand('   ');
      expect(result).toEqual({ command: '', args: '' });
    });

    it('preserves args casing', () => {
      const result = parseCommand('check XSS');
      expect(result).toEqual({ command: 'check', args: 'XSS' });
    });

    it('handles export with platform arg', () => {
      const result = parseCommand('export hackerone');
      expect(result).toEqual({ command: 'export', args: 'hackerone' });
    });

    it('handles args with multiple spaces', () => {
      const result = parseCommand('check   xss');
      expect(result).toEqual({ command: 'check', args: 'xss' });
    });
  });

  describe('REPL_COMMANDS', () => {
    it('contains all expected commands', () => {
      const names = REPL_COMMANDS.map((c) => c.name);
      expect(names).toContain('scan');
      expect(names).toContain('crawl');
      expect(names).toContain('check <name>');
      expect(names).toContain('recon');
      expect(names).toContain('findings');
      expect(names).toContain('export [hackerone|bugcrowd]');
      expect(names).toContain('screenshot <url>');
      expect(names).toContain('help');
      expect(names).toContain('quit');
    });

    it('each command has a description', () => {
      for (const cmd of REPL_COMMANDS) {
        expect(cmd.description).toBeTruthy();
        expect(cmd.description.length).toBeGreaterThan(5);
      }
    });
  });

  describe('formatHelp', () => {
    it('includes "Available commands" header', () => {
      const help = formatHelp();
      expect(help).toContain('Available commands');
    });

    it('lists all REPL commands', () => {
      const help = formatHelp();
      for (const cmd of REPL_COMMANDS) {
        expect(help).toContain(cmd.name);
      }
    });

    it('includes descriptions for each command', () => {
      const help = formatHelp();
      for (const cmd of REPL_COMMANDS) {
        expect(help).toContain(cmd.description);
      }
    });
  });

  describe('formatFindingsSummary', () => {
    it('shows message when no findings', () => {
      const output = formatFindingsSummary([]);
      expect(output).toContain('No findings yet');
    });

    it('shows finding count', () => {
      const findings = [
        makeFinding({ severity: 'high' }),
        makeFinding({ severity: 'medium' }),
      ];
      const output = formatFindingsSummary(findings);
      expect(output).toContain('2 unique');
    });

    it('shows severity labels', () => {
      const findings = [
        makeFinding({ severity: 'critical', title: 'Critical Bug' }),
        makeFinding({ severity: 'high', title: 'High Bug' }),
        makeFinding({ severity: 'medium', title: 'Medium Bug' }),
        makeFinding({ severity: 'low', title: 'Low Bug' }),
        makeFinding({ severity: 'info', title: 'Info Item' }),
      ];
      const output = formatFindingsSummary(findings);
      expect(output).toContain('CRITICAL');
      expect(output).toContain('HIGH');
      expect(output).toContain('MEDIUM');
      expect(output).toContain('LOW');
      expect(output).toContain('INFO');
    });

    it('includes finding titles', () => {
      const findings = [makeFinding({ title: 'SQL Injection in Login' })];
      const output = formatFindingsSummary(findings);
      expect(output).toContain('SQL Injection in Login');
    });

    it('includes finding URLs', () => {
      const findings = [makeFinding({ url: 'https://target.com/api/v1/users' })];
      const output = formatFindingsSummary(findings);
      expect(output).toContain('https://target.com/api/v1/users');
    });

    it('handles duplicate findings (shows raw vs unique count)', () => {
      const f1 = makeFinding({ id: 'dup-1', category: 'xss', url: 'https://example.com/a', title: 'XSS' });
      const f2 = makeFinding({ id: 'dup-2', category: 'xss', url: 'https://example.com/a', title: 'XSS' });
      const findings = [f1, f2];
      const output = formatFindingsSummary(findings);
      // Should mention raw count in parentheses
      expect(output).toContain('2 raw');
    });
  });
});

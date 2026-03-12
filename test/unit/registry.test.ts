import { describe, it, expect } from 'vitest';
import { parseRegistry, isDue } from '../../src/hunting/registry.js';

const VALID_REGISTRY = `programs:
  - name: "Example Corp"
    platform: hackerone
    scope_file: ./scopes/example.scope
    profile: standard
    schedule: weekly
    auth: ./auth/example.json
  - name: "Acme Inc"
    platform: bugcrowd
    scope_file: ./scopes/acme.scope
    profile: quick
    schedule: daily
`;

describe('parseRegistry', () => {
  it('parses a valid YAML-like registry', () => {
    const programs = parseRegistry(VALID_REGISTRY);
    expect(programs).toHaveLength(2);
  });

  it('parses name correctly', () => {
    const programs = parseRegistry(VALID_REGISTRY);
    expect(programs[0].name).toBe('Example Corp');
    expect(programs[1].name).toBe('Acme Inc');
  });

  it('parses platform correctly', () => {
    const programs = parseRegistry(VALID_REGISTRY);
    expect(programs[0].platform).toBe('hackerone');
    expect(programs[1].platform).toBe('bugcrowd');
  });

  it('converts scope_file snake_case to scopeFile camelCase', () => {
    const programs = parseRegistry(VALID_REGISTRY);
    expect(programs[0].scopeFile).toBe('./scopes/example.scope');
    expect(programs[1].scopeFile).toBe('./scopes/acme.scope');
  });

  it('parses profile and schedule correctly', () => {
    const programs = parseRegistry(VALID_REGISTRY);
    expect(programs[0].profile).toBe('standard');
    expect(programs[0].schedule).toBe('weekly');
    expect(programs[1].profile).toBe('quick');
    expect(programs[1].schedule).toBe('daily');
  });

  it('parses optional auth field', () => {
    const programs = parseRegistry(VALID_REGISTRY);
    expect(programs[0].auth).toBe('./auth/example.json');
    expect(programs[1].auth).toBeUndefined();
  });

  it('strips quotes from string values', () => {
    const content = `programs:\n  - name: 'Single Quoted'\n    platform: intigriti\n    scope_file: ./scope\n    profile: deep\n    schedule: monthly\n`;
    const programs = parseRegistry(content);
    expect(programs[0].name).toBe('Single Quoted');
  });

  it('throws when platform is missing', () => {
    const bad = `programs:\n  - name: "No Platform"\n    scope_file: ./scope\n    profile: standard\n    schedule: weekly\n`;
    expect(() => parseRegistry(bad)).toThrow(/platform/);
  });

  it('throws when schedule is missing', () => {
    const bad = `programs:\n  - name: "No Schedule"\n    platform: hackerone\n    scope_file: ./scope\n    profile: standard\n`;
    expect(() => parseRegistry(bad)).toThrow(/schedule/);
  });

  it('returns empty array for content with no program entries', () => {
    const programs = parseRegistry('programs:\n');
    expect(programs).toHaveLength(0);
  });

  it('handles last_scan field via snake_case conversion', () => {
    const content = `programs:\n  - name: "With LastScan"\n    platform: hackerone\n    scope_file: ./scope\n    profile: standard\n    schedule: weekly\n    last_scan: 2026-01-01T00:00:00.000Z\n`;
    const programs = parseRegistry(content);
    expect(programs[0].lastScan).toBe('2026-01-01T00:00:00.000Z');
  });
});

describe('isDue', () => {
  it('returns true when no lastScan provided (daily)', () => {
    expect(isDue('daily')).toBe(true);
  });

  it('returns true when no lastScan provided (weekly)', () => {
    expect(isDue('weekly')).toBe(true);
  });

  it('returns true when no lastScan provided (monthly)', () => {
    expect(isDue('monthly')).toBe(true);
  });

  it('returns false for daily scan done less than 1 day ago', () => {
    const recent = new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(); // 12 hours ago
    expect(isDue('daily', recent)).toBe(false);
  });

  it('returns true for daily scan done more than 1 day ago', () => {
    const old = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(); // 25 hours ago
    expect(isDue('daily', old)).toBe(true);
  });

  it('returns false for weekly scan done 3 days ago', () => {
    const recent = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
    expect(isDue('weekly', recent)).toBe(false);
  });

  it('returns true for weekly scan done 8 days ago', () => {
    const old = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    expect(isDue('weekly', old)).toBe(true);
  });

  it('returns false for biweekly scan done 10 days ago', () => {
    const recent = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    expect(isDue('biweekly', recent)).toBe(false);
  });

  it('returns true for biweekly scan done 15 days ago', () => {
    const old = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString();
    expect(isDue('biweekly', old)).toBe(true);
  });

  it('returns false for monthly scan done 20 days ago', () => {
    const recent = new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString();
    expect(isDue('monthly', recent)).toBe(false);
  });

  it('returns true for monthly scan done 31 days ago', () => {
    const old = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    expect(isDue('monthly', old)).toBe(true);
  });
});

import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('SQLi payload context wiring', () => {
  it('prioritizes MySQL payloads when PHP detected', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['mysql']);
    // MySQL payloads should come first
    expect(result[0].dbType).toBe('mysql');
    // All payloads still included (don't drop — just reorder)
    expect(result.length).toBeGreaterThanOrEqual(4);
  });

  it('prioritizes MSSQL payloads when .NET detected', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['mssql']);
    expect(result[0].dbType).toBe('mssql');
  });

  it('prioritizes PostgreSQL payloads when Python detected', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['postgres']);
    expect(result[0].dbType).toBe('postgres');
  });

  it('keeps original order when no context', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['unknown']);
    expect(result.length).toBeGreaterThanOrEqual(4);
    // Original order preserved (mysql first)
    expect(result[0].dbType).toBe('mysql');
  });

  it('handles multiple database types', async () => {
    const { prioritizeTimedPayloads } = await import('../../src/scanner/active/sqli.js');
    const result = prioritizeTimedPayloads(['postgres', 'sqlite']);
    // Postgres and sqlite payloads should come first
    const prioritizedTypes = result.slice(0, 2).map((p) => p.dbType);
    expect(prioritizedTypes).toContain('postgres');
    expect(prioritizedTypes).toContain('sqlite');
  });
});

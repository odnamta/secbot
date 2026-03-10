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

describe('SSTI payload context wiring', () => {
  it('prioritizes Jinja2 payloads when Django detected', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const result = prioritizeSstiPayloads(['jinja2']);
    expect(result[0].engine.toLowerCase()).toContain('jinja2');
  });

  it('prioritizes ERB payloads when Ruby detected', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const result = prioritizeSstiPayloads(['erb']);
    expect(result[0].engine.toLowerCase()).toContain('erb');
  });

  it('prioritizes Freemarker payloads when Java detected', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const result = prioritizeSstiPayloads(['freemarker']);
    expect(result[0].engine.toLowerCase()).toContain('freemarker');
  });

  it('keeps all payloads when no context', async () => {
    const { prioritizeSstiPayloads } = await import('../../src/scanner/active/ssti.js');
    const { SSTI_PAYLOADS } = await import('../../src/config/payloads/ssti.js');
    const result = prioritizeSstiPayloads(['unknown']);
    expect(result.length).toBe(SSTI_PAYLOADS.length);
  });
});

describe('XSS payload context wiring', () => {
  it('exports shouldPrioritizeDomXss function', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    expect(typeof shouldPrioritizeDomXss).toBe('function');
  });

  it('returns true when payloadContext.preferDomXss is true', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    const config = { payloadContext: { preferDomXss: true } } as any;
    expect(shouldPrioritizeDomXss(config)).toBe(true);
  });

  it('returns false when no payloadContext', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    const config = {} as any;
    expect(shouldPrioritizeDomXss(config)).toBe(false);
  });

  it('returns false when preferDomXss is false', async () => {
    const { shouldPrioritizeDomXss } = await import('../../src/scanner/active/xss.js');
    const config = { payloadContext: { preferDomXss: false } } as any;
    expect(shouldPrioritizeDomXss(config)).toBe(false);
  });
});

describe('CMDi payload context wiring', () => {
  it('prioritizes unix payloads when OS is unix', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('unix');
    expect(result.timing[0].os).toBe('unix');
    expect(result.output[0].os).toBe('unix');
  });

  it('prioritizes windows payloads when OS is windows', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('windows');
    expect(result.timing[0].os).toBe('windows');
  });

  it('keeps all payloads when OS is unknown', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('unknown');
    const totalPayloads = result.timing.length + result.output.length;
    expect(totalPayloads).toBeGreaterThanOrEqual(7);
  });

  it('includes all payloads even when prioritizing', async () => {
    const { prioritizeCmdiPayloads } = await import('../../src/scanner/active/cmdi.js');
    const result = prioritizeCmdiPayloads('unix');
    // Windows payloads should still be present (at the end)
    expect(result.timing.some((p) => p.os === 'windows')).toBe(true);
  });
});

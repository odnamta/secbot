import { describe, it, expect, vi } from 'vitest';
import type { CheckAuditEntry } from '../../src/scanner/types.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('CheckAuditEntry type', () => {
  it('can represent a completed check', () => {
    const entry: CheckAuditEntry = {
      name: 'xss',
      status: 'completed',
      findingsCount: 3,
      durationMs: 1200,
    };
    expect(entry.status).toBe('completed');
    expect(entry.findingsCount).toBe(3);
    expect(entry.error).toBeUndefined();
  });

  it('can represent a failed check with error', () => {
    const entry: CheckAuditEntry = {
      name: 'sqli',
      status: 'failed',
      findingsCount: 0,
      durationMs: 50,
      error: 'Target page crashed',
    };
    expect(entry.status).toBe('failed');
    expect(entry.findingsCount).toBe(0);
    expect(entry.error).toBe('Target page crashed');
  });

  it('can represent a skipped check', () => {
    const entry: CheckAuditEntry = {
      name: 'traversal',
      status: 'skipped',
      findingsCount: 0,
      durationMs: 0,
    };
    expect(entry.status).toBe('skipped');
  });
});

describe('runActiveChecks audit trail', () => {
  it('records completed check with findingsCount in audit', async () => {
    const { runActiveChecks } = await import('../../src/scanner/active/index.js');
    type AC = import('../../src/scanner/active/index.js').ActiveCheck;

    // Temporarily replace CHECK_REGISTRY for this test
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const originalLength = CHECK_REGISTRY.length;
    CHECK_REGISTRY.length = 0;

    const fakeCheck: AC = {
      name: 'fake-pass',
      category: 'xss',
      parallel: true,
      run: async () => [
        {
          id: 'f1',
          category: 'xss',
          severity: 'high',
          title: 'Test XSS',
          description: 'test',
          url: 'http://example.com',
          evidence: 'reflected',
          timestamp: new Date().toISOString(),
        },
      ],
    };
    CHECK_REGISTRY.push(fakeCheck);

    const mockContext = {
      newPage: vi.fn().mockResolvedValue({ close: vi.fn() }),
    } as any;

    const config = {
      targetUrl: 'http://example.com',
      profile: 'standard' as const,
      maxPages: 5,
      timeout: 10000,
      respectRobots: true,
      outputFormat: ['terminal'] as any,
      concurrency: 1,
      requestDelay: 0,
      logRequests: false,
      useAI: false,
    };

    const result = await runActiveChecks(mockContext, [], config);

    expect(result.audit).toHaveLength(1);
    expect(result.audit[0].name).toBe('fake-pass');
    expect(result.audit[0].status).toBe('completed');
    expect(result.audit[0].findingsCount).toBe(1);
    expect(result.audit[0].durationMs).toBeGreaterThanOrEqual(0);
    expect(result.audit[0].error).toBeUndefined();
    expect(result.findings).toHaveLength(1);

    // Restore registry
    CHECK_REGISTRY.length = 0;
    // We can't perfectly restore, but tests are isolated via vitest
  });

  it('records failed check with error message in audit', async () => {
    const { runActiveChecks, CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    type AC = import('../../src/scanner/active/index.js').ActiveCheck;

    CHECK_REGISTRY.length = 0;

    const crashingCheck: AC = {
      name: 'fake-crash',
      category: 'sqli',
      parallel: true,
      run: async () => {
        throw new Error('Browser page crashed unexpectedly');
      },
    };
    CHECK_REGISTRY.push(crashingCheck);

    const mockContext = {
      newPage: vi.fn().mockResolvedValue({ close: vi.fn() }),
    } as any;

    const config = {
      targetUrl: 'http://example.com',
      profile: 'standard' as const,
      maxPages: 5,
      timeout: 10000,
      respectRobots: true,
      outputFormat: ['terminal'] as any,
      concurrency: 1,
      requestDelay: 0,
      logRequests: false,
      useAI: false,
    };

    const result = await runActiveChecks(mockContext, [], config);

    expect(result.audit).toHaveLength(1);
    expect(result.audit[0].name).toBe('fake-crash');
    expect(result.audit[0].status).toBe('failed');
    expect(result.audit[0].findingsCount).toBe(0);
    expect(result.audit[0].error).toBe('Browser page crashed unexpectedly');
    expect(result.findings).toHaveLength(0);

    CHECK_REGISTRY.length = 0;
  });

  it('records skipped checks when --exclude-checks is used', async () => {
    const { runActiveChecks, CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    type AC = import('../../src/scanner/active/index.js').ActiveCheck;

    CHECK_REGISTRY.length = 0;

    const checkA: AC = {
      name: 'keep-me',
      category: 'cors-misconfiguration',
      parallel: true,
      run: async () => [],
    };
    const checkB: AC = {
      name: 'skip-me',
      category: 'xss',
      parallel: true,
      run: async () => {
        throw new Error('Should not run');
      },
    };
    CHECK_REGISTRY.push(checkA, checkB);

    const mockContext = {
      newPage: vi.fn().mockResolvedValue({ close: vi.fn() }),
    } as any;

    const config = {
      targetUrl: 'http://example.com',
      profile: 'standard' as const,
      maxPages: 5,
      timeout: 10000,
      respectRobots: true,
      outputFormat: ['terminal'] as any,
      concurrency: 1,
      requestDelay: 0,
      logRequests: false,
      useAI: false,
      excludeChecks: ['skip-me'],
    };

    const result = await runActiveChecks(mockContext, [], config);

    const skipped = result.audit.find((a) => a.name === 'skip-me');
    expect(skipped).toBeDefined();
    expect(skipped!.status).toBe('skipped');

    const completed = result.audit.find((a) => a.name === 'keep-me');
    expect(completed).toBeDefined();
    expect(completed!.status).toBe('completed');

    CHECK_REGISTRY.length = 0;
  });

  it('logs prominent error when >50% of checks fail', async () => {
    const { log } = await import('../../src/utils/logger.js');
    const { runActiveChecks, CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    type AC = import('../../src/scanner/active/index.js').ActiveCheck;

    CHECK_REGISTRY.length = 0;

    // 3 crashing checks, 1 passing — 75% failure rate
    for (let i = 0; i < 3; i++) {
      CHECK_REGISTRY.push({
        name: `crash-${i}`,
        category: 'xss',
        parallel: true,
        run: async () => { throw new Error('dead'); },
      } as AC);
    }
    CHECK_REGISTRY.push({
      name: 'survivor',
      category: 'tls',
      parallel: true,
      run: async () => [],
    } as AC);

    const mockContext = {
      newPage: vi.fn().mockResolvedValue({ close: vi.fn() }),
    } as any;

    const config = {
      targetUrl: 'http://example.com',
      profile: 'standard' as const,
      maxPages: 5,
      timeout: 10000,
      respectRobots: true,
      outputFormat: ['terminal'] as any,
      concurrency: 1,
      requestDelay: 0,
      logRequests: false,
      useAI: false,
    };

    await runActiveChecks(mockContext, [], config);

    // Verify log.error was called with the majority-failed warning
    expect(log.error).toHaveBeenCalledWith(
      expect.stringContaining('active checks failed'),
    );

    CHECK_REGISTRY.length = 0;
  });
});

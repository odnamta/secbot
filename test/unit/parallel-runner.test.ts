import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('parallel check runner', () => {
  it('separates checks into parallel and sequential groups', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');

    const parallel = CHECK_REGISTRY.filter((c) => c.parallel);
    const sequential = CHECK_REGISTRY.filter((c) => !c.parallel);

    // At least 7 checks should be parallelizable
    expect(parallel.length).toBeGreaterThanOrEqual(7);
    // At least 5 checks must remain sequential (xss, sqli, ssrf, ssti, cmdi, etc.)
    expect(sequential.length).toBeGreaterThanOrEqual(5);

    // Verify specific checks are in the right group
    expect(parallel.find((c) => c.name === 'cors')).toBeDefined();
    expect(parallel.find((c) => c.name === 'tls')).toBeDefined();
    expect(parallel.find((c) => c.name === 'sri')).toBeDefined();
    expect(parallel.find((c) => c.name === 'jwt')).toBeDefined();
    expect(parallel.find((c) => c.name === 'info-disclosure')).toBeDefined();
    expect(parallel.find((c) => c.name === 'js-cve')).toBeDefined();
    expect(parallel.find((c) => c.name === 'host-header')).toBeDefined();
    expect(parallel.find((c) => c.name === 'rate-limit')).toBeDefined();
    expect(parallel.find((c) => c.name === 'graphql')).toBeDefined();

    // These MUST be sequential (they inject payloads)
    expect(sequential.find((c) => c.name === 'xss')).toBeDefined();
    expect(sequential.find((c) => c.name === 'sqli')).toBeDefined();
    expect(sequential.find((c) => c.name === 'ssrf')).toBeDefined();
    expect(sequential.find((c) => c.name === 'ssti')).toBeDefined();
    expect(sequential.find((c) => c.name === 'cmdi')).toBeDefined();
  });
});

describe('splitChecksByParallelism', () => {
  it('returns parallel and sequential arrays', async () => {
    const { splitChecksByParallelism } = await import('../../src/scanner/active/index.js');
    type AC = import('../../src/scanner/active/index.js').ActiveCheck;

    const checks: AC[] = [
      { name: 'a', category: 'tls', parallel: true, run: async () => [] },
      { name: 'b', category: 'xss', run: async () => [] },
      { name: 'c', category: 'sri', parallel: true, run: async () => [] },
    ];
    const { parallel, sequential } = splitChecksByParallelism(checks);
    expect(parallel.map((c) => c.name)).toEqual(['a', 'c']);
    expect(sequential.map((c) => c.name)).toEqual(['b']);
  });

  it('returns empty arrays for empty input', async () => {
    const { splitChecksByParallelism } = await import('../../src/scanner/active/index.js');
    const { parallel, sequential } = splitChecksByParallelism([]);
    expect(parallel).toEqual([]);
    expect(sequential).toEqual([]);
  });
});

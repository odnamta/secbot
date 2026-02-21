import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { BrowserContext } from 'playwright';
import type { ScanConfig, CrawledPage, RawFinding } from '../../src/scanner/types.js';
import { CHECK_REGISTRY, runActiveChecks } from '../../src/scanner/active/index.js';
import type { ActiveCheck } from '../../src/scanner/active/index.js';

// Mock the logger to capture log output
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock the rate limiter with a real class so `new RateLimiter(...)` works
vi.mock('../../src/utils/rate-limiter.js', () => {
  class MockRateLimiter {
    async acquire() {}
    getStats() {
      return { totalRequests: 0, backoffs: 0, currentDelayMs: 100 };
    }
  }
  return { RateLimiter: MockRateLimiter };
});

// Import the mocked logger so we can inspect calls
import { log } from '../../src/utils/logger.js';

// Stub browser context - not actually used in unit tests
const mockContext = {} as BrowserContext;

// Minimal pages fixture
const mockPages: CrawledPage[] = [
  {
    url: 'https://example.com/',
    status: 200,
    headers: {},
    title: 'Test',
    forms: [],
    links: [],
    scripts: [],
    cookies: [],
  },
];

function makeConfig(overrides: Partial<ScanConfig> = {}): ScanConfig {
  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    maxPages: 25,
    timeout: 30000,
    respectRobots: true,
    outputFormat: ['terminal'],
    concurrency: 5,
    requestDelay: 100,
    logRequests: false,
    useAI: false,
    ...overrides,
  };
}

describe('--exclude-checks filtering', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Stub all check run methods to return empty findings without doing real scanning
    for (const check of CHECK_REGISTRY) {
      vi.spyOn(check, 'run').mockResolvedValue([]);
    }
  });

  it('runs all checks when excludeChecks is undefined', async () => {
    const config = makeConfig({ profile: 'deep' });

    await runActiveChecks(mockContext, mockPages, config);

    // All 11 checks should have been called
    for (const check of CHECK_REGISTRY) {
      expect(check.run).toHaveBeenCalled();
    }
  });

  it('runs all checks when excludeChecks is an empty array', async () => {
    const config = makeConfig({ profile: 'deep', excludeChecks: [] });

    await runActiveChecks(mockContext, mockPages, config);

    for (const check of CHECK_REGISTRY) {
      expect(check.run).toHaveBeenCalled();
    }
  });

  it('excludes specified checks by name', async () => {
    const config = makeConfig({
      profile: 'deep',
      excludeChecks: ['traversal', 'cmdi', 'sqli'],
    });

    await runActiveChecks(mockContext, mockPages, config);

    // These checks should NOT have run
    const traversal = CHECK_REGISTRY.find((c) => c.name === 'traversal')!;
    const cmdi = CHECK_REGISTRY.find((c) => c.name === 'cmdi')!;
    const sqli = CHECK_REGISTRY.find((c) => c.name === 'sqli')!;
    expect(traversal.run).not.toHaveBeenCalled();
    expect(cmdi.run).not.toHaveBeenCalled();
    expect(sqli.run).not.toHaveBeenCalled();

    // Other checks should still have run
    const xss = CHECK_REGISTRY.find((c) => c.name === 'xss')!;
    const cors = CHECK_REGISTRY.find((c) => c.name === 'cors')!;
    expect(xss.run).toHaveBeenCalled();
    expect(cors.run).toHaveBeenCalled();
  });

  it('logs which checks were excluded', async () => {
    const config = makeConfig({
      profile: 'deep',
      excludeChecks: ['ssrf', 'ssti'],
    });

    await runActiveChecks(mockContext, mockPages, config);

    expect(log.info).toHaveBeenCalledWith(
      expect.stringContaining('Excluded checks:'),
    );
    // The log message should mention both excluded checks
    const excludedCall = vi.mocked(log.info).mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('Excluded checks:'),
    );
    expect(excludedCall).toBeDefined();
    expect(excludedCall![0]).toContain('ssrf');
    expect(excludedCall![0]).toContain('ssti');
  });

  it('ignores invalid check names gracefully', async () => {
    const config = makeConfig({
      profile: 'deep',
      excludeChecks: ['nonexistent', 'fake-check', 'xss'],
    });

    await runActiveChecks(mockContext, mockPages, config);

    // xss should be excluded
    const xss = CHECK_REGISTRY.find((c) => c.name === 'xss')!;
    expect(xss.run).not.toHaveBeenCalled();

    // Invalid names should trigger a warning
    expect(log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Unknown check names'),
    );
    const warnCall = vi.mocked(log.warn).mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('Unknown check names'),
    );
    expect(warnCall).toBeDefined();
    expect(warnCall![0]).toContain('nonexistent');
    expect(warnCall![0]).toContain('fake-check');
    // xss is valid, should NOT be in the warning
    expect(warnCall![0]).not.toContain('xss');
  });

  it('excludes checks even when attack plan is present', async () => {
    const config = makeConfig({
      profile: 'deep',
      excludeChecks: ['xss'],
    });

    const attackPlan = {
      recommendedChecks: [
        { name: 'xss', priority: 1, reason: 'test' },
        { name: 'sqli', priority: 2, reason: 'test' },
        { name: 'cors', priority: 3, reason: 'test' },
      ],
      reasoning: 'test plan',
      skipReasons: {},
    };

    await runActiveChecks(mockContext, mockPages, config, attackPlan);

    // xss should be excluded even though the attack plan recommends it
    const xss = CHECK_REGISTRY.find((c) => c.name === 'xss')!;
    expect(xss.run).not.toHaveBeenCalled();

    // sqli and cors should still run
    const sqli = CHECK_REGISTRY.find((c) => c.name === 'sqli')!;
    const cors = CHECK_REGISTRY.find((c) => c.name === 'cors')!;
    expect(sqli.run).toHaveBeenCalled();
    expect(cors.run).toHaveBeenCalled();
  });

  it('excluding all checks results in no checks running', async () => {
    const allCheckNames = CHECK_REGISTRY.map((c) => c.name);
    const config = makeConfig({
      profile: 'deep',
      excludeChecks: allCheckNames,
    });

    const findings = await runActiveChecks(mockContext, mockPages, config);

    expect(findings).toEqual([]);
    for (const check of CHECK_REGISTRY) {
      expect(check.run).not.toHaveBeenCalled();
    }
  });
});

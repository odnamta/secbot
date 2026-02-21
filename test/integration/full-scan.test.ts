import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestServer, stopTestServer, getTestUrl } from '../setup.js';
import { crawl, closeBrowser } from '../../src/scanner/browser.js';
import { runPassiveChecks } from '../../src/scanner/passive.js';
import { runActiveChecks, CHECK_REGISTRY } from '../../src/scanner/active/index.js';
import { runRecon } from '../../src/scanner/recon.js';
import { deduplicateFindings } from '../../src/utils/dedup.js';
import { generateReport } from '../../src/ai/reporter.js';
import { buildConfig } from '../../src/config/defaults.js';
import type { ScanConfig, ScanResult, ScanSummary } from '../../src/scanner/types.js';

describe('Full scan integration', () => {
  let baseUrl: string;

  beforeAll(async () => {
    baseUrl = await startTestServer();
  }, 30000);

  afterAll(async () => {
    await stopTestServer();
  });

  it('runs a complete scan pipeline and produces valid ScanResult', async () => {
    const startedAt = new Date().toISOString();

    // Build config: standard profile, no AI
    const config: ScanConfig = buildConfig(baseUrl, {
      profile: 'standard',
      useAI: false,
      outputFormat: ['terminal'],
      respectRobots: false,
    });

    // Phase 1: Crawl
    const { pages, responses, browser, context } = await crawl(config);
    expect(pages.length).toBeGreaterThan(0);

    try {
      // Phase 2: Recon
      const recon = runRecon(pages, responses);
      expect(recon).toBeDefined();
      expect(recon.techStack).toBeDefined();

      // Phase 4: Passive checks
      const passiveFindings = runPassiveChecks(pages, responses);

      // Phase 5: Active checks (no attack plan = run all)
      const activeFindings = await runActiveChecks(context, pages, config);

      const allRawFindings = [...passiveFindings, ...activeFindings];

      // Dedup
      const dedupedFindings = deduplicateFindings(allRawFindings);
      expect(dedupedFindings.length).toBeLessThanOrEqual(allRawFindings.length);

      // Fallback validation (no AI)
      const validations = dedupedFindings.map((f) => ({
        findingId: f.id,
        isValid: true,
        confidence: 'medium' as const,
        reasoning: 'AI validation skipped',
      }));

      // Phase 7: Generate report (fallback mode)
      const { findings: interpretedFindings, summary } = await generateReport(
        baseUrl,
        dedupedFindings,
        validations,
        recon,
      );

      const completedAt = new Date().toISOString();

      // Compute new fields
      const scanDuration = new Date(completedAt).getTime() - new Date(startedAt).getTime();

      const passiveCheckNames = [
        'security-headers', 'cookie-flags', 'info-leakage',
        'mixed-content', 'sensitive-url-data', 'cross-origin-policy',
      ];
      const activeCheckNames = CHECK_REGISTRY
        .filter((c) => {
          if (c.name === 'traversal' && config.profile !== 'deep') return false;
          return true;
        })
        .map((c) => c.name);
      const checksRun = [...passiveCheckNames, ...activeCheckNames];

      const categoriesWithFindings = new Set(allRawFindings.map((f) => f.category));
      const passedChecks = checksRun.filter((name) => !categoriesWithFindings.has(name));
      summary.passedChecks = passedChecks;

      const hasHighOrCritical = interpretedFindings.some(
        (f) => f.severity === 'high' || f.severity === 'critical',
      );
      const exitCode = hasHighOrCritical ? 1 : 0;

      const scanResult: ScanResult = {
        targetUrl: baseUrl,
        profile: config.profile,
        startedAt,
        completedAt,
        pagesScanned: pages.length,
        rawFindings: allRawFindings,
        interpretedFindings,
        summary,
        recon,
        validatedFindings: validations,
        exitCode,
        scanDuration,
        checksRun,
      };

      // ─── Assertions ──────────────────────────────────────────

      // exitCode is 1 (vulnerable server has high/critical findings)
      expect(scanResult.exitCode).toBe(1);

      // scanDuration is positive
      expect(scanResult.scanDuration).toBeGreaterThan(0);

      // checksRun is non-empty
      expect(scanResult.checksRun.length).toBeGreaterThan(0);
      expect(scanResult.checksRun).toContain('security-headers');
      expect(scanResult.checksRun).toContain('xss');

      // At least 1 XSS finding in raw
      const xssFindings = allRawFindings.filter((f) => f.category === 'xss');
      expect(xssFindings.length).toBeGreaterThanOrEqual(1);

      // At least 1 security header finding
      const headerFindings = allRawFindings.filter((f) => f.category === 'security-headers');
      expect(headerFindings.length).toBeGreaterThanOrEqual(1);

      // pagesScanned > 0
      expect(scanResult.pagesScanned).toBeGreaterThan(0);

      // interpretedFindings has entries
      expect(scanResult.interpretedFindings.length).toBeGreaterThan(0);

      // summary fields are populated
      expect(scanResult.summary.totalRawFindings).toBeGreaterThan(0);
      expect(scanResult.summary.totalInterpretedFindings).toBeGreaterThan(0);
      expect(scanResult.summary.topIssues.length).toBeGreaterThan(0);
      expect(Array.isArray(scanResult.summary.passedChecks)).toBe(true);

      // passedChecks should NOT contain checks that found something
      for (const passed of scanResult.summary.passedChecks) {
        expect(categoriesWithFindings.has(passed)).toBe(false);
      }

    } finally {
      await closeBrowser(browser);
    }
  }, 120000);
});

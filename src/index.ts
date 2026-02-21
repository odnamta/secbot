#!/usr/bin/env node
import { config as loadEnv } from 'dotenv';
loadEnv({ path: '.env.local', override: false });
loadEnv({ override: false }); // fallback to .env

import { program } from 'commander';
import chalk from 'chalk';
import { resolve, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { crawl, closeBrowser } from './scanner/browser.js';
import { runPassiveChecks } from './scanner/passive.js';
import { runActiveChecks, CHECK_REGISTRY } from './scanner/active/index.js';
import { runRecon } from './scanner/recon.js';
import { planAttack } from './ai/planner.js';
import { validateFindings } from './ai/validator.js';
import { generateReport } from './ai/reporter.js';
import { printTerminalReport } from './reporter/terminal.js';
import { writeJsonReport } from './reporter/json.js';
import { writeHtmlReport } from './reporter/html.js';
import { writeBountyReport } from './reporter/bounty.js';
import { buildConfig } from './config/defaults.js';
import { parseScopePatterns } from './utils/scope.js';
import { RequestLogger } from './utils/request-logger.js';
import { log, setLogLevel } from './utils/logger.js';
import { deduplicateFindings } from './utils/dedup.js';
import { discoverRoutes } from './scanner/discovery/index.js';
import type { ScanConfig, ScanProfile, ScanResult } from './scanner/types.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));

let cleanupDone = false;
async function cleanup() {
  if (cleanupDone) return;
  cleanupDone = true;
  log.warn('Interrupted — cleaning up...');
  try { await closeBrowser(); } catch { /* best effort */ }
  process.exit(130);
}
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

program
  .name('secbot')
  .description('AI-powered security testing CLI')
  .version(pkg.version);

program
  .command('scan')
  .description('Scan a target URL for security vulnerabilities')
  .argument('<url>', 'Target URL to scan')
  .option('-p, --profile <profile>', 'Scan profile: quick, standard, deep', 'standard')
  .option('-a, --auth <path>', 'Path to Playwright storage state JSON for authenticated scanning')
  .option('-f, --format <formats>', 'Output formats: terminal,json,html,bounty (comma-separated)', 'terminal')
  .option('-o, --output <path>', 'Output directory for reports', './secbot-reports')
  .option('--max-pages <n>', 'Maximum pages to crawl', undefined)
  .option('--timeout <ms>', 'Per-page timeout in milliseconds', undefined)
  .option('--ignore-robots', 'Ignore robots.txt restrictions', false)
  .option('--scope <patterns>', 'Scope patterns: "*.example.com,-admin.example.com"')
  .option('--urls <file>', 'File with URLs to scan (one per line)')
  .option('--log-requests', 'Log all HTTP requests for accountability', false)
  .option('--no-ai', 'Skip AI interpretation (use rule-based fallback)')
  .option('--verbose', 'Enable verbose logging', false)
  .action(async (url: string, options: Record<string, unknown>) => {
    if (options.verbose) {
      setLogLevel('debug');
    }

    log.banner();

    // Validate URL
    let targetUrl: string;
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs are supported');
      }
      targetUrl = parsed.href;
    } catch {
      console.error(chalk.red(`Invalid URL: ${url}`));
      process.exit(1);
    }

    // Consent prompt for external targets
    const isLocalhost = /localhost|127\.0\.0\.1|0\.0\.0\.0/.test(targetUrl);
    if (!isLocalhost) {
      console.log(chalk.yellow.bold('  ⚠ DISCLAIMER'));
      console.log(chalk.yellow('  You are about to scan an external target.'));
      console.log(chalk.yellow('  Only scan targets you own or have explicit authorization to test.'));
      console.log(chalk.yellow(`  Target: ${targetUrl}`));
      console.log();

      if (process.stdin.isTTY) {
        const { createInterface } = await import('node:readline');
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        const answer = await new Promise<string>((res) => {
          rl.question(chalk.yellow('  Proceed? (y/N) '), (ans) => {
            rl.close();
            res(ans);
          });
        });
        if (answer.toLowerCase() !== 'y') {
          console.log('Scan cancelled.');
          process.exit(0);
        }
      }
      console.log();
    }

    // Build config
    const formats = (options.format as string).split(',').map((f) => f.trim()) as ScanConfig['outputFormat'];
    const scope = options.scope ? parseScopePatterns(options.scope as string) : undefined;
    const useAI = options.ai !== false;

    const config = buildConfig(targetUrl, {
      profile: options.profile as ScanProfile,
      authStorageState: options.auth as string | undefined,
      outputFormat: formats,
      outputPath: options.output as string,
      respectRobots: !options.ignoreRobots,
      scope,
      logRequests: options.logRequests === true,
      useAI,
      ...(options.maxPages ? { maxPages: parseInt(options.maxPages as string, 10) } : {}),
      ...(options.timeout ? { timeout: parseInt(options.timeout as string, 10) } : {}),
    });

    const scanId = new Date().toISOString().replace(/[:.]/g, '-');
    const outputDir = resolve(config.outputPath ?? './secbot-reports');
    const startedAt = new Date().toISOString();

    // Set up request logger (opt-in)
    const requestLogger = config.logRequests
      ? new RequestLogger(outputDir, scanId)
      : undefined;

    try {
      // ─── Phase 0: Route Discovery ──────────────────────────────
      log.info('Phase 0: Discovering routes...');
      const discoveredRoutes = await discoverRoutes(targetUrl, options.urls as string | undefined);
      if (discoveredRoutes.length > 0) {
        log.info(`Discovered ${discoveredRoutes.length} additional routes`);
      }
      const seedUrls = discoveredRoutes.map((r) => r.url);

      // ─── Phase 1: Crawl ────────────────────────────────────────
      log.info('Phase 1: Crawling target...');
      const { pages, responses, browser, context } = await crawl(config, seedUrls);

      if (pages.length === 0) {
        console.log(chalk.yellow('No pages were successfully crawled. Check the URL and try again.'));
        await closeBrowser(browser);
        process.exit(1);
      }

      try {
        // ─── Phase 2: Recon ──────────────────────────────────────
        log.info('Phase 2: Running reconnaissance...');
        const recon = runRecon(pages, responses);

        // ─── Phase 3: AI Attack Plan ─────────────────────────────
        let attackPlan;
        if (config.useAI) {
          log.info('Phase 3: AI planning attack strategy...');
          attackPlan = await planAttack(targetUrl, recon, pages, config.profile);
        } else {
          log.info('Phase 3: Skipping AI planning (--no-ai)');
        }

        // ─── Phase 4: Passive Scanning ───────────────────────────
        log.info('Phase 4: Running passive security checks...');
        const passiveFindings = runPassiveChecks(pages, responses);

        // ─── Phase 5: Active Scanning ────────────────────────────
        log.info('Phase 5: Running active security checks...');
        const activeFindings = await runActiveChecks(
          context,
          pages,
          config,
          attackPlan,
          requestLogger,
        );

        const allRawFindings = [...passiveFindings, ...activeFindings];

        // Deduplicate before AI validation to save tokens
        log.info(`Raw findings before dedup: ${allRawFindings.length}`);
        const dedupedFindings = deduplicateFindings(allRawFindings);
        log.info(`After dedup: ${dedupedFindings.length} unique findings`);

        // ─── Phase 6: AI Validation ──────────────────────────────
        let validations;
        if (config.useAI && dedupedFindings.length > 0) {
          log.info('Phase 6: AI validating findings...');
          validations = await validateFindings(targetUrl, dedupedFindings, recon);
        } else {
          log.info(config.useAI ? 'Phase 6: No findings to validate' : 'Phase 6: Skipping AI validation (--no-ai)');
          // Fallback: mark all as valid
          validations = dedupedFindings.map((f) => ({
            findingId: f.id,
            isValid: true,
            confidence: 'medium' as const,
            reasoning: 'AI validation skipped',
          }));
        }

        // ─── Phase 7: AI Report Generation ───────────────────────
        log.info('Phase 7: Generating report...');
        const { findings: interpretedFindings, summary } = await generateReport(
          targetUrl,
          dedupedFindings,
          validations,
          recon,
        );

        const completedAt = new Date().toISOString();

        // Compute new output fields
        const scanDuration = new Date(completedAt).getTime() - new Date(startedAt).getTime();

        // Determine which checks ran
        const passiveCheckNames = ['security-headers', 'cookie-flags', 'info-leakage', 'mixed-content', 'sensitive-url-data', 'cross-origin-policy'];
        const activeCheckNames = attackPlan
          ? [...attackPlan.recommendedChecks]
              .sort((a, b) => a.priority - b.priority)
              .map((rec) => CHECK_REGISTRY.find((c) => c.name === rec.name))
              .filter((c) => c !== undefined)
              .map((c) => c.name)
          : CHECK_REGISTRY
              .filter((c) => {
                if (c.name === 'traversal' && config.profile !== 'deep') return false;
                return true;
              })
              .map((c) => c.name);
        const checksRun = [...passiveCheckNames, ...activeCheckNames];

        // Determine which checks passed (ran but produced 0 findings)
        const categoriesWithFindings = new Set(allRawFindings.map((f) => f.category));
        const passedChecks = checksRun.filter((name) => !categoriesWithFindings.has(name));

        // Include passedChecks in the summary
        summary.passedChecks = passedChecks;

        const hasHighOrCritical = interpretedFindings.some(
          (f) => f.severity === 'high' || f.severity === 'critical'
        );
        const exitCode = hasHighOrCritical ? 1 : 0;

        const scanResult: ScanResult = {
          targetUrl,
          profile: config.profile,
          startedAt,
          completedAt,
          pagesScanned: pages.length,
          rawFindings: allRawFindings,
          interpretedFindings,
          summary,
          recon,
          attackPlan,
          validatedFindings: validations,
          exitCode,
          scanDuration,
          checksRun,
        };

        // ─── Phase 8: Output Reports ─────────────────────────────
        log.info('Phase 8: Writing reports...');

        if (formats.includes('terminal')) {
          printTerminalReport(scanResult);
        }

        if (formats.includes('json')) {
          const jsonPath = join(outputDir, `secbot-${scanId}.json`);
          writeJsonReport(scanResult, jsonPath);
        }

        if (formats.includes('html')) {
          const htmlPath = join(outputDir, `secbot-${scanId}.html`);
          writeHtmlReport(scanResult, htmlPath);
        }

        if (formats.includes('bounty')) {
          const bountyPath = join(outputDir, `secbot-${scanId}-bounty.md`);
          writeBountyReport(scanResult, bountyPath);
        }

        // Flush request log
        requestLogger?.flush();

        process.exitCode = exitCode;

        log.info('Scan complete!');
      } finally {
        // Always close browser
        await closeBrowser(browser);
      }
    } catch (err) {
      log.error(`Scan failed: ${(err as Error).message}`);
      if (options.verbose) {
        console.error(err);
      }
      process.exit(2);
    }
  });

program.parse();

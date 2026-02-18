#!/usr/bin/env node
import { config as loadEnv } from 'dotenv';
loadEnv({ path: '.env.local', override: false });
loadEnv({ override: false }); // fallback to .env

import { program } from 'commander';
import chalk from 'chalk';
import { resolve, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { crawl } from './scanner/browser.js';
import { runPassiveChecks } from './scanner/passive.js';
import { runActiveChecks } from './scanner/active.js';
import { interpretFindings, type AIProvider } from './ai/interpreter.js';
import { printTerminalReport } from './reporter/terminal.js';
import { writeJsonReport } from './reporter/json.js';
import { writeHtmlReport } from './reporter/html.js';
import { buildConfig } from './config/defaults.js';
import { log, setLogLevel } from './utils/logger.js';
import type { ScanConfig, ScanProfile, ScanResult } from './scanner/types.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));

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
  .option('-f, --format <formats>', 'Output formats: terminal,json,html (comma-separated)', 'terminal')
  .option('-o, --output <path>', 'Output directory for reports', './secbot-reports')
  .option('--max-pages <n>', 'Maximum pages to crawl', undefined)
  .option('--timeout <ms>', 'Per-page timeout in milliseconds', undefined)
  .option('--ignore-robots', 'Ignore robots.txt restrictions', false)
  .option('--ai-provider <provider>', 'AI provider: auto, ollama, anthropic, none (default: auto)', 'auto')
  .option('--ollama-model <model>', 'Ollama model to use (default: auto-detect)', undefined)
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

      // In non-interactive mode, proceed. In interactive mode, ask for consent
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
    const config = buildConfig(targetUrl, {
      profile: options.profile as ScanProfile,
      authStorageState: options.auth as string | undefined,
      outputFormat: formats,
      outputPath: options.output as string,
      respectRobots: !options.ignoreRobots,
      ...(options.maxPages ? { maxPages: parseInt(options.maxPages as string, 10) } : {}),
      ...(options.timeout ? { timeout: parseInt(options.timeout as string, 10) } : {}),
    });

    const startedAt = new Date().toISOString();

    try {
      // Phase 1: Crawl
      log.info('Phase 1: Crawling target...');
      const { pages, responses } = await crawl(config);

      if (pages.length === 0) {
        console.log(chalk.yellow('No pages were successfully crawled. Check the URL and try again.'));
        process.exit(1);
      }

      // Phase 2: Passive scanning
      log.info('Phase 2: Running passive security checks...');
      const passiveFindings = runPassiveChecks(pages, responses);

      // Phase 3: Active scanning
      log.info('Phase 3: Running active security checks...');
      const activeFindings = await runActiveChecks(pages, config);

      const allRawFindings = [...passiveFindings, ...activeFindings];

      // Phase 4: AI interpretation
      const aiProvider: AIProvider = options.ai === false ? 'none' : (options.aiProvider as AIProvider);
      log.info(`Phase 4: AI interpretation (provider: ${aiProvider})...`);
      const interpreted = await interpretFindings(targetUrl, allRawFindings, {
        provider: aiProvider,
        ollamaModel: options.ollamaModel as string,
      });
      const { findings: interpretedFindings, summary } = interpreted;

      const completedAt = new Date().toISOString();

      const scanResult: ScanResult = {
        targetUrl,
        profile: config.profile,
        startedAt,
        completedAt,
        pagesScanned: pages.length,
        rawFindings: allRawFindings,
        interpretedFindings,
        summary,
      };

      // Phase 5: Report
      log.info('Phase 5: Generating reports...');

      if (formats.includes('terminal')) {
        printTerminalReport(scanResult);
      }

      const outputDir = resolve(config.outputPath ?? './secbot-reports');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

      if (formats.includes('json')) {
        const jsonPath = join(outputDir, `secbot-${timestamp}.json`);
        writeJsonReport(scanResult, jsonPath);
      }

      if (formats.includes('html')) {
        const htmlPath = join(outputDir, `secbot-${timestamp}.html`);
        writeHtmlReport(scanResult, htmlPath);
      }

      log.info('Scan complete!');
    } catch (err) {
      log.error(`Scan failed: ${(err as Error).message}`);
      if (options.verbose) {
        console.error(err);
      }
      process.exit(1);
    }
  });

program.parse();

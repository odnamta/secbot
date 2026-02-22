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
import { runActiveChecks, CHECK_REGISTRY, loadAndRegisterPlugins } from './scanner/active/index.js';
import { runRecon } from './scanner/recon.js';
import { planAttack } from './ai/planner.js';
import { validateFindings } from './ai/validator.js';
import { generateReport } from './ai/reporter.js';
import { getTokenUsage } from './ai/client.js';
import { printTerminalReport } from './reporter/terminal.js';
import { writeJsonReport } from './reporter/json.js';
import { writeHtmlReport } from './reporter/html.js';
import { writeBountyReport } from './reporter/bounty.js';
import { writeSarifReport } from './reporter/sarif.js';
import { writeJunitReport } from './reporter/junit.js';
import { writeBurpExport } from './reporter/burp-xml.js';
import { writeHarExport } from './reporter/har.js';
import { buildConfig } from './config/defaults.js';
import { loadConfigFile } from './config/file.js';
import { parseScopePatterns } from './utils/scope.js';
import { RequestLogger } from './utils/request-logger.js';
import { log, setLogLevel } from './utils/logger.js';
import { deduplicateFindings } from './utils/dedup.js';
import { loadBaseline, diffFindings, saveBaseline } from './utils/baseline.js';
import { discoverRoutes } from './scanner/discovery/index.js';
import { validateCliOptions } from './utils/cli-validation.js';
import { CallbackServer } from './scanner/oob/callback-server.js';
import { waitForDelayedCallbacks, getDefaultWaitMs } from './scanner/oob/delayed-detection.js';
import { startInteractiveMode } from './interactive/repl.js';
import { authenticate } from './scanner/auth/authenticator.js';
import type { ScanConfig, ScanProfile, ScanResult, CheckCategory, AuthOptions } from './scanner/types.js';

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
  .argument('[url]', 'Target URL to scan (or set "target" in config file)')
  .option('-p, --profile <profile>', 'Scan profile: quick, standard, deep', 'standard')
  .option('-a, --auth <path>', 'Path to Playwright storage state JSON for authenticated scanning')
  .option('--idor-alt-auth <path>', 'Second user auth state for IDOR testing (requires --auth)')
  .option('-f, --format <formats>', 'Output formats: terminal,json,html,bounty,sarif,junit (comma-separated)', 'terminal')
  .option('-o, --output <path>', 'Output directory for reports', './secbot-reports')
  .option('--max-pages <n>', 'Maximum pages to crawl', undefined)
  .option('--timeout <ms>', 'Per-page timeout in milliseconds', undefined)
  .option('--ignore-robots', 'Ignore robots.txt restrictions', false)
  .option('--scope <patterns>', 'Scope patterns: "*.example.com,-admin.example.com"')
  .option('--urls <file>', 'File with URLs to scan (one per line)')
  .option('--log-requests', 'Log all HTTP requests for accountability', false)
  .option('--callback-url <url>', 'Callback URL for blind SSRF detection (e.g., your Burp Collaborator URL)')
  .option('--rate-limit <n>', 'Maximum requests per second (integer)', undefined)
  .option('--exclude-checks <checks>', 'Comma-separated list of check names to skip (e.g., "traversal,cmdi,sqli")')
  .option('--baseline <file>', 'Path to baseline JSON file — only report new findings')
  .option('--proxy <url>', 'HTTP or SOCKS5 proxy URL (e.g. http://host:8080 or socks5://host:1080)')
  .option('--export-burp', 'Export captured traffic as Burp Suite XML (requires --log-requests)', false)
  .option('--export-har', 'Export captured traffic as HAR 1.2 file (requires --log-requests)', false)
  .option('--login-url <url>', 'URL of login page for credential-based authentication')
  .option('--credentials <user:pass>', 'Username:password pair for login (use with --login-url)')
  .option('--credentials-file <path>', 'Path to file containing credentials (user:pass on first line)')
  .option('--callback-server <port>', 'Auto-start built-in OOB callback server on specified port')
  .option('--oob-wait <seconds>', 'How long to wait for delayed OOB callbacks (default: 30)')
  .option('--no-ai', 'Skip AI interpretation (use rule-based fallback)')
  .option('--verbose', 'Enable verbose logging', false)
  .action(async (url: string | undefined, options: Record<string, unknown>) => {
    if (options.verbose) {
      setLogLevel('debug');
    }

    log.banner();

    // Load config file early (needed for target fallback)
    const fileConfig = loadConfigFile();

    // Resolve URL: CLI arg > config file target
    const rawUrl = url ?? fileConfig?.target;
    if (!rawUrl) {
      console.error(chalk.red('No target URL provided. Pass a URL argument or set "target" in a config file.'));
      process.exit(1);
    }

    // Validate URL
    let targetUrl: string;
    try {
      const parsed = new URL(rawUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs are supported');
      }
      targetUrl = parsed.href;
    } catch {
      console.error(chalk.red(`Invalid URL: ${rawUrl}`));
      process.exit(1);
    }

    // Validate CLI options
    const validationErrors = validateCliOptions({
      profile: options.profile as string | undefined,
      auth: options.auth as string | undefined,
      urls: options.urls as string | undefined,
      maxPages: options.maxPages as string | undefined,
      timeout: options.timeout as string | undefined,
      rateLimit: options.rateLimit as string | undefined,
    });
    if (validationErrors.length > 0) {
      for (const err of validationErrors) {
        console.error(chalk.red(`${err.field}: ${err.message}`));
      }
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

    // Build config — merge: CLI args > config file > defaults
    const formatStr = options.format as string;
    // Commander sets default 'terminal' — detect if user explicitly passed --format
    const cliFormats = formatStr;
    const effectiveFormat = cliFormats ?? fileConfig?.format ?? 'terminal';
    const formats = effectiveFormat.split(',').map((f: string) => f.trim()) as ScanConfig['outputFormat'];

    const scopeStr = (options.scope as string | undefined) ?? fileConfig?.scope;
    const scope = scopeStr ? parseScopePatterns(scopeStr) : undefined;

    // --no-ai: commander sets options.ai to false when --no-ai is passed
    const useAI = options.ai === false ? false : (fileConfig?.noAi === true ? false : true);

    // Parse --exclude-checks (CLI overrides config file)
    const excludeChecksStr = options.excludeChecks as string | undefined;
    const excludeChecks = excludeChecksStr
      ? excludeChecksStr.split(',').map((s) => s.trim()).filter(Boolean)
      : fileConfig?.excludeChecks;

    // --export-burp / --export-har auto-enable --log-requests
    const exportBurp = options.exportBurp === true;
    const exportHar = options.exportHar === true;
    const logRequests = options.logRequests === true || fileConfig?.logRequests === true || exportBurp || exportHar;

    // Parse --login-url + credentials into AuthOptions
    // Priority: --credentials > --credentials-file > SECBOT_CREDENTIALS env var
    let authOpts: AuthOptions | undefined;
    const loginUrl = options.loginUrl as string | undefined;
    const cliCredentials = options.credentials as string | undefined;
    const credentialsFile = options.credentialsFile as string | undefined;

    let resolvedCredentials: string | undefined;

    if (cliCredentials) {
      // Highest priority: --credentials CLI flag
      log.warn('WARNING: Credentials passed via CLI are visible in process list and shell history.');
      log.warn('Consider using --credentials-file or SECBOT_CREDENTIALS env var instead.');
      resolvedCredentials = cliCredentials;
    } else if (credentialsFile) {
      // Second priority: --credentials-file
      try {
        const fileContent = readFileSync(resolve(credentialsFile), 'utf-8');
        const firstLine = fileContent.split('\n')[0]?.trim();
        if (!firstLine) {
          console.error(chalk.red('--credentials-file is empty or has no content on first line'));
          process.exit(1);
        }
        resolvedCredentials = firstLine;
      } catch (err) {
        console.error(chalk.red(`Failed to read credentials file: ${(err as Error).message}`));
        process.exit(1);
      }
    } else if (process.env.SECBOT_CREDENTIALS) {
      // Lowest priority: SECBOT_CREDENTIALS environment variable
      resolvedCredentials = process.env.SECBOT_CREDENTIALS.trim();
    }

    if (loginUrl && resolvedCredentials) {
      const colonIdx = resolvedCredentials.indexOf(':');
      if (colonIdx === -1) {
        console.error(chalk.red('Credentials must be in user:pass format'));
        process.exit(1);
      }
      authOpts = {
        loginUrl,
        username: resolvedCredentials.slice(0, colonIdx),
        password: resolvedCredentials.slice(colonIdx + 1),
      };
    } else if (loginUrl && !resolvedCredentials) {
      console.error(chalk.red('--login-url requires credentials (--credentials, --credentials-file, or SECBOT_CREDENTIALS env var)'));
      process.exit(1);
    } else if (!loginUrl && resolvedCredentials) {
      console.error(chalk.red('Credentials require --login-url'));
      process.exit(1);
    }

    const config = buildConfig(targetUrl, {
      profile: (options.profile as ScanProfile) ?? fileConfig?.profile,
      authStorageState: (options.auth as string | undefined) ?? fileConfig?.auth,
      idorAltAuthState: options.idorAltAuth as string | undefined,
      outputFormat: formats,
      outputPath: (options.output as string) ?? fileConfig?.output,
      respectRobots: options.ignoreRobots ? false : (fileConfig?.ignoreRobots ? false : true),
      scope,
      logRequests,
      useAI,
      callbackUrl: (options.callbackUrl as string | undefined) ?? fileConfig?.callbackUrl,
      exportBurp,
      exportHar,
      ...(excludeChecks ? { excludeChecks } : {}),
      ...(options.maxPages ? { maxPages: parseInt(options.maxPages as string, 10) }
        : fileConfig?.maxPages ? { maxPages: fileConfig.maxPages } : {}),
      ...(options.timeout ? { timeout: parseInt(options.timeout as string, 10) }
        : fileConfig?.timeout ? { timeout: fileConfig.timeout } : {}),
      ...(options.rateLimit ? { rateLimitRps: parseInt(options.rateLimit as string, 10) }
        : fileConfig?.rateLimit ? { rateLimitRps: fileConfig.rateLimit } : {}),
      ...(options.baseline ? { baselinePath: options.baseline as string }
        : fileConfig?.baseline ? { baselinePath: fileConfig.baseline } : {}),
      ...(options.proxy ? { proxy: options.proxy as string }
        : fileConfig?.proxy ? { proxy: fileConfig.proxy } : {}),
      ...(authOpts ? { auth: authOpts } : {}),
      ...(options.callbackServer ? { callbackServerPort: parseInt(options.callbackServer as string, 10) } : {}),
      ...(options.oobWait ? { oobWaitMs: parseInt(options.oobWait as string, 10) * 1000 } : {}),
      ...(fileConfig?.rateLimits ? { rateLimits: fileConfig.rateLimits } : {}),
    });

    if (config.callbackUrl) {
      log.info(`Callback URL configured: ${config.callbackUrl}`);
    }

    if (config.excludeChecks?.length) {
      log.info(`Excluding checks: ${config.excludeChecks.join(', ')}`);
    }

    if (config.proxy) {
      log.info(`Proxy configured: ${config.proxy}`);
    }

    // ─── OOB Callback Server ──────────────────────────────────
    let callbackServer: CallbackServer | undefined;
    if (config.callbackServerPort) {
      callbackServer = new CallbackServer();
      try {
        await callbackServer.start(config.callbackServerPort);
        // Auto-set callbackUrl if not already set
        if (!config.callbackUrl) {
          config.callbackUrl = `http://127.0.0.1:${config.callbackServerPort}`;
          log.info(`Callback URL auto-configured: ${config.callbackUrl}`);
        }
      } catch (err) {
        log.error(`Failed to start callback server on port ${config.callbackServerPort}: ${(err as Error).message}`);
        process.exit(2);
      }
    }

    // ─── Credential-based Authentication ─────────────────────────
    let authTmpDir: string | undefined;
    if (config.auth) {
      log.info('Authenticating with provided credentials...');
      const { chromium } = await import('playwright');
      const authBrowser = await chromium.launch({ headless: true });
      const authPage = await authBrowser.newPage();
      try {
        const authResult = await authenticate(authPage, config.auth);
        if (!authResult.success) {
          log.error(`Authentication failed: ${authResult.error}`);
          await authBrowser.close();
          process.exit(2);
        }
        if (authResult.storageState) {
          // Write storage state to a temp file so crawl() can consume it
          const { mkdtempSync, writeFileSync: writeFileSyncFs } = await import('node:fs');
          const { join: joinPath } = await import('node:path');
          authTmpDir = mkdtempSync(joinPath((await import('node:os')).tmpdir(), 'secbot-auth-'));
          const storageStatePath = joinPath(authTmpDir, 'storage-state.json');
          writeFileSyncFs(storageStatePath, authResult.storageState, { encoding: 'utf-8', mode: 0o600 });
          config.authStorageState = storageStatePath;
          log.info('Authentication successful — session captured');
        }
      } finally {
        await authBrowser.close();
      }
    }

    const scanId = new Date().toISOString().replace(/[:.]/g, '-');
    const outputDir = resolve(config.outputPath ?? './secbot-reports');
    const startedAt = new Date().toISOString();

    // Set up request logger (opt-in)
    const requestLogger = config.logRequests
      ? new RequestLogger(outputDir, scanId)
      : undefined;

    try {
      // ─── Load Plugins ────────────────────────────────────────────
      await loadAndRegisterPlugins();

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

        // Pass WAF detection to config so active checks can use WAF-aware encoding
        config.wafDetection = recon.waf;

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

        // ─── Baseline diff ─────────────────────────────────────
        let findingsForValidation = dedupedFindings;
        if (config.baselinePath) {
          try {
            const { existsSync } = await import('node:fs');
            if (existsSync(config.baselinePath)) {
              const baseline = loadBaseline(config.baselinePath);
              const newFindings = diffFindings(dedupedFindings, baseline);
              log.info(`${newFindings.length} findings are new (${baseline.length} in baseline, ${dedupedFindings.length} total)`);
              findingsForValidation = newFindings;
            } else {
              log.info(`Baseline file not found at ${config.baselinePath} — treating all findings as new`);
            }
          } catch (err) {
            log.warn(`Failed to load baseline: ${(err as Error).message} — treating all findings as new`);
          }
        }

        // ─── Phase 6: AI Validation ──────────────────────────────
        let validations;
        if (config.useAI && findingsForValidation.length > 0) {
          log.info('Phase 6: AI validating findings...');
          validations = await validateFindings(targetUrl, findingsForValidation, recon);
        } else {
          log.info(config.useAI ? 'Phase 6: No findings to validate' : 'Phase 6: Skipping AI validation (--no-ai)');
          // Fallback: mark all as valid
          validations = findingsForValidation.map((f) => ({
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
          findingsForValidation,
          validations,
          recon,
        );

        const completedAt = new Date().toISOString();

        // Compute new output fields
        const scanDuration = new Date(completedAt).getTime() - new Date(startedAt).getTime();

        // Determine which checks ran
        const passiveCheckNames: CheckCategory[] = ['security-headers', 'cookie-flags', 'info-leakage', 'mixed-content', 'sensitive-url-data', 'cross-origin-policy'];
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
        const passedChecks = checksRun.filter((name) => !categoriesWithFindings.has(name as CheckCategory));

        // Include passedChecks in the summary
        summary.passedChecks = passedChecks;

        const hasHighOrCritical = interpretedFindings.some(
          (f) => f.severity === 'high' || f.severity === 'critical'
        );
        const exitCode = hasHighOrCritical ? 1 : 0;

        // ─── Token Usage ──────────────────────────────────────────
        const tokenUsage = getTokenUsage();
        if (tokenUsage.totalTokens > 0) {
          log.info(`AI tokens used: ${tokenUsage.totalTokens} (input: ${tokenUsage.inputTokens}, output: ${tokenUsage.outputTokens})`);
        }

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
          ...(tokenUsage.totalTokens > 0 ? { tokenUsage } : {}),
          ...(config.callbackUrl ? { callbackUrl: config.callbackUrl } : {}),
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

        if (formats.includes('sarif')) {
          const sarifPath = join(outputDir, `secbot-${scanId}.sarif`);
          writeSarifReport(scanResult, sarifPath);
        }

        if (formats.includes('junit')) {
          const junitPath = join(outputDir, `secbot-${scanId}-junit.xml`);
          writeJunitReport(scanResult, junitPath);
        }

        // Flush request log before reading entries for export
        requestLogger?.flush();

        // Export traffic captures (Burp XML / HAR)
        if (requestLogger && (config.exportBurp || config.exportHar)) {
          const capturedEntries = requestLogger.readAllEntries();

          if (config.exportBurp) {
            const burpPath = join(outputDir, `secbot-${scanId}.burp.xml`);
            writeBurpExport(capturedEntries, burpPath);
          }

          if (config.exportHar) {
            const harPath = join(outputDir, `secbot-${scanId}.har`);
            writeHarExport(capturedEntries, harPath);
          }
        }

        // Save current findings as baseline for future diff
        const baselineOutPath = join(outputDir, 'secbot-baseline.json');
        saveBaseline(dedupedFindings, baselineOutPath);
        log.info(`Baseline saved: ${baselineOutPath}`);

        process.exitCode = exitCode;

        // Post-scan callback URL reminder
        if (config.callbackUrl && !callbackServer) {
          log.info('Callback URLs injected for blind detection. Check your callback server for hits.');
          log.info(`Callback URL prefix: ${config.callbackUrl}`);
        }

        // ─── OOB Delayed Detection ─────────────────────────────
        if (callbackServer) {
          const oobWait = config.oobWaitMs ?? getDefaultWaitMs();
          const delayedHits = await waitForDelayedCallbacks(callbackServer, oobWait);
          const allHits = callbackServer.getHits();

          if (allHits.length > 0) {
            log.info(`OOB callback server received ${allHits.length} total hit(s):`);
            for (const hit of allHits) {
              log.info(`  ${hit.method} ${hit.path} from ${hit.sourceIp} at ${hit.timestamp} (payload: ${hit.payloadId})`);
            }
          } else {
            log.info('OOB callback server received no hits during scan');
          }

          await callbackServer.stop();
        }

        log.info('Scan complete!');
      } finally {
        // Always close browser
        await closeBrowser(browser);
        // Clean up auth temp files (contains session tokens — must not persist)
        if (authTmpDir) {
          try {
            const { rmSync } = await import('node:fs');
            rmSync(authTmpDir, { recursive: true, force: true });
            log.debug('Cleaned up auth temp files');
          } catch {
            log.warn(`Failed to clean up auth temp dir: ${authTmpDir}`);
          }
        }
      }
    } catch (err) {
      // Clean up callback server on error
      if (callbackServer?.isRunning()) {
        try { await callbackServer.stop(); } catch { /* best effort */ }
      }
      // Clean up auth temp files on error path too
      if (authTmpDir) {
        try {
          const { rmSync } = await import('node:fs');
          rmSync(authTmpDir, { recursive: true, force: true });
        } catch { /* best effort */ }
      }
      log.error(`Scan failed: ${(err as Error).message}`);
      if (options.verbose) {
        console.error(err);
      }
      process.exit(2);
    }
  });

program
  .command('interactive')
  .description('Interactive security testing REPL')
  .argument('<url>', 'Target URL')
  .option('-p, --profile <profile>', 'Scan profile: quick, standard, deep', 'standard')
  .option('-a, --auth <path>', 'Path to Playwright storage state JSON for authenticated scanning')
  .option('-o, --output <path>', 'Output directory for reports', './secbot-reports')
  .option('--scope <patterns>', 'Scope patterns: "*.example.com,-admin.example.com"')
  .option('--proxy <url>', 'HTTP or SOCKS5 proxy URL')
  .option('--verbose', 'Enable verbose logging', false)
  .action(async (url: string, options: Record<string, unknown>) => {
    if (options.verbose) {
      setLogLevel('debug');
    }

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

    const scopeStr = options.scope as string | undefined;
    const scope = scopeStr ? parseScopePatterns(scopeStr) : undefined;

    const config = buildConfig(targetUrl, {
      profile: (options.profile as ScanProfile) ?? 'standard',
      authStorageState: options.auth as string | undefined,
      outputPath: (options.output as string) ?? './secbot-reports',
      scope,
      useAI: true,
      logRequests: false,
      ...(options.proxy ? { proxy: options.proxy as string } : {}),
    });

    try {
      await startInteractiveMode(targetUrl, config);
    } catch (err) {
      log.error(`Interactive mode failed: ${(err as Error).message}`);
      if (options.verbose) {
        console.error(err);
      }
      process.exit(2);
    }
  });

program.parse();

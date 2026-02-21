import { createInterface, type Interface } from 'node:readline';
import chalk from 'chalk';
import { resolve, join } from 'node:path';
import { crawl, closeBrowser, type CrawlResult } from '../scanner/browser.js';
import { runPassiveChecks } from '../scanner/passive.js';
import { runActiveChecks, CHECK_REGISTRY } from '../scanner/active/index.js';
import { runRecon } from '../scanner/recon.js';
import { captureScreenshot } from '../scanner/screenshot.js';
import { formatForHackerOne, formatForBugcrowd } from '../reporter/bounty-export.js';
import { deduplicateFindings } from '../utils/dedup.js';
import { generateReport } from '../ai/reporter.js';
import { log } from '../utils/logger.js';
import type {
  ScanConfig,
  RawFinding,
  InterpretedFinding,
  CrawledPage,
  InterceptedResponse,
  ReconResult,
} from '../scanner/types.js';

/** All available REPL commands */
export const REPL_COMMANDS = [
  { name: 'scan', description: 'Run full security scan' },
  { name: 'crawl', description: 'Crawl target, show discovered pages' },
  { name: 'check <name>', description: 'Run a specific check (xss, sqli, cors, redirect, traversal, ssrf, ssti, cmdi, idor, tls, sri)' },
  { name: 'recon', description: 'Run reconnaissance only' },
  { name: 'findings', description: 'Show current accumulated findings' },
  { name: 'export [hackerone|bugcrowd]', description: 'Export findings in bounty platform format' },
  { name: 'screenshot <url>', description: 'Take a full-page screenshot of a URL' },
  { name: 'help', description: 'Show available commands' },
  { name: 'quit', description: 'Close browser and exit' },
] as const;

/** Parse a raw input line into command + args */
export function parseCommand(input: string): { command: string; args: string } {
  const trimmed = input.trim();
  const spaceIndex = trimmed.indexOf(' ');
  if (spaceIndex === -1) {
    return { command: trimmed.toLowerCase(), args: '' };
  }
  return {
    command: trimmed.slice(0, spaceIndex).toLowerCase(),
    args: trimmed.slice(spaceIndex + 1).trim(),
  };
}

/** Format the help text */
export function formatHelp(): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(chalk.bold('Available commands:'));
  lines.push('');
  for (const cmd of REPL_COMMANDS) {
    lines.push(`  ${chalk.cyan(cmd.name.padEnd(30))} ${cmd.description}`);
  }
  lines.push('');
  return lines.join('\n');
}

/** Format findings for display */
export function formatFindingsSummary(findings: RawFinding[]): string {
  if (findings.length === 0) {
    return chalk.gray('  No findings yet. Run a scan or check first.');
  }

  const lines: string[] = [];
  const deduped = deduplicateFindings(findings);

  lines.push('');
  lines.push(chalk.bold(`Findings: ${deduped.length} unique (${findings.length} raw)`));
  lines.push('');

  // Group by severity
  const bySeverity: Record<string, RawFinding[]> = {};
  for (const f of deduped) {
    if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
    bySeverity[f.severity].push(f);
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    const group = bySeverity[sev];
    if (!group || group.length === 0) continue;

    const colorFn =
      sev === 'critical' ? chalk.bgRed.white :
      sev === 'high' ? chalk.red :
      sev === 'medium' ? chalk.yellow :
      sev === 'low' ? chalk.cyan :
      chalk.gray;

    for (const f of group) {
      lines.push(`  ${colorFn(`[${sev.toUpperCase()}]`)} ${f.title}`);
      lines.push(`    ${chalk.gray(f.url)}`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

/** Interactive REPL session state */
interface ReplState {
  crawlResult: CrawlResult | null;
  pages: CrawledPage[];
  responses: InterceptedResponse[];
  recon: ReconResult | null;
  rawFindings: RawFinding[];
  interpretedFindings: InterpretedFinding[];
}

/**
 * Start the interactive security testing REPL.
 * Browser stays open between commands; findings accumulate.
 */
export async function startInteractiveMode(
  targetUrl: string,
  config: ScanConfig,
): Promise<void> {
  const state: ReplState = {
    crawlResult: null,
    pages: [],
    responses: [],
    recon: null,
    rawFindings: [],
    interpretedFindings: [],
  };

  const outputDir = resolve(config.outputPath ?? './secbot-reports');

  console.log(chalk.bold.cyan(`
  ╔═══════════════════════════════════════╗
  ║       SecBot Interactive Mode         ║
  ╚═══════════════════════════════════════╝
`));
  console.log(`  Target: ${chalk.bold(targetUrl)}`);
  console.log(`  Profile: ${config.profile}`);
  console.log(`  Type ${chalk.cyan('help')} for available commands.`);
  console.log('');

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: chalk.green('secbot> '),
  });

  rl.prompt();

  for await (const line of rl) {
    const { command, args } = parseCommand(line);

    if (!command) {
      rl.prompt();
      continue;
    }

    try {
      switch (command) {
        case 'help':
          console.log(formatHelp());
          break;

        case 'quit':
        case 'exit':
          console.log(chalk.gray('Shutting down...'));
          if (state.crawlResult) {
            await closeBrowser(state.crawlResult.browser);
          }
          rl.close();
          return;

        case 'crawl':
          console.log(chalk.blue('Crawling target...'));
          if (state.crawlResult) {
            await closeBrowser(state.crawlResult.browser);
          }
          state.crawlResult = await crawl(config);
          state.pages = state.crawlResult.pages;
          state.responses = state.crawlResult.responses;
          console.log(chalk.green(`Crawled ${state.pages.length} pages:`));
          for (const page of state.pages) {
            console.log(`  ${chalk.cyan(page.url)} [${page.status}] ${page.title}`);
          }
          console.log('');
          break;

        case 'recon':
          if (state.pages.length === 0) {
            console.log(chalk.yellow('No pages crawled yet. Run "crawl" first.'));
            break;
          }
          console.log(chalk.blue('Running reconnaissance...'));
          state.recon = runRecon(state.pages, state.responses);
          console.log(chalk.green('Recon complete:'));
          console.log(`  Technologies: ${state.recon.techStack.detected.join(', ') || 'none detected'}`);
          console.log(`  WAF: ${state.recon.waf.detected ? state.recon.waf.name : 'none detected'}`);
          console.log(`  Framework: ${state.recon.framework.name ?? 'unknown'}`);
          console.log(`  API routes: ${state.recon.endpoints.apiRoutes.length}`);
          console.log(`  Forms: ${state.recon.endpoints.forms.length}`);
          console.log('');
          break;

        case 'scan': {
          console.log(chalk.blue('Running full scan...'));
          // Crawl if not done
          if (state.pages.length === 0) {
            console.log(chalk.blue('  Step 1/4: Crawling...'));
            if (state.crawlResult) {
              await closeBrowser(state.crawlResult.browser);
            }
            state.crawlResult = await crawl(config);
            state.pages = state.crawlResult.pages;
            state.responses = state.crawlResult.responses;
            console.log(chalk.green(`  Crawled ${state.pages.length} pages`));
          }

          // Recon
          console.log(chalk.blue('  Step 2/4: Reconnaissance...'));
          state.recon = runRecon(state.pages, state.responses);

          // Passive checks
          console.log(chalk.blue('  Step 3/4: Passive checks...'));
          const passiveFindings = runPassiveChecks(state.pages, state.responses);
          state.rawFindings.push(...passiveFindings);

          // Active checks
          if (state.crawlResult) {
            console.log(chalk.blue('  Step 4/4: Active checks...'));
            const activeFindings = await runActiveChecks(
              state.crawlResult.context,
              state.pages,
              config,
            );
            state.rawFindings.push(...activeFindings);
          }

          const deduped = deduplicateFindings(state.rawFindings);
          console.log(chalk.green(`Scan complete: ${deduped.length} unique findings`));
          console.log(formatFindingsSummary(state.rawFindings));
          break;
        }

        case 'check': {
          if (!args) {
            console.log(chalk.yellow('Usage: check <name>'));
            console.log(`  Available: ${CHECK_REGISTRY.map((c) => c.name).join(', ')}`);
            break;
          }

          const checkName = args.toLowerCase();
          const check = CHECK_REGISTRY.find((c) => c.name === checkName);
          if (!check) {
            console.log(chalk.red(`Unknown check: ${checkName}`));
            console.log(`  Available: ${CHECK_REGISTRY.map((c) => c.name).join(', ')}`);
            break;
          }

          if (state.pages.length === 0) {
            console.log(chalk.yellow('No pages crawled yet. Run "crawl" first.'));
            break;
          }

          if (!state.crawlResult) {
            console.log(chalk.yellow('Browser context not available. Run "crawl" first.'));
            break;
          }

          console.log(chalk.blue(`Running ${checkName} check...`));
          const { buildTargets } = await import('../scanner/active/index.js');
          const targets = buildTargets(state.pages, config.targetUrl, config.scope);
          const checkFindings = await check.run(
            state.crawlResult.context,
            targets,
            config,
          );
          state.rawFindings.push(...checkFindings);
          console.log(chalk.green(`${checkName}: ${checkFindings.length} findings`));
          for (const f of checkFindings) {
            log.finding(f.severity, f.title);
          }
          console.log('');
          break;
        }

        case 'findings':
          console.log(formatFindingsSummary(state.rawFindings));
          break;

        case 'export': {
          const platform = args.toLowerCase() || 'hackerone';
          if (platform !== 'hackerone' && platform !== 'bugcrowd') {
            console.log(chalk.yellow('Usage: export [hackerone|bugcrowd]'));
            break;
          }

          // Generate interpreted findings if we haven't yet
          if (state.interpretedFindings.length === 0 && state.rawFindings.length > 0) {
            console.log(chalk.blue('Generating interpreted findings for export...'));
            const deduped = deduplicateFindings(state.rawFindings);
            const validations = deduped.map((f) => ({
              findingId: f.id,
              isValid: true,
              confidence: 'medium' as const,
              reasoning: 'Interactive mode — no AI validation',
            }));
            const report = await generateReport(
              targetUrl,
              deduped,
              validations,
              state.recon ?? undefined,
            );
            state.interpretedFindings = report.findings;
          }

          if (state.interpretedFindings.length === 0) {
            console.log(chalk.yellow('No findings to export. Run a scan first.'));
            break;
          }

          const formatter = platform === 'hackerone' ? formatForHackerOne : formatForBugcrowd;
          console.log(chalk.bold(`\n--- ${platform.toUpperCase()} Export ---\n`));
          for (const finding of state.interpretedFindings) {
            console.log(formatter(finding));
            console.log('---\n');
          }
          break;
        }

        case 'screenshot': {
          if (!args) {
            console.log(chalk.yellow('Usage: screenshot <url>'));
            break;
          }

          let screenshotUrl = args;
          try {
            new URL(screenshotUrl);
          } catch {
            // Try prepending the target origin
            try {
              const origin = new URL(targetUrl).origin;
              screenshotUrl = new URL(args, origin).href;
            } catch {
              console.log(chalk.red(`Invalid URL: ${args}`));
              break;
            }
          }

          if (!state.crawlResult) {
            console.log(chalk.yellow('No browser context. Run "crawl" first.'));
            break;
          }

          console.log(chalk.blue(`Taking screenshot of ${screenshotUrl}...`));
          const page = await state.crawlResult.context.newPage();
          try {
            await page.goto(screenshotUrl, {
              waitUntil: 'networkidle',
              timeout: 15000,
            });
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const outPath = join(outputDir, `screenshot-${timestamp}.png`);
            await captureScreenshot(page, outPath);
            console.log(chalk.green(`Screenshot saved: ${outPath}`));
          } catch (err) {
            console.log(chalk.red(`Screenshot failed: ${(err as Error).message}`));
          } finally {
            await page.close();
          }
          console.log('');
          break;
        }

        default:
          console.log(chalk.yellow(`Unknown command: ${command}. Type "help" for available commands.`));
          break;
      }
    } catch (err) {
      console.log(chalk.red(`Error: ${(err as Error).message}`));
    }

    rl.prompt();
  }

  // Handle stream close (e.g., Ctrl+D)
  if (state.crawlResult) {
    await closeBrowser(state.crawlResult.browser);
  }
}

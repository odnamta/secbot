/**
 * Scan orchestrator — runs autonomous bounty hunting across registered programs.
 * Sequential scanning, schedule-based, with escalation queue integration.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { Program, HuntSummary } from './types.js';
import { loadRegistry, isDue } from './registry.js';
import { EscalationQueue } from './escalation.js';
import { formatHuntSummary, sendNotification } from './notify.js';
import { log } from '../utils/logger.js';

/**
 * Filter programs that are due for scanning based on their schedule.
 */
export function getDuePrograms(programs: Program[]): Program[] {
  return programs.filter(p => {
    if (p.enabled === false) return false;
    return isDue(p.schedule, p.lastScan);
  });
}

export interface OrchestratorOptions {
  registryPath: string;
  resultsDir?: string;
  queueDir?: string;
  dryRun?: boolean;
}

export interface ProgramScanResult {
  program: string;
  findings: { high: number; medium: number; low: number };
  escalations: number;
  duration: number; // ms
  error?: string;
}

/**
 * Orchestrator runs scans sequentially across due programs.
 * It does NOT import the scan function directly — instead it accepts
 * a scan callback so the caller wires up the actual scanner.
 */
export class Orchestrator {
  private options: OrchestratorOptions;
  private resultsDir: string;
  private queueDir: string;

  constructor(options: OrchestratorOptions) {
    this.options = options;
    this.resultsDir = options.resultsDir ?? join(homedir(), '.secbot', 'results');
    this.queueDir = options.queueDir ?? join(homedir(), '.secbot', 'queue');
  }

  /**
   * Run the hunt — scan all due programs sequentially.
   * @param scanFn - callback that runs a scan for a given program, returns findings count + escalation queue
   */
  async hunt(
    scanFn: (program: Program) => Promise<ProgramScanResult>,
  ): Promise<HuntSummary> {
    const startTime = Date.now();
    const programs = await loadRegistry(this.options.registryPath);
    const due = getDuePrograms(programs);

    if (due.length === 0) {
      log.info('No programs due for scanning');
      return {
        programs: 0,
        findings: { high: 0, medium: 0, low: 0 },
        escalations: 0,
        duration: '0s',
        scannedAt: new Date().toISOString(),
      };
    }

    if (this.options.dryRun) {
      log.info(`Dry run — would scan ${due.length} programs: ${due.map(p => p.name).join(', ')}`);
      return {
        programs: due.length,
        findings: { high: 0, medium: 0, low: 0 },
        escalations: 0,
        duration: '0s',
        scannedAt: new Date().toISOString(),
      };
    }

    const results: ProgramScanResult[] = [];
    const totalFindings = { high: 0, medium: 0, low: 0 };
    let totalEscalations = 0;

    // Sequential scanning
    for (const program of due) {
      log.info(`Scanning: ${program.name} (${program.platform})`);
      try {
        const result = await scanFn(program);
        results.push(result);
        totalFindings.high += result.findings.high;
        totalFindings.medium += result.findings.medium;
        totalFindings.low += result.findings.low;
        totalEscalations += result.escalations;

        // Save result
        await this.saveResult(program.name, result);
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        log.error(`Failed to scan ${program.name}: ${error}`);
        results.push({
          program: program.name,
          findings: { high: 0, medium: 0, low: 0 },
          escalations: 0,
          duration: 0,
          error,
        });
      }
    }

    const elapsed = Date.now() - startTime;
    const summary: HuntSummary = {
      programs: due.length,
      findings: totalFindings,
      escalations: totalEscalations,
      duration: formatElapsed(elapsed),
      scannedAt: new Date().toISOString(),
    };

    // Send notification
    await sendNotification(summary);

    // Save hunt summary
    await this.saveSummary(summary);

    return summary;
  }

  private async saveResult(programName: string, result: ProgramScanResult): Promise<void> {
    const date = new Date().toISOString().split('T')[0];
    const dir = join(this.resultsDir, programName);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, `${date}.json`), JSON.stringify(result, null, 2));
  }

  private async saveSummary(summary: HuntSummary): Promise<void> {
    const date = new Date().toISOString().split('T')[0];
    const dir = join(this.resultsDir, '_summaries');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, `${date}.json`), JSON.stringify(summary, null, 2));
  }
}

function formatElapsed(ms: number): string {
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  return `${Math.round(ms / 3600000)}h ${Math.round((ms % 3600000) / 60000)}m`;
}

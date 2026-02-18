import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ScanResult } from '../scanner/types.js';
import { log } from '../utils/logger.js';

export function writeJsonReport(result: ScanResult, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
  log.info(`JSON report written to: ${outputPath}`);
}

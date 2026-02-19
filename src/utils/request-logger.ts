import { writeFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { RequestLogEntry } from '../scanner/types.js';
import { log } from './logger.js';

export class RequestLogger {
  private entries: RequestLogEntry[] = [];
  private outputPath: string;
  private flushed = false;

  constructor(outputDir: string, scanId: string) {
    this.outputPath = join(outputDir, scanId, 'requests.jsonl');
  }

  log(entry: RequestLogEntry): void {
    this.entries.push(entry);
  }

  /** Flush all logged requests to a JSONL file */
  flush(): void {
    if (this.flushed || this.entries.length === 0) return;

    mkdirSync(dirname(this.outputPath), { recursive: true });
    const lines = this.entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    writeFileSync(this.outputPath, lines, 'utf-8');
    this.flushed = true;

    log.info(`Request log written: ${this.entries.length} entries → ${this.outputPath}`);
  }

  get count(): number {
    return this.entries.length;
  }

  get path(): string {
    return this.outputPath;
  }
}

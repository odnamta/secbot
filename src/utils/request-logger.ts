import { mkdirSync, appendFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { RequestLogEntry } from '../scanner/types.js';
import { log } from './logger.js';

const MAX_BUFFER_SIZE = 500;

export class RequestLogger {
  private buffer: RequestLogEntry[] = [];
  private outputPath: string;
  private totalCount = 0;
  private dirCreated = false;

  constructor(outputDir: string, scanId: string) {
    this.outputPath = join(outputDir, scanId, 'requests.jsonl');
  }

  log(entry: RequestLogEntry): void {
    this.buffer.push(entry);
    this.totalCount++;

    // Auto-flush when buffer is full to prevent memory buildup
    if (this.buffer.length >= MAX_BUFFER_SIZE) {
      this.flushBuffer();
    }
  }

  /** Flush remaining entries and finalize the log */
  flush(): void {
    if (this.totalCount === 0) return;
    this.flushBuffer();
    log.info(`Request log written: ${this.totalCount} entries → ${this.outputPath}`);
  }

  private flushBuffer(): void {
    if (this.buffer.length === 0) return;

    if (!this.dirCreated) {
      mkdirSync(dirname(this.outputPath), { recursive: true });
      this.dirCreated = true;
    }

    const lines = this.buffer.map((e) => JSON.stringify(e)).join('\n') + '\n';
    appendFileSync(this.outputPath, lines, 'utf-8');
    this.buffer = [];
  }

  get count(): number {
    return this.totalCount;
  }

  get path(): string {
    return this.outputPath;
  }

  /**
   * Read all logged entries back from the JSONL file (flushed + any remaining in buffer).
   * Call flush() before this to ensure all entries are on disk.
   */
  readAllEntries(): RequestLogEntry[] {
    const entries: RequestLogEntry[] = [];

    // Read from flushed file
    if (existsSync(this.outputPath)) {
      const content = readFileSync(this.outputPath, 'utf-8');
      const lines = content.split('\n').filter((line) => line.trim().length > 0);
      for (const line of lines) {
        try {
          entries.push(JSON.parse(line) as RequestLogEntry);
        } catch {
          // skip malformed lines
        }
      }
    }

    // Include any unflushed buffer entries
    entries.push(...this.buffer);

    return entries;
  }
}

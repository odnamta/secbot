import type { FPPattern } from './types.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

export class FPMemory {
  private patterns: FPPattern[] = [];
  private filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath ?? join(homedir(), '.secbot', 'learning', 'false-positives.json');
  }

  async load(): Promise<void> {
    try {
      const data = await readFile(this.filePath, 'utf-8');
      this.patterns = JSON.parse(data);
    } catch { this.patterns = []; }
  }

  async save(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, JSON.stringify(this.patterns, null, 2));
  }

  record(entry: Omit<FPPattern, 'firstSeen' | 'lastSeen'>): void {
    const existing = this.patterns.find(p => p.category === entry.category && p.pattern === entry.pattern);
    if (existing) {
      existing.count += entry.count;
      existing.lastSeen = new Date().toISOString();
    } else {
      this.patterns.push({
        ...entry,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
      });
    }
  }

  isKnownFP(category: string, pattern: string): boolean {
    return this.patterns.some(p => p.category === category && p.pattern === pattern && p.count >= 1);
  }

  confidenceAdjustment(category: string, pattern: string): 'downgrade' | 'none' {
    const match = this.patterns.find(p => p.category === category && p.pattern === pattern);
    if (match && match.count >= 3) return 'downgrade';
    return 'none';
  }

  getPatterns(): FPPattern[] { return [...this.patterns]; }

  getPatternsForCategory(category: string): FPPattern[] {
    return this.patterns.filter(p => p.category === category);
  }
}

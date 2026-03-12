import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import type { TechRecommendation } from './types.js';

interface TechRecord {
  techStack: string[];
  category: string;
  effective: boolean;
  timestamp: string;
}

export class TechProfiler {
  private records: TechRecord[] = [];
  private filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath ?? join(homedir(), '.secbot', 'learning', 'tech-profiles.json');
  }

  async load(): Promise<void> {
    try { this.records = JSON.parse(await readFile(this.filePath, 'utf-8')); } catch { this.records = []; }
  }

  async save(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, JSON.stringify(this.records, null, 2));
  }

  record(techStack: string[], category: string, effective: boolean): void {
    this.records.push({ techStack: techStack.sort(), category, effective, timestamp: new Date().toISOString() });
  }

  recommend(techStack: string[]): TechRecommendation {
    const key = techStack.sort().join('+');
    const matching = this.records.filter(r => r.techStack.sort().join('+') === key);

    const categoryStats = new Map<string, { effective: number; total: number }>();
    for (const r of matching) {
      const s = categoryStats.get(r.category) ?? { effective: 0, total: 0 };
      s.total++;
      if (r.effective) s.effective++;
      categoryStats.set(r.category, s);
    }

    const prioritize: string[] = [];
    const deprioritize: string[] = [];
    for (const [cat, stats] of categoryStats) {
      if (stats.total >= 3) {
        const rate = stats.effective / stats.total;
        if (rate >= 0.5) prioritize.push(cat);
        else if (rate < 0.2) deprioritize.push(cat);
      }
    }

    return { prioritize, deprioritize };
  }
}

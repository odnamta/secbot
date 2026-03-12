// src/learning/outcomes.ts
import type { OutcomeRecord, OutcomeStats } from './types.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

export class OutcomeTracker {
  private records: OutcomeRecord[] = [];
  private filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath ?? join(homedir(), '.secbot', 'learning', 'outcomes.json');
  }

  async load(): Promise<void> {
    try {
      const data = await readFile(this.filePath, 'utf-8');
      this.records = JSON.parse(data);
    } catch { this.records = []; }
  }

  async save(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, JSON.stringify(this.records, null, 2));
  }

  record(entry: OutcomeRecord): void {
    this.records.push(entry);
  }

  getStats(): OutcomeStats {
    return {
      total: this.records.length,
      accepted: this.records.filter(r => r.outcome === 'accepted').length,
      duplicate: this.records.filter(r => r.outcome === 'duplicate').length,
      informative: this.records.filter(r => r.outcome === 'informative').length,
      notApplicable: this.records.filter(r => r.outcome === 'not-applicable').length,
      outOfScope: this.records.filter(r => r.outcome === 'out-of-scope').length,
      totalBounty: this.records.reduce((sum, r) => sum + (r.bounty ?? 0), 0),
    };
  }

  successRateByCategory(): Record<string, number> {
    const groups = new Map<string, { accepted: number; total: number }>();
    for (const r of this.records) {
      const g = groups.get(r.category) ?? { accepted: 0, total: 0 };
      g.total++;
      if (r.outcome === 'accepted') g.accepted++;
      groups.set(r.category, g);
    }
    const rates: Record<string, number> = {};
    for (const [cat, g] of groups) {
      rates[cat] = g.total > 0 ? g.accepted / g.total : 0;
    }
    return rates;
  }

  successRateByTechStack(): Record<string, number> {
    const groups = new Map<string, { accepted: number; total: number }>();
    for (const r of this.records) {
      const key = r.techStack.sort().join('+') || 'unknown';
      const g = groups.get(key) ?? { accepted: 0, total: 0 };
      g.total++;
      if (r.outcome === 'accepted') g.accepted++;
      groups.set(key, g);
    }
    const rates: Record<string, number> = {};
    for (const [stack, g] of groups) {
      rates[stack] = g.total > 0 ? g.accepted / g.total : 0;
    }
    return rates;
  }

  getRecords(): OutcomeRecord[] { return [...this.records]; }
}

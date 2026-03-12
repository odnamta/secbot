import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

interface PayloadRecord {
  waf: string;
  strategy: string;
  success: boolean;
  timestamp: string;
}

export class PayloadStats {
  private records: PayloadRecord[] = [];
  private filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath ?? join(homedir(), '.secbot', 'learning', 'payload-stats.json');
  }

  async load(): Promise<void> {
    try { this.records = JSON.parse(await readFile(this.filePath, 'utf-8')); } catch { this.records = []; }
  }

  async save(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, JSON.stringify(this.records, null, 2));
  }

  record(waf: string, strategy: string, success: boolean): void {
    this.records.push({ waf, strategy, success, timestamp: new Date().toISOString() });
  }

  bestStrategy(waf: string): string | undefined {
    const matching = this.records.filter(r => r.waf === waf);
    const strategyStats = new Map<string, { success: number; total: number }>();
    for (const r of matching) {
      const s = strategyStats.get(r.strategy) ?? { success: 0, total: 0 };
      s.total++;
      if (r.success) s.success++;
      strategyStats.set(r.strategy, s);
    }
    let best: string | undefined;
    let bestRate = -1;
    for (const [strategy, stats] of strategyStats) {
      const rate = stats.success / stats.total;
      if (rate > bestRate) { bestRate = rate; best = strategy; }
    }
    return best;
  }

  worstStrategy(waf: string): string | undefined {
    const matching = this.records.filter(r => r.waf === waf);
    const strategyStats = new Map<string, { success: number; total: number }>();
    for (const r of matching) {
      const s = strategyStats.get(r.strategy) ?? { success: 0, total: 0 };
      s.total++;
      if (r.success) s.success++;
      strategyStats.set(r.strategy, s);
    }
    let worst: string | undefined;
    let worstRate = 2;
    for (const [strategy, stats] of strategyStats) {
      const rate = stats.success / stats.total;
      if (rate < worstRate) { worstRate = rate; worst = strategy; }
    }
    return worst;
  }

  getStatsForWaf(waf: string): Record<string, { success: number; total: number; rate: number }> {
    const matching = this.records.filter(r => r.waf === waf);
    const result: Record<string, { success: number; total: number; rate: number }> = {};
    for (const r of matching) {
      if (!result[r.strategy]) result[r.strategy] = { success: 0, total: 0, rate: 0 };
      result[r.strategy].total++;
      if (r.success) result[r.strategy].success++;
    }
    for (const key of Object.keys(result)) {
      result[key].rate = result[key].total > 0 ? result[key].success / result[key].total : 0;
    }
    return result;
  }
}

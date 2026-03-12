import type { EscalationItem, EscalationQueueData } from './types.js';
import type { RawFinding } from '../scanner/types.js';
import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';

export class EscalationQueue {
  private items: EscalationItem[] = [];
  private target = '';
  private completed = 0;

  setTarget(target: string): void { this.target = target; }
  setCompleted(count: number): void { this.completed = count; }

  addBlocked(url: string, reason: EscalationItem['reason'], type?: string): void {
    this.items.push({ url, reason, type, timestamp: new Date().toISOString() });
  }

  addAmbiguousFinding(finding: RawFinding): void {
    this.items.push({
      url: finding.url,
      reason: 'ambiguous-finding',
      confidence: finding.confidence ?? 'medium',
      findingId: finding.id,
      timestamp: new Date().toISOString(),
    });
  }

  getItems(): EscalationItem[] { return [...this.items]; }

  toJSON(): EscalationQueueData {
    return {
      target: this.target,
      scanDate: new Date().toISOString(),
      completed: this.completed,
      needsHuman: this.items.length,
      blocked: this.items,
    };
  }

  async save(dir: string, programName: string): Promise<string> {
    const date = new Date().toISOString().split('T')[0];
    const filePath = join(dir, programName, `${date}.json`);
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, JSON.stringify(this.toJSON(), null, 2));
    return filePath;
  }

  static async load(filePath: string): Promise<EscalationQueue> {
    const data = JSON.parse(await readFile(filePath, 'utf-8')) as EscalationQueueData;
    const queue = new EscalationQueue();
    queue.target = data.target;
    queue.completed = data.completed;
    queue.items.push(...data.blocked);
    return queue;
  }
}

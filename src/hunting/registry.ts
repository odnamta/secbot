import type { Program, Schedule } from './types.js';
import { readFile, writeFile } from 'node:fs/promises';

function snakeToCamel(key: string): string {
  return key.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase());
}

function stripQuotes(value: string): string {
  return value.replace(/^["']|["']$/g, '').trim();
}

export function parseRegistry(content: string): Program[] {
  const lines = content.split('\n');
  const programs: Program[] = [];
  let current: Record<string, string> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();

    // Detect start of a new program entry
    const nameMatch = line.match(/^\s*-\s+name:\s*(.+)$/);
    if (nameMatch) {
      if (current !== null) {
        programs.push(buildProgram(current));
      }
      current = { name: stripQuotes(nameMatch[1]) };
      continue;
    }

    // Parse key: value pairs within a program block
    if (current !== null) {
      const kvMatch = line.match(/^\s+(\w+):\s*(.+)$/);
      if (kvMatch) {
        const rawKey = kvMatch[1];
        const value = stripQuotes(kvMatch[2]);
        const camelKey = snakeToCamel(rawKey);
        current[camelKey] = value;
      }
    }
  }

  // Push last program
  if (current !== null) {
    programs.push(buildProgram(current));
  }

  return programs;
}

function buildProgram(raw: Record<string, string>): Program {
  if (!raw['name']) throw new Error('Program missing required field: name');
  if (!raw['platform']) throw new Error(`Program "${raw['name']}" missing required field: platform`);
  if (!raw['schedule']) throw new Error(`Program "${raw['name']}" missing required field: schedule`);

  const program: Program = {
    name: raw['name'],
    platform: raw['platform'] as Program['platform'],
    scopeFile: raw['scopeFile'] ?? '',
    profile: (raw['profile'] as Program['profile']) ?? 'standard',
    schedule: raw['schedule'] as Schedule,
  };

  if (raw['auth']) program.auth = raw['auth'];
  if (raw['lastScan']) program.lastScan = raw['lastScan'];
  if (raw['enabled'] !== undefined) program.enabled = raw['enabled'] !== 'false';

  return program;
}

const SCHEDULE_DAYS: Record<Schedule, number> = {
  daily: 1,
  weekly: 7,
  biweekly: 14,
  monthly: 30,
};

export function isDue(schedule: Schedule, lastScan?: string): boolean {
  if (!lastScan) return true;

  const last = new Date(lastScan);
  const now = new Date();
  const diffMs = now.getTime() - last.getTime();
  const diffDays = diffMs / (1000 * 60 * 60 * 24);

  return diffDays >= SCHEDULE_DAYS[schedule];
}

export async function loadRegistry(filePath: string): Promise<Program[]> {
  const content = await readFile(filePath, 'utf-8');
  return parseRegistry(content);
}

export async function saveLastScan(
  filePath: string,
  programName: string,
  date: string,
): Promise<void> {
  const content = await readFile(filePath, 'utf-8');
  const lines = content.split('\n');
  const result: string[] = [];

  let inTargetProgram = false;
  let lastScanUpdated = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const nameMatch = line.match(/^\s*-\s+name:\s*(.+)$/);

    if (nameMatch) {
      const name = stripQuotes(nameMatch[1]);
      inTargetProgram = name === programName;
      lastScanUpdated = false;
    }

    if (inTargetProgram && line.match(/^\s+last_scan:\s*/)) {
      result.push(line.replace(/last_scan:\s*.+$/, `last_scan: ${date}`));
      lastScanUpdated = true;
      continue;
    }

    result.push(line);

    // If we're at the end of the target program block (next program starts or EOF),
    // and lastScan wasn't found, insert it
    const nextLine = lines[i + 1];
    if (inTargetProgram && !lastScanUpdated) {
      const nextIsNewProgram = nextLine !== undefined && nextLine.match(/^\s*-\s+name:/);
      const isLastLine = i === lines.length - 1;
      if (nextIsNewProgram || isLastLine) {
        result.push(`    last_scan: ${date}`);
        lastScanUpdated = true;
        inTargetProgram = false;
      }
    }
  }

  await writeFile(filePath, result.join('\n'), 'utf-8');
}

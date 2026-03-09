import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  getHistoryPath,
  loadHistory,
  saveHistory,
  buildHistoryEntry,
  addToHistory,
  getTrendSummary,
  type ScanHistory,
  type ScanHistoryEntry,
} from '../../src/utils/scan-history.js';
import type { ScanResult, Severity } from '../../src/scanner/types.js';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    startedAt: '2026-03-09T12:00:00Z',
    completedAt: '2026-03-09T12:01:00Z',
    pagesScanned: 10,
    rawFindings: [],
    interpretedFindings: [],
    summary: {
      totalFindings: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      topFindings: [],
    },
    exitCode: 0,
    scanDuration: 60000,
    checksRun: ['xss', 'sqli'],
    ...overrides,
  } as ScanResult;
}

function makeEntry(overrides: Partial<ScanHistoryEntry> = {}): ScanHistoryEntry {
  return {
    id: '20260309120000',
    targetUrl: 'https://example.com',
    timestamp: '2026-03-09T12:00:00Z',
    duration: 60000,
    profile: 'standard',
    pagesScanned: 10,
    totalFindings: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    checksRun: ['xss', 'sqli'],
    newFindings: 0,
    resolvedFindings: 0,
    exitCode: 0,
    ...overrides,
  };
}

describe('getHistoryPath', () => {
  it('generates path with hostname', () => {
    const path = getHistoryPath('/out', 'https://example.com');
    expect(path).toBe('/out/secbot-history-example.com.json');
  });

  it('sanitizes special characters in hostname', () => {
    const path = getHistoryPath('/out', 'https://my-app.example.com:8080');
    expect(path).toContain('secbot-history-');
    expect(path).toContain('my-app.example.com');
  });
});

describe('loadHistory / saveHistory', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'secbot-hist-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns empty history for non-existent file', () => {
    const history = loadHistory(join(tmpDir, 'nope.json'));
    expect(history.version).toBe(1);
    expect(history.entries).toEqual([]);
  });

  it('round-trips save/load', () => {
    const filePath = join(tmpDir, 'test.json');
    const history: ScanHistory = {
      version: 1,
      target: 'https://example.com',
      entries: [makeEntry()],
    };
    saveHistory(history, filePath);
    const loaded = loadHistory(filePath);
    expect(loaded).toEqual(history);
  });

  it('returns empty history for corrupt file', () => {
    const filePath = join(tmpDir, 'bad.json');
    writeFileSync(filePath, 'not json', 'utf-8');
    const history = loadHistory(filePath);
    expect(history.entries).toEqual([]);
  });

  it('returns empty history for wrong version', () => {
    const filePath = join(tmpDir, 'old.json');
    writeFileSync(filePath, JSON.stringify({ version: 99, entries: [] }), 'utf-8');
    const history = loadHistory(filePath);
    expect(history.entries).toEqual([]);
  });
});

describe('buildHistoryEntry', () => {
  it('builds entry from scan result', () => {
    const result = makeScanResult({
      rawFindings: [
        { id: '1', category: 'xss', severity: 'high', title: 'XSS', description: '', url: 'https://example.com/a', evidence: '', timestamp: '' },
      ] as any,
      summary: {
        totalFindings: 1,
        bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        topFindings: [],
      },
    });

    const entry = buildHistoryEntry(result);
    expect(entry.totalFindings).toBe(1);
    expect(entry.bySeverity.high).toBe(1);
    expect(entry.newFindings).toBe(1);
    expect(entry.resolvedFindings).toBe(0);
  });

  it('calculates new/resolved vs previous entry', () => {
    const previous = makeEntry({ totalFindings: 5 });
    const result = makeScanResult({
      rawFindings: Array.from({ length: 3 }, (_, i) => ({
        id: String(i), category: 'xss', severity: 'high' as Severity,
        title: `Finding ${i}`, description: '', url: `https://example.com/${i}`,
        evidence: '', timestamp: '',
      })) as any,
      summary: {
        totalFindings: 3,
        bySeverity: { critical: 0, high: 3, medium: 0, low: 0, info: 0 },
        topFindings: [],
      },
    });

    const entry = buildHistoryEntry(result, previous);
    expect(entry.totalFindings).toBe(3);
    expect(entry.resolvedFindings).toBe(2); // 5 -> 3
    expect(entry.newFindings).toBe(0); // 3 <= 5
  });
});

describe('addToHistory', () => {
  it('appends entry to history', () => {
    const history: ScanHistory = { version: 1, target: 'https://example.com', entries: [] };
    const result = makeScanResult();
    const updated = addToHistory(history, result);
    expect(updated.entries).toHaveLength(1);
  });

  it('keeps max 100 entries', () => {
    const entries = Array.from({ length: 100 }, (_, i) =>
      makeEntry({ id: String(i), timestamp: `2026-01-${String(i + 1).padStart(2, '0')}T00:00:00Z` }),
    );
    const history: ScanHistory = { version: 1, target: 'https://example.com', entries };
    const result = makeScanResult();
    const updated = addToHistory(history, result);
    expect(updated.entries).toHaveLength(100);
    // First entry should be entries[1], not entries[0] (oldest dropped)
    expect(updated.entries[0].id).toBe('1');
  });
});

describe('getTrendSummary', () => {
  it('returns no-history message for empty', () => {
    const summary = getTrendSummary({ version: 1, target: '', entries: [] });
    expect(summary).toContain('No scan history');
  });

  it('returns first-scan message for single entry', () => {
    const summary = getTrendSummary({
      version: 1, target: '', entries: [makeEntry()],
    });
    expect(summary).toContain('First scan');
  });

  it('shows improvement when findings decrease', () => {
    const entries = [
      makeEntry({ totalFindings: 10, bySeverity: { critical: 0, high: 5, medium: 5, low: 0, info: 0 } }),
      makeEntry({ totalFindings: 5, bySeverity: { critical: 0, high: 2, medium: 3, low: 0, info: 0 }, duration: 30000 }),
    ];
    const summary = getTrendSummary({ version: 1, target: '', entries });
    expect(summary).toContain('improving');
    expect(summary).toContain('-5');
  });

  it('shows increase when findings grow', () => {
    const entries = [
      makeEntry({ totalFindings: 3 }),
      makeEntry({ totalFindings: 7 }),
    ];
    const summary = getTrendSummary({ version: 1, target: '', entries });
    expect(summary).toContain('+4');
  });
});

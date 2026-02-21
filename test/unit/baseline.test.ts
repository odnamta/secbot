import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  loadBaseline,
  diffFindings,
  saveBaseline,
  generateFindingFingerprint,
} from '../../src/utils/baseline.js';
import type { RawFinding } from '../../src/scanner/types.js';
import type { BaselineFinding } from '../../src/utils/baseline.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    category: 'security-headers',
    severity: 'medium',
    title: 'Missing HSTS',
    description: 'Strict-Transport-Security header not set',
    url: 'https://example.com',
    evidence: 'Header missing',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'secbot-baseline-test-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort cleanup
    }
  }
  tempDirs.length = 0;
});

describe('generateFindingFingerprint', () => {
  it('is deterministic — same input produces same hash', () => {
    const finding = makeFinding({
      category: 'xss',
      url: 'https://example.com/page',
      title: 'Reflected XSS',
    });

    const fp1 = generateFindingFingerprint(finding);
    const fp2 = generateFindingFingerprint(finding);

    expect(fp1).toBe(fp2);
    expect(fp1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
  });

  it('ignores timestamp and id', () => {
    const finding1 = makeFinding({
      id: 'id-1',
      category: 'xss',
      url: 'https://example.com/page',
      title: 'Reflected XSS',
      timestamp: '2025-01-01T00:00:00.000Z',
    });

    const finding2 = makeFinding({
      id: 'id-2',
      category: 'xss',
      url: 'https://example.com/page',
      title: 'Reflected XSS',
      timestamp: '2026-02-21T12:00:00.000Z',
    });

    expect(generateFindingFingerprint(finding1)).toBe(
      generateFindingFingerprint(finding2),
    );
  });

  it('produces different fingerprints for different category+url+title combos', () => {
    const f1 = makeFinding({ category: 'xss', url: 'https://a.com', title: 'A' });
    const f2 = makeFinding({ category: 'sqli', url: 'https://a.com', title: 'A' });
    const f3 = makeFinding({ category: 'xss', url: 'https://b.com', title: 'A' });
    const f4 = makeFinding({ category: 'xss', url: 'https://a.com', title: 'B' });

    const fps = [f1, f2, f3, f4].map(generateFindingFingerprint);
    const unique = new Set(fps);
    expect(unique.size).toBe(4);
  });
});

describe('loadBaseline', () => {
  it('reads valid JSON baseline file', () => {
    const dir = makeTempDir();
    const filePath = join(dir, 'baseline.json');
    const data: BaselineFinding[] = [
      {
        fingerprint: 'abc123',
        category: 'xss',
        url: 'https://example.com',
        title: 'Reflected XSS',
        firstSeen: '2025-01-01T00:00:00.000Z',
      },
    ];
    writeFileSync(filePath, JSON.stringify(data), 'utf-8');

    const result = loadBaseline(filePath);
    expect(result).toEqual(data);
  });

  it('throws on invalid JSON', () => {
    const dir = makeTempDir();
    const filePath = join(dir, 'bad.json');
    writeFileSync(filePath, 'not-json', 'utf-8');

    expect(() => loadBaseline(filePath)).toThrow();
  });

  it('throws on non-array JSON', () => {
    const dir = makeTempDir();
    const filePath = join(dir, 'obj.json');
    writeFileSync(filePath, JSON.stringify({ foo: 'bar' }), 'utf-8');

    expect(() => loadBaseline(filePath)).toThrow('Baseline file must contain a JSON array');
  });
});

describe('diffFindings', () => {
  it('returns only new findings not in baseline', () => {
    const existing = makeFinding({
      category: 'xss',
      url: 'https://example.com/page1',
      title: 'Reflected XSS',
    });
    const newOne = makeFinding({
      category: 'sqli',
      url: 'https://example.com/page2',
      title: 'SQL Injection',
    });

    const baseline: BaselineFinding[] = [
      {
        fingerprint: generateFindingFingerprint(existing),
        category: existing.category,
        url: existing.url,
        title: existing.title,
        firstSeen: existing.timestamp,
      },
    ];

    const result = diffFindings([existing, newOne], baseline);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe('SQL Injection');
  });

  it('returns all findings when baseline is empty', () => {
    const findings = [
      makeFinding({ title: 'A', url: 'https://a.com' }),
      makeFinding({ title: 'B', url: 'https://b.com' }),
    ];

    const result = diffFindings(findings, []);
    expect(result).toHaveLength(2);
  });

  it('returns empty when all findings are in baseline', () => {
    const f1 = makeFinding({ category: 'xss', url: 'https://a.com', title: 'XSS' });
    const f2 = makeFinding({ category: 'sqli', url: 'https://b.com', title: 'SQLi' });

    const baseline: BaselineFinding[] = [f1, f2].map((f) => ({
      fingerprint: generateFindingFingerprint(f),
      category: f.category,
      url: f.url,
      title: f.title,
      firstSeen: f.timestamp,
    }));

    const result = diffFindings([f1, f2], baseline);
    expect(result).toHaveLength(0);
  });
});

describe('saveBaseline', () => {
  it('creates valid JSON file with correct structure', () => {
    const dir = makeTempDir();
    const filePath = join(dir, 'output-baseline.json');

    const findings = [
      makeFinding({
        category: 'xss',
        url: 'https://example.com/a',
        title: 'XSS found',
        timestamp: '2025-06-01T00:00:00.000Z',
      }),
      makeFinding({
        category: 'sqli',
        url: 'https://example.com/b',
        title: 'SQLi found',
        timestamp: '2025-06-02T00:00:00.000Z',
      }),
    ];

    saveBaseline(findings, filePath);

    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw) as BaselineFinding[];

    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toHaveProperty('fingerprint');
    expect(parsed[0]).toHaveProperty('category', 'xss');
    expect(parsed[0]).toHaveProperty('url', 'https://example.com/a');
    expect(parsed[0]).toHaveProperty('title', 'XSS found');
    expect(parsed[0]).toHaveProperty('firstSeen', '2025-06-01T00:00:00.000Z');

    // Verify fingerprint matches what generateFindingFingerprint produces
    expect(parsed[0].fingerprint).toBe(generateFindingFingerprint(findings[0]));
    expect(parsed[1].fingerprint).toBe(generateFindingFingerprint(findings[1]));
  });

  it('creates parent directories if needed', () => {
    const dir = makeTempDir();
    const filePath = join(dir, 'nested', 'deep', 'baseline.json');

    saveBaseline([makeFinding()], filePath);

    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(1);
  });
});

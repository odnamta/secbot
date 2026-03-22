import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync, existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { autoTriageFindings, isDuplicateOfSubmitted, formatFindingForBounty, slugify } from '../../src/hunting/auto-triage.js';
import { formatHuntSummary, formatDetailedNotification } from '../../src/hunting/notify.js';
import type { InterpretedFinding, RawFinding } from '../../src/scanner/types.js';
import type { HuntSummary } from '../../src/hunting/types.js';
import type { TriageInfo } from '../../src/hunting/notify.js';

// ─── Test Helpers ─────────────────────────────────────────────

function makeFinding(overrides: Partial<InterpretedFinding> = {}): InterpretedFinding {
  return {
    title: 'Reflected Cross-Site Scripting (XSS)',
    severity: 'high',
    confidence: 'high',
    owaspCategory: 'A03:2021 - Injection',
    description: 'User input is reflected without encoding.',
    impact: 'Attacker can execute arbitrary JavaScript.',
    reproductionSteps: [
      'Navigate to https://example.com/search?q=test',
      'Inject payload: <script>alert(1)</script>',
    ],
    suggestedFix: 'Implement output encoding.',
    affectedUrls: ['https://example.com/search?q=test'],
    rawFindingIds: ['f-abc12345'],
    ...overrides,
  };
}

function makeRawFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: 'f-abc12345',
    category: 'xss',
    severity: 'high',
    title: 'Reflected XSS',
    description: 'XSS in search param',
    url: 'https://example.com/search?q=test',
    evidence: 'Reflected <script>alert(1)</script>',
    timestamp: new Date().toISOString(),
    confidence: 'high',
    ...overrides,
  };
}

function makeSummary(overrides: Partial<HuntSummary> = {}): HuntSummary {
  return {
    programs: 3,
    findings: { high: 0, medium: 0, low: 0 },
    escalations: 0,
    duration: '2m 34s',
    scannedAt: new Date().toISOString(),
    ...overrides,
  };
}

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), 'secbot-triage-'));
});

afterEach(() => {
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch { /* best effort */ }
});

// ─── B1: Auto-staging ─────────────────────────────────────────

describe('autoTriageFindings', () => {
  it('stages high-confidence, high-severity findings', () => {
    const findings = [makeFinding({ severity: 'high', confidence: 'high' })];
    const raw = [makeRawFinding()];

    const result = autoTriageFindings(findings, raw, 'test-program', tempDir);

    expect(result.staged).toBe(1);
    expect(result.skippedLowConfidence).toBe(0);
    expect(result.skippedDuplicate).toBe(0);

    const pendingDir = join(tempDir, 'pending', 'test-program');
    const files = readdirSync(pendingDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/\.md$/);
  });

  it('stages high-confidence, critical-severity findings', () => {
    const findings = [makeFinding({ severity: 'critical', confidence: 'high' })];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(1);
  });

  it('stages high-confidence, medium-severity findings', () => {
    const findings = [makeFinding({ severity: 'medium', confidence: 'high' })];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(1);
  });

  it('skips low-severity findings', () => {
    const findings = [makeFinding({ severity: 'low', confidence: 'high' })];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(0);
    expect(result.skippedLowConfidence).toBe(1);
  });

  it('skips info-severity findings', () => {
    const findings = [makeFinding({ severity: 'info', confidence: 'high' })];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(0);
    expect(result.skippedLowConfidence).toBe(1);
  });

  it('skips medium-confidence findings', () => {
    const findings = [makeFinding({ confidence: 'medium' })];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(0);
    expect(result.skippedLowConfidence).toBe(1);
  });

  it('skips low-confidence findings', () => {
    const findings = [makeFinding({ confidence: 'low' })];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(0);
    expect(result.skippedLowConfidence).toBe(1);
  });

  it('stages multiple qualifying findings', () => {
    const findings = [
      makeFinding({ rawFindingIds: ['f-001aaaaa'] }),
      makeFinding({ title: 'SQL Injection', rawFindingIds: ['f-002bbbbb'] }),
      makeFinding({ severity: 'low', rawFindingIds: ['f-003ccccc'] }),
    ];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(2);
    expect(result.skippedLowConfidence).toBe(1);
  });

  it('creates pending directory structure', () => {
    autoTriageFindings([makeFinding()], [], 'my-program', tempDir);
    expect(existsSync(join(tempDir, 'pending', 'my-program'))).toBe(true);
  });

  it('file name contains finding ID prefix and title slug', () => {
    const findings = [makeFinding({ rawFindingIds: ['f-abc12345-xyz'] })];
    autoTriageFindings(findings, [], 'prog', tempDir);

    const files = readdirSync(join(tempDir, 'pending', 'prog'));
    expect(files[0]).toContain('f-abc123');
    expect(files[0]).toContain('reflected-cross-site-scripting');
  });

  it('uses "unknown" prefix when no rawFindingIds', () => {
    const findings = [makeFinding({ rawFindingIds: [] })];
    autoTriageFindings(findings, [], 'prog', tempDir);

    const files = readdirSync(join(tempDir, 'pending', 'prog'));
    expect(files[0]).toMatch(/^unknown-/);
  });

  it('returns zero counts when no findings provided', () => {
    const result = autoTriageFindings([], [], 'prog', tempDir);
    expect(result.staged).toBe(0);
    expect(result.skippedDuplicate).toBe(0);
    expect(result.skippedLowConfidence).toBe(0);
  });
});

// ─── B2: Duplicate detection ──────────────────────────────────

describe('isDuplicateOfSubmitted', () => {
  it('returns false when no submitted/accepted dirs exist', () => {
    const finding = makeFinding();
    expect(isDuplicateOfSubmitted(finding, tempDir, 'prog')).toBe(false);
  });

  it('detects duplicate by title slug in submitted/', () => {
    const submittedDir = join(tempDir, 'submitted', 'prog');
    mkdirSync(submittedDir, { recursive: true });
    writeFileSync(join(submittedDir, 'f-old-reflected-cross-site-scripting-xss.md'), '# Old report');

    const finding = makeFinding();
    expect(isDuplicateOfSubmitted(finding, tempDir, 'prog')).toBe(true);
  });

  it('detects duplicate by title slug in accepted/', () => {
    const acceptedDir = join(tempDir, 'accepted', 'prog');
    mkdirSync(acceptedDir, { recursive: true });
    writeFileSync(join(acceptedDir, 'f-old-reflected-cross-site-scripting-xss.md'), '# Accepted report');

    const finding = makeFinding();
    expect(isDuplicateOfSubmitted(finding, tempDir, 'prog')).toBe(true);
  });

  it('detects duplicate by URL match in submitted files', () => {
    const submittedDir = join(tempDir, 'submitted', 'prog');
    mkdirSync(submittedDir, { recursive: true });
    writeFileSync(
      join(submittedDir, 'f-old-some-other-title.md'),
      '# Different title\n\nAffected URL: https://example.com/search?q=test\n',
    );

    const finding = makeFinding({ affectedUrls: ['https://example.com/search?q=test'] });
    expect(isDuplicateOfSubmitted(finding, tempDir, 'prog')).toBe(true);
  });

  it('returns false for different finding title and URL', () => {
    const submittedDir = join(tempDir, 'submitted', 'prog');
    mkdirSync(submittedDir, { recursive: true });
    writeFileSync(
      join(submittedDir, 'f-old-cors-misconfiguration.md'),
      '# CORS issue\nhttps://other.com/api\n',
    );

    const finding = makeFinding({ affectedUrls: ['https://example.com/search?q=test'] });
    expect(isDuplicateOfSubmitted(finding, tempDir, 'prog')).toBe(false);
  });

  it('checks both submitted and accepted dirs', () => {
    // Only accepted dir has the match
    const acceptedDir = join(tempDir, 'accepted', 'prog');
    mkdirSync(acceptedDir, { recursive: true });
    writeFileSync(join(acceptedDir, 'f-old-reflected-cross-site-scripting-xss.md'), '# Report');

    // submitted dir exists but no match
    const submittedDir = join(tempDir, 'submitted', 'prog');
    mkdirSync(submittedDir, { recursive: true });
    writeFileSync(join(submittedDir, 'f-old-sqli.md'), '# SQLi');

    expect(isDuplicateOfSubmitted(makeFinding(), tempDir, 'prog')).toBe(true);
  });

  it('skips non-.md files', () => {
    const submittedDir = join(tempDir, 'submitted', 'prog');
    mkdirSync(submittedDir, { recursive: true });
    writeFileSync(join(submittedDir, 'notes.txt'), 'reflected-cross-site-scripting-xss');

    expect(isDuplicateOfSubmitted(makeFinding(), tempDir, 'prog')).toBe(false);
  });
});

describe('autoTriageFindings dedup integration', () => {
  it('skips findings that match submitted reports', () => {
    const submittedDir = join(tempDir, 'submitted', 'prog');
    mkdirSync(submittedDir, { recursive: true });
    writeFileSync(join(submittedDir, 'f-old-reflected-cross-site-scripting-xss.md'), '# Already submitted');

    const findings = [makeFinding()];
    const result = autoTriageFindings(findings, [], 'prog', tempDir);
    expect(result.staged).toBe(0);
    expect(result.skippedDuplicate).toBe(1);
  });
});

// ─── Formatting ───────────────────────────────────────────────

describe('formatFindingForBounty', () => {
  it('includes auto-triage header comments', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('<!-- Auto-triaged by SecBot -->');
    expect(md).toContain('<!-- Confidence: high');
    expect(md).toContain('Severity: high');
  });

  it('includes finding title', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('Reflected Cross-Site Scripting (XSS)');
  });

  it('includes description', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('User input is reflected without encoding');
  });

  it('includes steps to reproduce', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('Navigate to https://example.com/search?q=test');
  });

  it('includes impact section', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('Attacker can execute arbitrary JavaScript');
  });

  it('includes suggested fix', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('Implement output encoding');
  });

  it('includes affected URLs', () => {
    const md = formatFindingForBounty(makeFinding(), []);
    expect(md).toContain('https://example.com/search?q=test');
  });

  it('passes raw findings context to formatter for evidence', () => {
    const raw = makeRawFinding({
      request: { method: 'GET', url: 'https://example.com/search?q=<script>alert(1)</script>' },
      response: { status: 200, bodySnippet: '<html><script>alert(1)</script></html>' },
      evidencePack: {
        curlCommand: "curl -L -i 'https://example.com/search?q=<script>alert(1)</script>'",
        httpExchange: {
          request: { method: 'GET', url: 'https://example.com/search?q=<script>alert(1)</script>' },
          response: { status: 200, body: '<html><script>alert(1)</script></html>' },
        },
      },
    });
    const md = formatFindingForBounty(makeFinding(), [raw]);
    expect(md).toContain('curl');
    expect(md).toContain('HTTP/1.1 200');
  });
});

describe('slugify', () => {
  it('converts title to kebab-case', () => {
    expect(slugify('Reflected Cross-Site Scripting (XSS)')).toBe('reflected-cross-site-scripting-xss');
  });

  it('removes special characters', () => {
    expect(slugify('SQL Injection: UNION-based')).toBe('sql-injection-union-based');
  });

  it('trims leading/trailing hyphens', () => {
    expect(slugify('---hello---')).toBe('hello');
  });

  it('truncates to 80 chars', () => {
    const longTitle = 'a'.repeat(100);
    expect(slugify(longTitle).length).toBeLessThanOrEqual(80);
  });

  it('handles empty string', () => {
    expect(slugify('')).toBe('');
  });
});

// ─── B3: Improved hunt summary notifications ─────────────────

describe('formatHuntSummary with triage info', () => {
  it('includes triage staged count when present', () => {
    const triageInfo: TriageInfo = {
      perProgram: {
        'example-program': { staged: 3, skippedDuplicate: 1, skippedLowConfidence: 2 },
      },
    };
    const result = formatHuntSummary(makeSummary({ findings: { high: 3, medium: 2, low: 0 } }), triageInfo);
    expect(result).toContain('Staged: 3');
    expect(result).toContain('example-program:3');
  });

  it('omits triage section when no findings staged', () => {
    const triageInfo: TriageInfo = {
      perProgram: {
        'prog': { staged: 0, skippedDuplicate: 0, skippedLowConfidence: 5 },
      },
    };
    const result = formatHuntSummary(makeSummary(), triageInfo);
    expect(result).not.toContain('Staged');
  });

  it('works without triage info (backward compatible)', () => {
    const result = formatHuntSummary(makeSummary({ programs: 2 }));
    expect(result).toContain('2 programs scanned');
    expect(result).not.toContain('Staged');
  });

  it('aggregates staged count across multiple programs', () => {
    const triageInfo: TriageInfo = {
      perProgram: {
        'prog-a': { staged: 2, skippedDuplicate: 0, skippedLowConfidence: 0 },
        'prog-b': { staged: 1, skippedDuplicate: 0, skippedLowConfidence: 0 },
      },
    };
    const result = formatHuntSummary(makeSummary(), triageInfo);
    expect(result).toContain('Staged: 3');
  });
});

describe('formatDetailedNotification', () => {
  it('includes header and time', () => {
    const result = formatDetailedNotification(makeSummary());
    expect(result).toContain('=== SecBot Hunt Report ===');
    expect(result).toContain('Time:');
  });

  it('includes findings breakdown', () => {
    const result = formatDetailedNotification(makeSummary({
      findings: { high: 5, medium: 3, low: 1 },
    }));
    expect(result).toContain('Findings: 9 total');
    expect(result).toContain('High-confidence: 5');
    expect(result).toContain('Medium: 3');
    expect(result).toContain('Low: 1');
  });

  it('includes per-program triage breakdown', () => {
    const triageInfo: TriageInfo = {
      perProgram: {
        'hackerone-prog': { staged: 2, skippedDuplicate: 1, skippedLowConfidence: 3 },
      },
    };
    const result = formatDetailedNotification(makeSummary(), triageInfo);
    expect(result).toContain('Pending Bounty Reports: 2 staged');
    expect(result).toContain('hackerone-prog: 2 new (1 dup, 3 filtered)');
  });

  it('includes ACTION REQUIRED section for staged findings', () => {
    const triageInfo: TriageInfo = {
      perProgram: {
        'prog': { staged: 1, skippedDuplicate: 0, skippedLowConfidence: 0 },
      },
    };
    const result = formatDetailedNotification(makeSummary(), triageInfo);
    expect(result).toContain('*** ACTION REQUIRED ***');
    expect(result).toContain('[REVIEW] 1 finding(s) staged in bounty-pool/pending/');
  });

  it('includes ACTION REQUIRED section for escalations', () => {
    const triageInfo: TriageInfo = {
      perProgram: {},
      escalationItems: [
        { url: 'https://example.com/admin', reason: 'captcha', timestamp: new Date().toISOString() },
        { url: 'https://example.com/login', reason: '2fa-required', timestamp: new Date().toISOString() },
      ],
    };
    const result = formatDetailedNotification(makeSummary({ escalations: 2 }), triageInfo);
    expect(result).toContain('*** ACTION REQUIRED ***');
    expect(result).toContain('[ESCALATION] 2 item(s) need human intervention');
    expect(result).toContain('captcha: https://example.com/admin');
    expect(result).toContain('2fa-required: https://example.com/login');
  });

  it('truncates escalation items to 5', () => {
    const items = Array.from({ length: 8 }, (_, i) => ({
      url: `https://example.com/page${i}`,
      reason: 'captcha' as const,
      timestamp: new Date().toISOString(),
    }));
    const triageInfo: TriageInfo = {
      perProgram: {},
      escalationItems: items,
    };
    const result = formatDetailedNotification(makeSummary({ escalations: 8 }), triageInfo);
    expect(result).toContain('... and 3 more');
  });

  it('omits ACTION REQUIRED when nothing needs attention', () => {
    const result = formatDetailedNotification(makeSummary());
    expect(result).not.toContain('ACTION REQUIRED');
  });

  it('includes end marker', () => {
    const result = formatDetailedNotification(makeSummary());
    expect(result).toContain('=== End Report ===');
  });
});

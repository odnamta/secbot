import { describe, it, expect } from 'vitest';
import { analyzeGaps, calculateQualityScore, formatGapReport } from '../../src/learning/gap-analysis.js';
import type { ScanResult, CheckAuditEntry } from '../../src/scanner/types.js';

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    targetUrl: 'https://example.com',
    profile: 'standard',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    pagesScanned: 10,
    rawFindings: [],
    interpretedFindings: [],
    summary: {
      totalRawFindings: 0,
      totalInterpretedFindings: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      topIssues: [],
      passedChecks: [],
    },
    exitCode: 0,
    scanDuration: 30000,
    checksRun: [],
    ...overrides,
  };
}

function makeAudit(
  name: string,
  status: 'completed' | 'failed' | 'skipped',
  findingsCount = 0,
  durationMs = 10000,
  error?: string,
): CheckAuditEntry {
  return { name, status, findingsCount, durationMs, ...(error ? { error } : {}) };
}

describe('analyzeGaps', () => {
  it('identifies silent checks (completed with 0 findings)', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('xss', 'completed', 0),
        makeAudit('sqli', 'completed', 2),
        makeAudit('cors-misconfiguration', 'completed', 0),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.silentChecks).toEqual(['xss', 'cors-misconfiguration']);
  });

  it('identifies failed checks with error messages', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('ssrf', 'failed', 0, 0, 'Request timed out'),
        makeAudit('xss', 'completed', 1),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.failedChecks).toHaveLength(1);
    expect(analysis.failedChecks[0].name).toBe('ssrf');
    expect(analysis.failedChecks[0].error).toBe('Request timed out');
  });

  it('identifies skipped checks', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('jwt', 'skipped', 0, 0),
        makeAudit('xss', 'completed', 0),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.skippedChecks).toEqual(['jwt']);
  });

  it('returns surface coverage from recon data', () => {
    const result = makeScanResult({
      pagesScanned: 15,
      recon: {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: {
          pages: ['/', '/about'],
          apiRoutes: ['/api/v1/users', '/api/v1/items'],
          forms: [{ action: '/login', method: 'POST', inputs: [], pageUrl: '/' }],
          staticAssets: [],
          graphql: [],
        },
      },
    });
    const analysis = analyzeGaps(result);
    expect(analysis.surfaceCoverage.pagesScanned).toBe(15);
    expect(analysis.surfaceCoverage.apiEndpoints).toBe(2);
    expect(analysis.surfaceCoverage.formsFound).toBe(1);
  });

  it('handles missing checkAudit gracefully', () => {
    const result = makeScanResult({ checkAudit: undefined });
    const analysis = analyzeGaps(result);
    expect(analysis.silentChecks).toEqual([]);
    expect(analysis.failedChecks).toEqual([]);
    expect(analysis.skippedChecks).toEqual([]);
  });

  it('sets category depth to deep for checks with findings', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('xss', 'completed', 3, 2000),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.categoryDepth['xss']).toBe('deep');
  });

  it('sets category depth based on duration for silent checks', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('sqli', 'completed', 0, 35000), // >30s = deep
        makeAudit('xss', 'completed', 0, 10000),  // >5s = shallow
        makeAudit('cors-misconfiguration', 'completed', 0, 2000), // <5s = none
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.categoryDepth['sqli']).toBe('deep');
    expect(analysis.categoryDepth['xss']).toBe('shallow');
    expect(analysis.categoryDepth['cors-misconfiguration']).toBe('none');
  });

  it('sets category depth to none for failed checks', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('ssrf', 'failed', 0, 5000, 'crash'),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.categoryDepth['ssrf']).toBe('none');
  });
});

describe('suggestions', () => {
  it('suggests auth when page count is low', () => {
    const result = makeScanResult({ pagesScanned: 3 });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions).toContain(
      'Low page count — consider authenticated scanning (--auth) to access more pages'
    );
  });

  it('does not suggest auth when page count is adequate', () => {
    const result = makeScanResult({ pagesScanned: 10 });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('Low page count'))).toBe(false);
  });

  it('suggests API discovery when no API endpoints found', () => {
    const result = makeScanResult({
      recon: {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: [], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
    });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('No API endpoints'))).toBe(true);
  });

  it('suggests form injection issue when no forms found', () => {
    const result = makeScanResult({
      recon: {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: [], apiRoutes: ['/api/foo'], forms: [], staticAssets: [], graphql: [] },
      },
    });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('No forms found'))).toBe(true);
  });

  it('suggests timeout fix when checks timed out', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('xss', 'failed', 0, 0, 'Navigation timed out after 30000ms'),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('Timeout issues'))).toBe(true);
  });

  it('suggests increasing timeout when many checks failed', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('xss', 'failed', 0, 0, 'error'),
        makeAudit('sqli', 'failed', 0, 0, 'error'),
        makeAudit('cors-misconfiguration', 'completed', 0),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('checks failed'))).toBe(true);
  });

  it('suggests zero findings message when nothing found', () => {
    const result = makeScanResult({ rawFindings: [] });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('Zero findings'))).toBe(true);
  });

  it('suggests WordPress deep profile when WP detected but no SQLi', () => {
    const result = makeScanResult({
      recon: {
        techStack: { languages: [], detected: ['WordPress 6.4'] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: [], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
      },
      checkAudit: [
        makeAudit('sqli', 'completed', 0),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('WordPress'))).toBe(true);
  });

  it('suggests GraphQL manual check when detected but no findings', () => {
    const result = makeScanResult({
      recon: {
        techStack: { languages: [], detected: ['GraphQL'] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: { pages: [], apiRoutes: [], forms: [], staticAssets: [], graphql: ['/graphql'] },
      },
      checkAudit: [
        makeAudit('graphql', 'completed', 0),
      ],
    });
    const analysis = analyzeGaps(result);
    expect(analysis.suggestions.some(s => s.includes('GraphQL'))).toBe(true);
  });
});

describe('calculateQualityScore', () => {
  it('returns 0 when no checks ran', () => {
    const result = makeScanResult();
    const score = calculateQualityScore(result, [], [], [], {
      pagesScanned: 0,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(0);
  });

  it('gives 40 points for 100% check completion', () => {
    const result = makeScanResult();
    const completed = [makeAudit('xss', 'completed', 0), makeAudit('sqli', 'completed', 0)];
    const score = calculateQualityScore(result, completed, [], [], {
      pagesScanned: 0,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(40);
  });

  it('gives partial completion points when some checks fail', () => {
    const result = makeScanResult();
    const completed = [makeAudit('xss', 'completed', 0)];
    const failed = [makeAudit('sqli', 'failed', 0, 0, 'err')];
    const score = calculateQualityScore(result, completed, failed, [], {
      pagesScanned: 0,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(20); // 1/2 * 40
  });

  it('gives surface coverage points for pages', () => {
    const result = makeScanResult();
    const score10 = calculateQualityScore(result, [], [], [], {
      pagesScanned: 10,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    const score5 = calculateQualityScore(result, [], [], [], {
      pagesScanned: 5,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    const score2 = calculateQualityScore(result, [], [], [], {
      pagesScanned: 2,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score10).toBe(10); // >= 10 pages = 10 pts
    expect(score5).toBe(5);   // >= 5 pages = 5 pts
    expect(score2).toBe(0);   // < 5 pages = 0 pts
  });

  it('gives surface coverage points for API endpoints and forms', () => {
    const result = makeScanResult();
    const score = calculateQualityScore(result, [], [], [], {
      pagesScanned: 0,
      apiEndpoints: 3,
      formsFound: 2,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(20); // 10 (api) + 10 (forms)
  });

  it('gives finding quality points for high-confidence findings', () => {
    const result = makeScanResult({
      rawFindings: [
        {
          id: 'f1',
          category: 'xss',
          severity: 'high',
          title: 'XSS',
          description: 'test',
          url: 'https://example.com',
          evidence: 'test',
          timestamp: new Date().toISOString(),
          confidence: 'high',
        },
      ],
    });
    const score = calculateQualityScore(result, [], [], [], {
      pagesScanned: 0,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(30); // 15 (high confidence) + 15 (not noisy)
  });

  it('does not give noise-free points when findings exceed 50', () => {
    const findings = Array.from({ length: 51 }, (_, i) => ({
      id: `f${i}`,
      category: 'xss' as const,
      severity: 'medium' as const,
      title: `XSS ${i}`,
      description: 'test',
      url: 'https://example.com',
      evidence: 'test',
      timestamp: new Date().toISOString(),
      confidence: 'low' as const,
    }));
    const result = makeScanResult({ rawFindings: findings });
    const score = calculateQualityScore(result, [], [], [], {
      pagesScanned: 0,
      apiEndpoints: 0,
      formsFound: 0,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(0); // no high confidence, 51 findings = noisy
  });

  it('caps score at 100', () => {
    const findings = [
      {
        id: 'f1',
        category: 'xss' as const,
        severity: 'high' as const,
        title: 'XSS',
        description: 'test',
        url: 'https://example.com',
        evidence: 'test',
        timestamp: new Date().toISOString(),
        confidence: 'high' as const,
      },
    ];
    const result = makeScanResult({ rawFindings: findings });
    const completed = Array.from({ length: 10 }, (_, i) => makeAudit(`check-${i}`, 'completed', 0));
    const score = calculateQualityScore(result, completed, [], [], {
      pagesScanned: 20,
      apiEndpoints: 5,
      formsFound: 3,
      paramsDiscovered: 0,
      subdomainsFound: 0,
    });
    expect(score).toBe(100);
  });
});

describe('formatGapReport', () => {
  it('includes quality score in header', () => {
    const analysis = analyzeGaps(makeScanResult());
    const report = formatGapReport(analysis);
    expect(report).toContain('Scan Quality Report');
    expect(report).toContain('/100');
  });

  it('includes failed checks section when failures exist', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('ssrf', 'failed', 0, 0, 'Connection refused'),
      ],
    });
    const analysis = analyzeGaps(result);
    const report = formatGapReport(analysis);
    expect(report).toContain('Failed checks (1)');
    expect(report).toContain('ssrf');
    expect(report).toContain('Connection refused');
  });

  it('does not include failed checks section when none failed', () => {
    const result = makeScanResult({
      checkAudit: [
        makeAudit('xss', 'completed', 0),
      ],
    });
    const analysis = analyzeGaps(result);
    const report = formatGapReport(analysis);
    expect(report).not.toContain('Failed checks');
  });

  it('includes suggestions section', () => {
    const result = makeScanResult({ pagesScanned: 2 });
    const analysis = analyzeGaps(result);
    const report = formatGapReport(analysis);
    expect(report).toContain('Suggestions');
    expect(report).toContain('Low page count');
  });

  it('includes surface coverage line', () => {
    const result = makeScanResult({
      pagesScanned: 7,
      recon: {
        techStack: { languages: [], detected: [] },
        waf: { detected: false, confidence: 'low', evidence: [] },
        framework: { confidence: 'low', evidence: [] },
        endpoints: {
          pages: [],
          apiRoutes: ['/api/v1/users'],
          forms: [{ action: '/login', method: 'POST', inputs: [], pageUrl: '/' }],
          staticAssets: [],
          graphql: [],
        },
      },
    });
    const analysis = analyzeGaps(result);
    const report = formatGapReport(analysis);
    expect(report).toContain('7 pages');
    expect(report).toContain('1 API endpoints');
    expect(report).toContain('1 forms');
  });

  it('limits failed checks display to 5', () => {
    const checkAudit = Array.from({ length: 8 }, (_, i) =>
      makeAudit(`check-${i}`, 'failed', 0, 0, `Error ${i}`)
    );
    const result = makeScanResult({ checkAudit });
    const analysis = analyzeGaps(result);
    const report = formatGapReport(analysis);
    // Should show "Failed checks (8)" but only list 5
    expect(report).toContain('Failed checks (8)');
    expect(report).toContain('check-0');
    expect(report).toContain('check-4');
    expect(report).not.toContain('check-5');
  });
});

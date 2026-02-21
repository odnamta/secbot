import { describe, it, expect } from 'vitest';
import { formatForHackerOne, formatForBugcrowd } from '../../src/reporter/bounty-export.js';
import type { InterpretedFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<InterpretedFinding> = {}): InterpretedFinding {
  return {
    title: 'Reflected Cross-Site Scripting (XSS)',
    severity: 'high',
    confidence: 'high',
    owaspCategory: 'A03:2021 - Injection',
    description: 'User input is reflected in the response without proper encoding, allowing script injection.',
    impact: 'An attacker can execute arbitrary JavaScript in the context of the victim\'s browser session.',
    reproductionSteps: [
      'Navigate to https://example.com/search?q=test',
      'Inject payload: <script>alert(document.cookie)</script>',
      'Observe the script executes in the browser',
    ],
    suggestedFix: 'Implement output encoding for all user-controlled input reflected in HTML responses.',
    codeExample: 'GET /search?q=<script>alert(1)</script> HTTP/1.1\nHost: example.com',
    affectedUrls: ['https://example.com/search?q=test', 'https://example.com/results?q=test'],
    rawFindingIds: ['f-001'],
    ...overrides,
  };
}

describe('bounty-export', () => {
  describe('formatForHackerOne', () => {
    it('produces valid markdown with title header', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('## Reflected Cross-Site Scripting (XSS)');
    });

    it('includes severity in HackerOne format', () => {
      const output = formatForHackerOne(makeFinding({ severity: 'critical' }));
      expect(output).toContain('Critical (9.0-10.0)');
    });

    it('includes severity mapping for all levels', () => {
      expect(formatForHackerOne(makeFinding({ severity: 'critical' }))).toContain('Critical (9.0-10.0)');
      expect(formatForHackerOne(makeFinding({ severity: 'high' }))).toContain('High (7.0-8.9)');
      expect(formatForHackerOne(makeFinding({ severity: 'medium' }))).toContain('Medium (4.0-6.9)');
      expect(formatForHackerOne(makeFinding({ severity: 'low' }))).toContain('Low (0.1-3.9)');
      expect(formatForHackerOne(makeFinding({ severity: 'info' }))).toContain('None (Informational)');
    });

    it('includes OWASP category as weakness', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('**Weakness:** A03:2021 - Injection');
    });

    it('includes asset URL', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('**Asset:** https://example.com/search?q=test');
    });

    it('includes summary section with description', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('### Summary');
      expect(output).toContain('User input is reflected in the response');
    });

    it('includes numbered steps to reproduce', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('### Steps To Reproduce');
      expect(output).toContain('1. Navigate to https://example.com/search?q=test');
      expect(output).toContain('2. Inject payload');
      expect(output).toContain('3. Observe the script executes');
    });

    it('provides default steps when reproduction steps are empty', () => {
      const output = formatForHackerOne(makeFinding({ reproductionSteps: [] }));
      expect(output).toContain('1. Navigate to the affected URL');
    });

    it('includes code example as supporting material', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('### Supporting Material/References');
      expect(output).toContain('```');
      expect(output).toContain('GET /search?q=<script>alert(1)</script>');
    });

    it('omits supporting material when no code example', () => {
      const output = formatForHackerOne(makeFinding({ codeExample: undefined }));
      expect(output).not.toContain('### Supporting Material/References');
    });

    it('includes impact section', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('### Impact');
      expect(output).toContain('execute arbitrary JavaScript');
    });

    it('includes affected URLs', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('### Affected URLs');
      expect(output).toContain('- https://example.com/search?q=test');
      expect(output).toContain('- https://example.com/results?q=test');
    });

    it('truncates affected URLs list to 10', () => {
      const urls = Array.from({ length: 15 }, (_, i) => `https://example.com/page${i}`);
      const output = formatForHackerOne(makeFinding({ affectedUrls: urls }));
      expect(output).toContain('- https://example.com/page9');
      expect(output).toContain('... and 5 more');
      expect(output).not.toContain('- https://example.com/page10');
    });

    it('includes suggested fix', () => {
      const output = formatForHackerOne(makeFinding());
      expect(output).toContain('### Suggested Fix');
      expect(output).toContain('Implement output encoding');
    });

    it('shows N/A asset when no affected URLs', () => {
      const output = formatForHackerOne(makeFinding({ affectedUrls: [] }));
      expect(output).toContain('**Asset:** N/A');
    });
  });

  describe('formatForBugcrowd', () => {
    it('produces markdown with H1 title header', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('# Reflected Cross-Site Scripting (XSS)');
    });

    it('includes priority in Bugcrowd P1-P5 format', () => {
      expect(formatForBugcrowd(makeFinding({ severity: 'critical' }))).toContain('P1 - Critical');
      expect(formatForBugcrowd(makeFinding({ severity: 'high' }))).toContain('P2 - High');
      expect(formatForBugcrowd(makeFinding({ severity: 'medium' }))).toContain('P3 - Medium');
      expect(formatForBugcrowd(makeFinding({ severity: 'low' }))).toContain('P4 - Low');
      expect(formatForBugcrowd(makeFinding({ severity: 'info' }))).toContain('P5 - Informational');
    });

    it('includes vulnerability type from OWASP category', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('**Vulnerability Type:** A03:2021 - Injection');
    });

    it('includes target URL', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('**URL:** https://example.com/search?q=test');
    });

    it('includes confidence level', () => {
      const output = formatForBugcrowd(makeFinding({ confidence: 'medium' }));
      expect(output).toContain('**Confidence:** medium');
    });

    it('includes description section', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('## Description');
      expect(output).toContain('User input is reflected');
    });

    it('includes proof of concept with numbered steps', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('## Proof of Concept');
      expect(output).toContain('1. Navigate to');
    });

    it('includes HTTP request/response code block', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('## HTTP Request/Response');
      expect(output).toContain('```http');
      expect(output).toContain('GET /search?q=<script>alert(1)</script>');
    });

    it('omits HTTP section when no code example', () => {
      const output = formatForBugcrowd(makeFinding({ codeExample: undefined }));
      expect(output).not.toContain('## HTTP Request/Response');
    });

    it('includes impact section', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('## Impact');
    });

    it('includes affected endpoints', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('## Affected Endpoints');
    });

    it('includes remediation section', () => {
      const output = formatForBugcrowd(makeFinding());
      expect(output).toContain('## Remediation');
      expect(output).toContain('Implement output encoding');
    });
  });

  describe('cross-format consistency', () => {
    it('both formats include the same finding title', () => {
      const finding = makeFinding();
      const h1 = formatForHackerOne(finding);
      const bc = formatForBugcrowd(finding);
      expect(h1).toContain('Reflected Cross-Site Scripting (XSS)');
      expect(bc).toContain('Reflected Cross-Site Scripting (XSS)');
    });

    it('both formats include reproduction steps', () => {
      const finding = makeFinding();
      const h1 = formatForHackerOne(finding);
      const bc = formatForBugcrowd(finding);
      expect(h1).toContain('Navigate to https://example.com/search?q=test');
      expect(bc).toContain('Navigate to https://example.com/search?q=test');
    });

    it('both formats include impact', () => {
      const finding = makeFinding();
      const h1 = formatForHackerOne(finding);
      const bc = formatForBugcrowd(finding);
      expect(h1).toContain('execute arbitrary JavaScript');
      expect(bc).toContain('execute arbitrary JavaScript');
    });
  });
});

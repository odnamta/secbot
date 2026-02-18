import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ScanResult, InterpretedFinding, Severity } from '../scanner/types.js';
import { log } from '../utils/logger.js';

export function writeHtmlReport(result: ScanResult, outputPath: string): void {
  const html = generateHtml(result);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, html, 'utf-8');
  log.info(`HTML report written to: ${outputPath}`);
}

function generateHtml(result: ScanResult): string {
  const sorted = [...result.interpretedFindings].sort(
    (a, b) => severityOrder(b.severity) - severityOrder(a.severity),
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecBot Report — ${escapeHtml(result.targetUrl)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 900px; margin: 0 auto; padding: 2rem; }
    h1 { color: #38bdf8; margin-bottom: 0.5rem; }
    .meta { color: #94a3b8; margin-bottom: 2rem; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat { background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }
    .stat .value { font-size: 2rem; font-weight: bold; }
    .stat .label { color: #94a3b8; font-size: 0.875rem; }
    .severity-bar { display: flex; gap: 0.5rem; margin-bottom: 2rem; }
    .sev-badge { padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.875rem; font-weight: 600; }
    .sev-critical { background: #dc2626; color: white; }
    .sev-high { background: #ea580c; color: white; }
    .sev-medium { background: #ca8a04; color: white; }
    .sev-low { background: #0891b2; color: white; }
    .sev-info { background: #64748b; color: white; }
    .finding { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid #64748b; }
    .finding.critical { border-left-color: #dc2626; }
    .finding.high { border-left-color: #ea580c; }
    .finding.medium { border-left-color: #ca8a04; }
    .finding.low { border-left-color: #0891b2; }
    .finding h3 { color: #f8fafc; margin-bottom: 0.5rem; }
    .finding .owasp { color: #94a3b8; font-size: 0.875rem; margin-bottom: 0.75rem; }
    .finding p { margin-bottom: 0.75rem; }
    .finding .label { color: #38bdf8; font-weight: 600; }
    .finding ul { padding-left: 1.5rem; margin-bottom: 0.75rem; }
    .finding code { background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.875rem; }
    .finding pre { background: #0f172a; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.875rem; margin-bottom: 0.75rem; }
    .urls { color: #94a3b8; font-size: 0.875rem; }
    footer { text-align: center; color: #64748b; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <div class="container">
    <h1>SecBot Security Report</h1>
    <div class="meta">
      <p>Target: ${escapeHtml(result.targetUrl)}</p>
      <p>Profile: ${result.profile} | Pages: ${result.pagesScanned} | ${formatDuration(result.startedAt, result.completedAt)}</p>
      <p>Generated: ${new Date(result.completedAt).toLocaleString()}</p>
    </div>

    <div class="summary">
      <div class="stat">
        <div class="value">${result.summary.totalRawFindings}</div>
        <div class="label">Raw Findings</div>
      </div>
      <div class="stat">
        <div class="value">${result.summary.totalInterpretedFindings}</div>
        <div class="label">Actionable</div>
      </div>
      <div class="stat">
        <div class="value" style="color: ${result.summary.bySeverity.critical > 0 ? '#dc2626' : result.summary.bySeverity.high > 0 ? '#ea580c' : '#22c55e'}">${result.summary.bySeverity.critical + result.summary.bySeverity.high}</div>
        <div class="label">Critical/High</div>
      </div>
      <div class="stat">
        <div class="value">${result.pagesScanned}</div>
        <div class="label">Pages Scanned</div>
      </div>
    </div>

    <div class="severity-bar">
      ${result.summary.bySeverity.critical > 0 ? `<span class="sev-badge sev-critical">${result.summary.bySeverity.critical} Critical</span>` : ''}
      ${result.summary.bySeverity.high > 0 ? `<span class="sev-badge sev-high">${result.summary.bySeverity.high} High</span>` : ''}
      ${result.summary.bySeverity.medium > 0 ? `<span class="sev-badge sev-medium">${result.summary.bySeverity.medium} Medium</span>` : ''}
      ${result.summary.bySeverity.low > 0 ? `<span class="sev-badge sev-low">${result.summary.bySeverity.low} Low</span>` : ''}
      ${result.summary.bySeverity.info > 0 ? `<span class="sev-badge sev-info">${result.summary.bySeverity.info} Info</span>` : ''}
    </div>

    ${sorted.length === 0 ? '<p style="color: #22c55e; text-align: center; padding: 2rem;">No actionable vulnerabilities found!</p>' : ''}

    ${sorted.map((f, i) => renderFinding(i + 1, f)).join('\n')}

    <footer>
      <p>Generated by SecBot v0.0.1 — AI-Powered Security Scanner</p>
    </footer>
  </div>
</body>
</html>`;
}

function renderFinding(index: number, finding: InterpretedFinding): string {
  return `
    <div class="finding ${finding.severity}">
      <h3>#${index} <span class="sev-badge sev-${finding.severity}">${finding.severity.toUpperCase()}</span> ${escapeHtml(finding.title)}</h3>
      <div class="owasp">${escapeHtml(finding.owaspCategory)} | Confidence: ${finding.confidence}</div>
      <p>${escapeHtml(finding.description)}</p>
      <p><span class="label">Impact:</span> ${escapeHtml(finding.impact)}</p>
      ${finding.affectedUrls?.length > 0 ? `
      <p class="label">Affected URLs:</p>
      <ul class="urls">
        ${finding.affectedUrls.slice(0, 5).map((u) => `<li>${escapeHtml(u)}</li>`).join('\n        ')}
        ${finding.affectedUrls.length > 5 ? `<li>... and ${finding.affectedUrls.length - 5} more</li>` : ''}
      </ul>` : ''}
      ${finding.reproductionSteps?.length > 0 ? `
      <p class="label">Reproduction Steps:</p>
      <ol>
        ${finding.reproductionSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join('\n        ')}
      </ol>` : ''}
      ${finding.suggestedFix ? `<p><span class="label">Suggested Fix:</span> ${escapeHtml(finding.suggestedFix)}</p>` : ''}
      ${finding.codeExample ? `<pre><code>${escapeHtml(finding.codeExample)}</code></pre>` : ''}
    </div>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityOrder(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}

function formatDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ScanResult, InterpretedFinding, RawFinding, EvidencePack } from '../scanner/types.js';
import { log } from '../utils/logger.js';
import { severityOrder, formatDuration } from '../utils/shared.js';
import { getCvssForFinding, inferCategoryFromTitle } from '../utils/cvss.js';
import { generateCurlCommand } from '../utils/evidence.js';

const htmlPkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'));

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

  // Build raw findings lookup by ID for evidence enrichment
  const rawFindingsMap = new Map<string, RawFinding>();
  for (const rf of result.rawFindings) {
    rawFindingsMap.set(rf.id, rf);
  }

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
    .evidence-section { margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid #334155; }
    .evidence-section h4 { color: #38bdf8; font-size: 0.9rem; margin-bottom: 0.5rem; }
    .cvss-badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 700; margin-left: 0.5rem; }
    .cvss-critical { background: #dc2626; color: white; }
    .cvss-high { background: #ea580c; color: white; }
    .cvss-medium { background: #ca8a04; color: white; }
    .cvss-low { background: #0891b2; color: white; }
    .cvss-none { background: #64748b; color: white; }
    .cvss-vector { color: #94a3b8; font-size: 0.8rem; font-family: monospace; margin-left: 0.5rem; }
    .evidence-detail { margin-bottom: 0.75rem; }
    .evidence-detail summary { cursor: pointer; color: #38bdf8; font-weight: 600; font-size: 0.875rem; padding: 0.25rem 0; }
    .evidence-detail summary:hover { color: #7dd3fc; }
    .evidence-detail pre { margin-top: 0.5rem; white-space: pre-wrap; word-break: break-all; }
    .screenshot-note { color: #94a3b8; font-size: 0.8rem; font-style: italic; }
    .payload-tag { display: inline-block; background: #312e81; color: #c7d2fe; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; font-family: monospace; margin-right: 0.5rem; }
    .detection-tag { display: inline-block; background: #1e3a5f; color: #93c5fd; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; margin-right: 0.5rem; }
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

    ${sorted.map((f, i) => renderFinding(i + 1, f, rawFindingsMap)).join('\n')}

    <footer>
      <p>Generated by SecBot v${htmlPkg.version} — AI-Powered Security Scanner</p>
    </footer>
  </div>
</body>
</html>`;
}

function renderFinding(index: number, finding: InterpretedFinding, rawFindingsMap: Map<string, RawFinding>): string {
  // Look up matching raw findings for evidence data
  const matchedRawFindings = (finding.rawFindingIds ?? [])
    .map((id) => rawFindingsMap.get(id))
    .filter((rf): rf is RawFinding => rf !== undefined);

  // Use the first matched raw finding as primary evidence source
  const primaryRaw = matchedRawFindings[0];

  // Compute CVSS score — use raw finding's category when available, otherwise infer from title
  const category = primaryRaw?.category ?? inferCategoryFromTitle(finding.title);
  const cvss = getCvssForFinding(category, finding.severity);

  // Build evidence pack from primary raw finding
  const evidencePack = primaryRaw?.evidencePack;

  // Generate curl command — prefer evidencePack's curlCommand, then generate from raw finding
  const curlCommand = evidencePack?.curlCommand ?? (primaryRaw ? generateCurlCommand(primaryRaw) : undefined);

  return `
    <div class="finding ${finding.severity}">
      <h3>#${index} <span class="sev-badge sev-${finding.severity}">${finding.severity.toUpperCase()}</span> ${escapeHtml(finding.title)}</h3>
      <div class="owasp">${escapeHtml(finding.owaspCategory)} | Confidence: ${finding.confidence}
        <span class="cvss-badge cvss-${cvss.rating.toLowerCase()}">${cvss.score.toFixed(1)} ${cvss.rating}</span>
        <span class="cvss-vector">${escapeHtml(cvss.vector)}</span>
      </div>
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
      ${renderEvidenceSection(primaryRaw, evidencePack, curlCommand)}
    </div>`;
}

function renderEvidenceSection(
  rawFinding: RawFinding | undefined,
  evidencePack: EvidencePack | undefined,
  curlCommand: string | undefined,
): string {
  // If there's no raw finding at all, skip the evidence section
  if (!rawFinding && !evidencePack && !curlCommand) return '';

  const parts: string[] = [];
  parts.push('<div class="evidence-section">');
  parts.push('<h4>Evidence</h4>');

  // Payload and detection method tags
  const tags: string[] = [];
  if (evidencePack?.payloadUsed) {
    tags.push(`<span class="payload-tag">${escapeHtml(evidencePack.payloadUsed)}</span>`);
  }
  if (evidencePack?.detectionMethod) {
    tags.push(`<span class="detection-tag">${escapeHtml(evidencePack.detectionMethod)}</span>`);
  }
  if (tags.length > 0) {
    parts.push(`<p>${tags.join(' ')}</p>`);
  }

  // Response indicators
  if (evidencePack?.responseIndicators && evidencePack.responseIndicators.length > 0) {
    parts.push('<p><span class="label">Indicators:</span></p>');
    parts.push('<ul class="urls">');
    for (const indicator of evidencePack.responseIndicators.slice(0, 5)) {
      parts.push(`  <li>${escapeHtml(indicator)}</li>`);
    }
    parts.push('</ul>');
  }

  // Reproduction URL
  if (evidencePack?.reproductionUrl) {
    parts.push(`<p><span class="label">Reproduction URL:</span> <code>${escapeHtml(evidencePack.reproductionUrl)}</code></p>`);
  }

  // Curl command — collapsible
  if (curlCommand) {
    parts.push(`<details class="evidence-detail">
  <summary>Curl Command</summary>
  <pre><code>${escapeHtml(curlCommand)}</code></pre>
</details>`);
  }

  // HTTP Exchange — collapsible
  if (evidencePack?.httpExchange) {
    const exchange = evidencePack.httpExchange;
    const reqParts: string[] = [];
    reqParts.push(`${exchange.request.method} ${exchange.request.url}`);
    if (exchange.request.headers) {
      for (const [key, value] of Object.entries(exchange.request.headers)) {
        reqParts.push(`${key}: ${value}`);
      }
    }
    if (exchange.request.body) {
      reqParts.push('');
      reqParts.push(exchange.request.body);
    }

    const resParts: string[] = [];
    resParts.push(`HTTP ${exchange.response.status}`);
    if (exchange.response.headers) {
      for (const [key, value] of Object.entries(exchange.response.headers)) {
        resParts.push(`${key}: ${value}`);
      }
    }
    if (exchange.response.body) {
      resParts.push('');
      // Truncate large response bodies
      const body = exchange.response.body.length > 2000
        ? exchange.response.body.slice(0, 2000) + '\n... (truncated)'
        : exchange.response.body;
      resParts.push(body);
    }

    parts.push(`<details class="evidence-detail">
  <summary>HTTP Exchange</summary>
  <pre><code>${escapeHtml('--- REQUEST ---\n' + reqParts.join('\n') + '\n\n--- RESPONSE ---\n' + resParts.join('\n'))}</code></pre>
</details>`);
  }

  // Screenshot reference
  if (evidencePack?.screenshotPath) {
    parts.push(`<p class="screenshot-note">Screenshot captured: ${escapeHtml(evidencePack.screenshotPath)}</p>`);
  }

  parts.push('</div>');
  return parts.join('\n      ');
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// severityOrder and formatDuration imported from shared utils

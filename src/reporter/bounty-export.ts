import type { InterpretedFinding, RawFinding, EvidencePack } from '../scanner/types.js';

interface ExportContext {
  rawFindings?: RawFinding[];
}

/**
 * Format a finding for HackerOne submission.
 * Produces copy-paste ready markdown with HTTP evidence.
 */
export function formatForHackerOne(finding: InterpretedFinding, ctx?: ExportContext): string {
  const lines: string[] = [];
  const evidencePack = getEvidencePack(finding, ctx);

  lines.push(`## ${finding.title}`);
  lines.push('');

  const h1Severity = mapToHackerOneSeverity(finding.severity);
  lines.push(`**Severity:** ${h1Severity}`);
  lines.push(`**Weakness:** ${finding.owaspCategory}`);
  lines.push(`**Asset:** ${finding.affectedUrls?.[0] ?? 'N/A'}`);
  lines.push('');

  // Summary
  lines.push('### Summary');
  lines.push('');
  lines.push(finding.description);
  lines.push('');

  // Steps to Reproduce
  lines.push('### Steps To Reproduce');
  lines.push('');
  if (finding.reproductionSteps.length > 0) {
    for (let i = 0; i < finding.reproductionSteps.length; i++) {
      lines.push(`${i + 1}. ${finding.reproductionSteps[i]}`);
    }
  } else {
    lines.push('1. Navigate to the affected URL');
    lines.push('2. Observe the vulnerability');
  }
  lines.push('');

  // Curl command for easy reproduction
  if (evidencePack?.curlCommand) {
    lines.push('**Quick reproduction:**');
    lines.push('');
    lines.push('```bash');
    lines.push(evidencePack.curlCommand);
    lines.push('```');
    lines.push('');
  }

  // Supporting Material / PoC — HTTP evidence
  lines.push('### Supporting Material/References');
  lines.push('');

  if (evidencePack?.httpExchange) {
    const { request, response } = evidencePack.httpExchange;
    lines.push('**Request:**');
    lines.push('```http');
    lines.push(`${request.method} ${request.url} HTTP/1.1`);
    if (request.headers) {
      for (const [k, v] of Object.entries(request.headers)) {
        lines.push(`${k}: ${v}`);
      }
    }
    if (request.body) {
      lines.push('');
      lines.push(request.body);
    }
    lines.push('```');
    lines.push('');

    if (response) {
      lines.push('**Response:**');
      lines.push('```http');
      lines.push(`HTTP/1.1 ${response.status}`);
      if (response.headers) {
        for (const [k, v] of Object.entries(response.headers)) {
          lines.push(`${k}: ${v}`);
        }
      }
      if (response.body) {
        lines.push('');
        const body = response.body.length > 500
          ? response.body.slice(0, 500) + '\n[...truncated]'
          : response.body;
        lines.push(body);
      }
      lines.push('```');
      lines.push('');
    }
  } else if (finding.codeExample) {
    lines.push('```');
    lines.push(finding.codeExample);
    lines.push('```');
    lines.push('');
  }

  if (evidencePack?.payloadUsed) {
    lines.push(`**Payload used:** \`${evidencePack.payloadUsed}\``);
    lines.push('');
  }

  // Impact
  lines.push('### Impact');
  lines.push('');
  lines.push(finding.impact);
  lines.push('');

  // Affected URLs
  if (finding.affectedUrls.length > 0) {
    lines.push('### Affected URLs');
    lines.push('');
    for (const url of finding.affectedUrls.slice(0, 10)) {
      lines.push(`- ${url}`);
    }
    if (finding.affectedUrls.length > 10) {
      lines.push(`- ... and ${finding.affectedUrls.length - 10} more`);
    }
    lines.push('');
  }

  // Suggested Fix
  lines.push('### Suggested Fix');
  lines.push('');
  lines.push(finding.suggestedFix);
  lines.push('');

  return lines.join('\n');
}

/**
 * Format a finding for Bugcrowd submission.
 * Produces copy-paste ready markdown with HTTP evidence.
 */
export function formatForBugcrowd(finding: InterpretedFinding, ctx?: ExportContext): string {
  const lines: string[] = [];
  const evidencePack = getEvidencePack(finding, ctx);

  lines.push(`# ${finding.title}`);
  lines.push('');

  const bcPriority = mapToBugcrowdPriority(finding.severity);
  lines.push(`**Priority:** ${bcPriority}`);
  lines.push(`**Vulnerability Type:** ${finding.owaspCategory}`);
  lines.push(`**URL:** ${finding.affectedUrls?.[0] ?? 'N/A'}`);
  lines.push(`**Confidence:** ${finding.confidence}`);
  lines.push('');

  // Description
  lines.push('## Description');
  lines.push('');
  lines.push(finding.description);
  lines.push('');

  // Proof of Concept
  lines.push('## Proof of Concept');
  lines.push('');
  if (finding.reproductionSteps.length > 0) {
    for (let i = 0; i < finding.reproductionSteps.length; i++) {
      lines.push(`${i + 1}. ${finding.reproductionSteps[i]}`);
    }
  } else {
    lines.push('1. Navigate to the affected URL');
    lines.push('2. Observe the vulnerability');
  }
  lines.push('');

  // Curl reproduction
  if (evidencePack?.curlCommand) {
    lines.push('**Reproduce:**');
    lines.push('```bash');
    lines.push(evidencePack.curlCommand);
    lines.push('```');
    lines.push('');
  }

  // HTTP Request/Response
  lines.push('## HTTP Request/Response');
  lines.push('');

  if (evidencePack?.httpExchange) {
    const { request, response } = evidencePack.httpExchange;
    lines.push('```http');
    lines.push(`${request.method} ${request.url} HTTP/1.1`);
    if (request.headers) {
      for (const [k, v] of Object.entries(request.headers)) {
        lines.push(`${k}: ${v}`);
      }
    }
    if (request.body) {
      lines.push('');
      lines.push(request.body);
    }
    lines.push('```');
    lines.push('');
    if (response) {
      lines.push('```http');
      lines.push(`HTTP/1.1 ${response.status}`);
      if (response.headers) {
        for (const [k, v] of Object.entries(response.headers)) {
          lines.push(`${k}: ${v}`);
        }
      }
      if (response.body) {
        lines.push('');
        const body = response.body.length > 500
          ? response.body.slice(0, 500) + '\n[...truncated]'
          : response.body;
        lines.push(body);
      }
      lines.push('```');
      lines.push('');
    }
  } else if (finding.codeExample) {
    lines.push('```http');
    lines.push(finding.codeExample);
    lines.push('```');
    lines.push('');
  } else {
    lines.push('*No HTTP exchange captured for this finding.*');
    lines.push('');
  }

  // Impact
  lines.push('## Impact');
  lines.push('');
  lines.push(finding.impact);
  lines.push('');

  // Affected Endpoints
  if (finding.affectedUrls.length > 0) {
    lines.push('## Affected Endpoints');
    lines.push('');
    for (const url of finding.affectedUrls.slice(0, 10)) {
      lines.push(`- ${url}`);
    }
    if (finding.affectedUrls.length > 10) {
      lines.push(`- ... and ${finding.affectedUrls.length - 10} more`);
    }
    lines.push('');
  }

  // Remediation
  lines.push('## Remediation');
  lines.push('');
  lines.push(finding.suggestedFix);
  lines.push('');

  return lines.join('\n');
}

/**
 * Look up the best evidence pack from raw findings backing an interpreted finding.
 */
function getEvidencePack(
  finding: InterpretedFinding,
  ctx?: ExportContext,
): EvidencePack | undefined {
  if (!ctx?.rawFindings || !finding.rawFindingIds?.length) return undefined;

  const rawMap = new Map<string, RawFinding>();
  for (const raw of ctx.rawFindings) {
    rawMap.set(raw.id, raw);
  }

  for (const id of finding.rawFindingIds) {
    const raw = rawMap.get(id);
    if (raw?.evidencePack) return raw.evidencePack;
  }

  return undefined;
}

function mapToHackerOneSeverity(severity: string): string {
  switch (severity) {
    case 'critical': return 'Critical (9.0-10.0)';
    case 'high': return 'High (7.0-8.9)';
    case 'medium': return 'Medium (4.0-6.9)';
    case 'low': return 'Low (0.1-3.9)';
    case 'info': return 'None (Informational)';
    default: return 'None (Informational)';
  }
}

function mapToBugcrowdPriority(severity: string): string {
  switch (severity) {
    case 'critical': return 'P1 - Critical';
    case 'high': return 'P2 - High';
    case 'medium': return 'P3 - Medium';
    case 'low': return 'P4 - Low';
    case 'info': return 'P5 - Informational';
    default: return 'P5 - Informational';
  }
}

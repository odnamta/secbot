import type { InterpretedFinding } from '../scanner/types.js';

/**
 * Format a finding for HackerOne submission.
 * Produces copy-paste ready markdown.
 */
export function formatForHackerOne(finding: InterpretedFinding): string {
  const lines: string[] = [];

  lines.push(`## ${finding.title}`);
  lines.push('');

  // Severity mapping for HackerOne taxonomy
  const h1Severity = mapToHackerOneSeverity(finding.severity);
  lines.push(`**Severity:** ${h1Severity}`);
  lines.push(`**Weakness:** ${finding.owaspCategory}`);
  lines.push(`**Asset:** ${finding.affectedUrls?.[0] ?? 'N/A'}`);
  lines.push('');

  // Description
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

  // Supporting Material / PoC
  if (finding.codeExample) {
    lines.push('### Supporting Material/References');
    lines.push('');
    lines.push('```');
    lines.push(finding.codeExample);
    lines.push('```');
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
 * Produces copy-paste ready markdown.
 */
export function formatForBugcrowd(finding: InterpretedFinding): string {
  const lines: string[] = [];

  lines.push(`# ${finding.title}`);
  lines.push('');

  // Bugcrowd uses P1-P5 priority ratings
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

  // HTTP Request/Response
  if (finding.codeExample) {
    lines.push('## HTTP Request/Response');
    lines.push('');
    lines.push('```http');
    lines.push(finding.codeExample);
    lines.push('```');
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

import type {
  RawFinding,
  InterpretedFinding,
  ScanSummary,
  Severity,
} from '../scanner/types.js';

/** Rule-based fallback when no AI is available */
export function fallbackInterpretation(rawFindings: RawFinding[]): {
  findings: InterpretedFinding[];
  summary: ScanSummary;
} {
  if (rawFindings.length === 0) {
    return {
      findings: [],
      summary: {
        totalRawFindings: 0,
        totalInterpretedFindings: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        topIssues: ['No vulnerabilities found'],
      },
    };
  }

  // Deduplicate by category + title
  const grouped = new Map<string, RawFinding[]>();
  for (const f of rawFindings) {
    const key = `${f.category}:${f.title}`;
    const existing = grouped.get(key) ?? [];
    existing.push(f);
    grouped.set(key, existing);
  }

  const findings: InterpretedFinding[] = [];
  for (const [, group] of grouped) {
    const first = group[0];
    findings.push({
      title: first.title,
      severity: first.severity,
      confidence: 'medium',
      owaspCategory: mapToOwasp(first.category),
      description: first.description,
      impact: getGenericImpact(first.category),
      reproductionSteps: [
        `1. Navigate to ${first.url}`,
        `2. Inspect the ${first.category} finding`,
        `3. Evidence: ${first.evidence}`,
      ],
      suggestedFix: getGenericFix(first.category),
      affectedUrls: [...new Set(group.map((f) => f.url))],
      rawFindingIds: group.map((f) => f.id),
    });
  }

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    bySeverity[f.severity]++;
  }

  return {
    findings,
    summary: {
      totalRawFindings: rawFindings.length,
      totalInterpretedFindings: findings.length,
      bySeverity,
      topIssues: findings
        .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
        .slice(0, 3)
        .map((f) => f.title),
    },
  };
}

export function severityOrder(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}

export function mapToOwasp(category: string): string {
  const map: Record<string, string> = {
    'security-headers': 'A05:2021 - Security Misconfiguration',
    'cookie-flags': 'A05:2021 - Security Misconfiguration',
    'info-leakage': 'A05:2021 - Security Misconfiguration',
    'mixed-content': 'A02:2021 - Cryptographic Failures',
    'sensitive-url-data': 'A02:2021 - Cryptographic Failures',
    xss: 'A03:2021 - Injection',
    sqli: 'A03:2021 - Injection',
    'open-redirect': 'A01:2021 - Broken Access Control',
    'cors-misconfiguration': 'A05:2021 - Security Misconfiguration',
    'directory-traversal': 'A01:2021 - Broken Access Control',
    idor: 'A01:2021 - Broken Access Control',
    tls: 'A02:2021 - Cryptographic Failures',
  };
  return map[category] ?? 'Unknown';
}

export function getGenericImpact(category: string): string {
  const map: Record<string, string> = {
    'security-headers': 'Missing security headers reduce defense-in-depth, making other attacks easier to exploit.',
    'cookie-flags': 'Insecure cookies can be stolen or manipulated, potentially leading to session hijacking.',
    'info-leakage': 'Exposed server information helps attackers identify specific vulnerabilities to exploit.',
    'mixed-content': 'HTTP resources on HTTPS pages can be intercepted and modified by attackers.',
    'sensitive-url-data': 'Sensitive data in URLs is logged in server logs, browser history, and may leak via Referer headers.',
    xss: 'An attacker can execute JavaScript in victims\' browsers, stealing sessions, credentials, or performing actions as the user.',
    sqli: 'An attacker can read, modify, or delete database contents, potentially taking full control of the application.',
    'open-redirect': 'Attackers can redirect users to malicious sites, enabling phishing and credential theft.',
    'cors-misconfiguration': 'Attackers can read authenticated API responses from their own malicious website.',
    'directory-traversal': 'Attackers can read arbitrary files from the server, including configuration and credentials.',
  };
  return map[category] ?? 'Unknown impact.';
}

export function getGenericFix(category: string): string {
  const map: Record<string, string> = {
    'security-headers': 'Add the recommended security headers to your web server or application middleware configuration.',
    'cookie-flags': 'Set HttpOnly, Secure, and SameSite=Strict flags on all session cookies.',
    'info-leakage': 'Remove version information from Server and X-Powered-By headers. Configure custom error pages.',
    'mixed-content': 'Ensure all resources are loaded over HTTPS. Use Content-Security-Policy to enforce.',
    'sensitive-url-data': 'Move sensitive data from URL parameters to POST request bodies or headers.',
    xss: 'Sanitize and encode all user input before rendering. Use a Content-Security-Policy header.',
    sqli: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL.',
    'open-redirect': 'Validate redirect URLs against an allowlist of trusted domains.',
    'cors-misconfiguration': 'Configure CORS to allow only specific trusted origins, not wildcards with credentials.',
    'directory-traversal': 'Validate and sanitize file path inputs. Use allowlists for permitted paths.',
  };
  return map[category] ?? 'Review and fix the identified vulnerability.';
}

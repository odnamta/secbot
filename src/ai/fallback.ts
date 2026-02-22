import type {
  RawFinding,
  InterpretedFinding,
  ScanSummary,
  Severity,
} from '../scanner/types.js';
import { severityOrder } from '../utils/shared.js';

/** Rule-based fallback when no AI is available */
export function fallbackInterpretation(rawFindings: RawFinding[], passedChecks?: string[]): {
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
        passedChecks: passedChecks ?? [],
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
      passedChecks: passedChecks ?? [],
    },
  };
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
    ssrf: 'A10:2021 - Server-Side Request Forgery',
    ssti: 'A03:2021 - Injection',
    'command-injection': 'A03:2021 - Injection',
    idor: 'A01:2021 - Broken Access Control',
    tls: 'A02:2021 - Cryptographic Failures',
    sri: 'A08:2021 - Software and Data Integrity Failures',
    'cross-origin-policy': 'A05:2021 - Security Misconfiguration',
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
    ssrf: 'An attacker can make the server send requests to internal services, potentially accessing cloud metadata, internal APIs, or pivoting to internal networks.',
    ssti: 'An attacker can execute arbitrary code on the server through template engine injection, leading to full server compromise.',
    'command-injection': 'An attacker can execute arbitrary OS commands on the server, leading to full system compromise.',
    idor: 'An attacker can access, modify, or delete other users\' data by manipulating object references (IDs) in requests.',
    tls: 'Weak TLS configuration allows attackers to intercept or downgrade encrypted communications, exposing sensitive data in transit.',
    sri: 'External resources loaded without integrity verification can be tampered with if the CDN or third-party host is compromised.',
    'cross-origin-policy': 'Missing cross-origin isolation policies allow cross-origin attacks like Spectre to read sensitive data from the application.',
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
    ssrf: 'Validate and restrict URLs to allowed domains/IPs. Block internal/private IP ranges. Use an allowlist for permitted URL schemes and hosts.',
    ssti: 'Avoid passing user input directly into template engines. Use sandboxed template environments. Prefer logic-less templates (e.g., Mustache).',
    'command-injection': 'Never pass user input to shell commands. Use language-native APIs instead of shell exec. If unavoidable, use strict allowlists and escape all input.',
    idor: 'Implement proper authorization checks on every object access. Use non-sequential, unpredictable identifiers (UUIDs). Verify the authenticated user owns the requested resource.',
    tls: 'Use TLS 1.2+ only. Disable weak cipher suites. Enable HSTS with a long max-age. Use certificates from trusted CAs and keep them up to date.',
    sri: 'Add integrity attributes to all external <script> and <link> tags. Use the crossorigin="anonymous" attribute. Generate hashes with shasum or online SRI generators.',
    'cross-origin-policy': 'Set Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and Cross-Origin-Resource-Policy headers to enable cross-origin isolation.',
  };
  return map[category] ?? 'Review and fix the identified vulnerability.';
}

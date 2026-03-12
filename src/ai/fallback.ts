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
    'info-disclosure': 'A01:2021 - Broken Access Control',
    'js-cve': 'A06:2021 - Vulnerable and Outdated Components',
    'crlf-injection': 'A03:2021 - Injection',
    'rate-limit': 'A07:2021 - Identification and Authentication Failures',
    jwt: 'A07:2021 - Identification and Authentication Failures',
    'race-condition': 'A04:2021 - Insecure Design',
    graphql: 'A01:2021 - Broken Access Control',
    'host-header': 'A05:2021 - Security Misconfiguration',
    'file-upload': 'A04:2021 - Insecure Design',
    'broken-access-control': 'A01:2021 - Broken Access Control',
    'business-logic': 'A04:2021 - Insecure Design',
    websocket: 'A07:2021 - Identification and Authentication Failures',
    'api-versioning': 'A05:2021 - Security Misconfiguration',
    'vuln-chain': 'A01:2021 - Broken Access Control',
    'subdomain-takeover': 'A05:2021 - Security Misconfiguration',
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
    'info-disclosure': 'Exposed files such as .git, .env, or source maps reveal internal paths, credentials, and source code to attackers.',
    'js-cve': 'Known vulnerabilities in outdated JavaScript libraries can be exploited using publicly available exploit code.',
    'crlf-injection': 'Injecting CR/LF characters into HTTP headers enables response splitting, cache poisoning, and session fixation.',
    'rate-limit': 'Missing rate limiting allows attackers to brute-force credentials, OTPs, or overwhelm the application with automated requests.',
    jwt: 'Weak JWT implementation allows attackers to forge tokens, bypass authentication, or escalate privileges.',
    'race-condition': 'Concurrent request abuse can exploit time-of-check to time-of-use gaps, causing duplicate transactions or state corruption.',
    graphql: 'Exposed introspection, missing depth limits, or unprotected mutations allow attackers to extract the full schema and abuse sensitive operations.',
    'host-header': 'Host header injection enables cache poisoning, password reset hijacking, and server-side request routing manipulation.',
    'file-upload': 'Unrestricted file upload allows attackers to upload web shells, polyglot files, or malicious content leading to remote code execution.',
    'broken-access-control': 'Missing or insufficient access controls allow attackers to access admin endpoints, bypass authorization, or escalate privileges.',
    'business-logic': 'Flaws in application logic allow attackers to manipulate prices, bypass workflow steps, or abuse intended functionality.',
    websocket: 'Insecure WebSocket connections allow attackers to hijack sessions, inject messages, or bypass authentication checks.',
    'api-versioning': 'Deprecated or unpatched API versions may lack security fixes present in current versions, exposing legacy vulnerabilities.',
    'vuln-chain': 'Combining multiple lower-severity vulnerabilities creates a higher-impact attack chain that bypasses individual mitigations.',
    'subdomain-takeover': 'An attacker can register the unclaimed cloud resource and serve malicious content, phishing pages, or steal cookies from a trusted subdomain of your domain.',
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
    'info-disclosure': 'Block public access to .git, .env, source maps, and backup files via web server rules and ensure sensitive files are outside the web root.',
    'js-cve': 'Update vulnerable JavaScript libraries to patched versions and use automated dependency scanning (e.g., npm audit) in your CI pipeline.',
    'crlf-injection': 'Strip or reject CR (\\r) and LF (\\n) characters from all user input used in HTTP headers or redirect URLs.',
    'rate-limit': 'Implement rate limiting on authentication and sensitive API endpoints using token bucket or sliding window algorithms.',
    jwt: 'Use strong signing algorithms (RS256/ES256), enforce token expiry, validate all claims server-side, and never store sensitive data in JWT payloads.',
    'race-condition': 'Use database-level locking, idempotency keys, or serialized transactions to prevent concurrent request abuse on state-changing operations.',
    graphql: 'Disable introspection in production, enforce query depth and complexity limits, and require authorization on all mutations.',
    'host-header': 'Validate the Host header against an allowlist of expected domains and ignore X-Forwarded-Host from untrusted sources.',
    'file-upload': 'Validate file type by content (magic bytes), enforce size limits, rename uploaded files, store outside web root, and serve with Content-Disposition: attachment.',
    'broken-access-control': 'Implement server-side authorization checks on every request, deny by default, and enforce role-based access control consistently across all endpoints.',
    'business-logic': 'Validate all business rules server-side, enforce workflow step ordering, re-verify prices and quantities at checkout, and add tamper-detection on critical operations.',
    websocket: 'Authenticate WebSocket connections on handshake, validate and sanitize all incoming messages, and use WSS (TLS) for transport encryption.',
    'api-versioning': 'Deprecate and disable old API versions, apply the same security patches across all active versions, and redirect clients to the latest version.',
    'vuln-chain': 'Address each individual vulnerability in the chain; fixing any single link breaks the entire attack path.',
    'subdomain-takeover': 'Remove the dangling CNAME DNS record immediately, or claim the resource on the target service to prevent takeover. Audit all subdomain CNAMEs regularly.',
  };
  return map[category] ?? 'Review and fix the identified vulnerability.';
}

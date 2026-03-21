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
    oauth: 'A07:2021 - Identification and Authentication Failures',
    'cache-poisoning': 'A05:2021 - Security Misconfiguration',
    csrf: 'A01:2021 - Broken Access Control',
    'prototype-pollution': 'A03:2021 - Injection',
    xxe: 'A05:2021 - Security Misconfiguration',
    'insecure-deserialization': 'A08:2021 - Software and Data Integrity Failures',
    'request-smuggling': 'A05:2021 - Security Misconfiguration',
    'ldap-injection': 'A03:2021 - Injection',
    'content-type-confusion': 'A01:2021 - Broken Access Control',
    'method-override': 'A01:2021 - Broken Access Control',
    'email-injection': 'A03:2021 - Injection',
    bfla: 'A01:2021 - Broken Access Control',
    clickjacking: 'A05:2021 - Security Misconfiguration',
    'timing-attack': 'A07:2021 - Identification and Authentication Failures',
    'verbose-errors': 'A05:2021 - Security Misconfiguration',
    'xpath-injection': 'A03:2021 - Injection',
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
    oauth: 'Flaws in the OAuth flow allow attackers to perform CSRF attacks to link victim accounts, steal authorization codes via redirect_uri bypass, or harvest tokens from URL logs and Referer headers.',
    'cache-poisoning': 'An attacker can poison the cache with a crafted response, causing all subsequent visitors to receive malicious content served from the cache — enabling XSS, phishing, or credential theft at scale.',
    csrf: 'Missing CSRF protection allows attackers to craft malicious pages that perform state-changing actions (password changes, transfers, profile updates) on behalf of authenticated users without their consent.',
    'prototype-pollution': 'An attacker can inject properties onto Object.prototype via __proto__ or constructor.prototype, leading to denial of service, authentication bypass, property injection, or remote code execution in Node.js applications.',
    xxe: 'An attacker can read arbitrary files from the server, perform SSRF attacks to internal services, or cause denial of service via entity expansion (billion laughs). With out-of-band techniques, even blind XXE can exfiltrate data.',
    'insecure-deserialization': 'An attacker can achieve Remote Code Execution by sending crafted serialized objects that exploit gadget chains in the application classpath. Even without RCE, deserialization of untrusted data can lead to denial of service, authentication bypass, or arbitrary object instantiation.',
    'request-smuggling': 'An attacker can smuggle requests through a proxy/CDN to bypass security controls, steal credentials from other users via request hijacking, poison the web cache to serve malicious content, or access internal-only endpoints. This is a critical infrastructure vulnerability.',
    'ldap-injection': 'An attacker can bypass authentication by injecting LDAP filter operators (wildcard, tautology), extract directory attributes (email, phone, group memberships), or enumerate valid usernames. In enterprise environments using Active Directory or OpenLDAP, this can lead to full domain compromise.',
    'content-type-confusion': 'An attacker can bypass CSRF token validation by sending requests with an unexpected Content-Type (e.g., text/plain, which browsers send without CORS preflight). If the server processes the body but skips CSRF checks for non-form content types, any state-changing action can be performed cross-origin without the victim\'s consent.',
    'method-override': 'An attacker can bypass access controls by sending a POST request with X-HTTP-Method-Override: DELETE (or PUT/PATCH). If the ACL only checks the HTTP method but the framework routes based on the override header, the attacker can perform unauthorized destructive operations like account deletion or privilege escalation.',
    'email-injection': 'An attacker can inject additional SMTP headers (Bcc, Cc, Subject) into outgoing emails by embedding CRLF sequences in form fields. This turns the application\'s mail server into a spam relay, enables phishing from a trusted domain, and can bypass email-based security controls.',
    bfla: 'An attacker can access admin-only API functions (export, bulk-delete, config, user management) by probing undocumented endpoints inferred from the API structure. Missing function-level authorization lets any authenticated user execute privileged operations, leading to data exfiltration, mass deletion, or full account takeover.',
    clickjacking: 'An attacker can embed the target page in a transparent iframe on a malicious site, tricking users into clicking hidden buttons or links. This enables unauthorized actions (fund transfers, settings changes, account deletion) performed under the victim\'s authenticated session without their knowledge.',
    'timing-attack': 'An attacker can enumerate valid usernames by measuring authentication response times. Consistent timing differences between valid and invalid usernames reveal which accounts exist, enabling targeted attacks (credential stuffing, phishing, password spraying) against confirmed accounts.',
    'verbose-errors': 'Verbose error messages expose internal application details — stack traces reveal file paths and code structure, debug pages show configuration and environment variables, and database errors leak query structure and schema information. Attackers use this reconnaissance to craft targeted exploits.',
    'xpath-injection': 'An attacker can manipulate XPath queries to bypass authentication, extract sensitive data from XML documents, or enumerate the XML structure. XPath injection in authentication systems often allows login bypass via tautology attacks (e.g., \' or \'1\'=\'1). Unlike SQL injection, XPath has no permission model — successful injection gives access to the entire XML document.',
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
    oauth: 'Always require and validate the state parameter in OAuth authorization requests. Enforce a strict allowlist of registered redirect_uri values. Never include access tokens in URL parameters — use response_mode=fragment only when necessary and prefer response_mode=form_post for server-side flows.',
    'cache-poisoning': 'Ensure all user-controlled headers that affect the response are included in the cache key. Validate and normalize Host and forwarding headers server-side. Use Vary headers correctly and consider using cache-busting techniques for sensitive endpoints.',
    csrf: 'Add CSRF tokens to all state-changing forms. Use the Synchronizer Token pattern or Double Submit Cookie pattern. Set SameSite=Strict on session cookies. For APIs, require custom headers (e.g., X-Requested-With) that cannot be sent cross-origin without CORS approval.',
    'prototype-pollution': 'Use Object.create(null) for dictionaries instead of plain objects. Freeze Object.prototype with Object.freeze(Object.prototype). Sanitize __proto__ and constructor keys from all user input. Use Map instead of objects for key-value stores. Avoid recursive merge functions (lodash.merge, jQuery.extend deep) on untrusted input.',
    xxe: 'Disable external entity processing in the XML parser configuration. In Java: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true). In PHP: libxml_disable_entity_loader(true). In .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit. Use JSON instead of XML where possible.',
    'insecure-deserialization': 'Never deserialize untrusted input. In Java: avoid ObjectInputStream on user data, use allowlists with ObjectInputFilter (JEP 290). In PHP: avoid unserialize() on user input, use json_decode() instead. In Python: never use pickle on untrusted data, use JSON. In .NET: avoid BinaryFormatter and TypeNameHandling.Auto in Newtonsoft.Json. Use language-agnostic formats (JSON, protobuf) for data exchange.',
    'request-smuggling': 'Normalize Content-Length and Transfer-Encoding handling across all layers. Configure the front-end proxy to reject ambiguous requests (both CL and TE headers). Use HTTP/2 end-to-end to eliminate smuggling. Disable connection reuse between proxy and backend if smuggling is confirmed. Deploy HAProxy/Nginx with strict HTTP parsing.',
    'ldap-injection': 'Never concatenate user input into LDAP filter strings. Use parameterized LDAP queries or escape special characters (*, (, ), \\, NUL) with the LDAP-specific encoding (\\2a, \\28, \\29, \\5c, \\00). In Java use javax.naming.ldap.Rdn.escapeValue(). In PHP use ldap_escape(). In Python use ldap3.utils.conv.escape_filter_chars(). Validate input against strict allowlists for username fields.',
    'content-type-confusion': 'Validate the Content-Type header on all state-changing endpoints and reject unexpected values with 415 Unsupported Media Type. Apply CSRF token validation regardless of content type — not just for application/x-www-form-urlencoded. Use SameSite=Strict cookies for additional defense-in-depth.',
    'method-override': 'Disable HTTP method override headers (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override) and _method parameters in production. If method override is required, apply access control checks after the method override is resolved, not before. Configure the framework to only accept explicit HTTP methods.',
    'email-injection': 'Sanitize all user input used in email headers by stripping CR (\\r) and LF (\\n) characters. Use email library APIs that handle header encoding safely (e.g., PHPMailer, Nodemailer) rather than manual header construction. Validate email addresses against a strict pattern and reject any containing newlines.',
    bfla: 'Implement function-level authorization checks on every API endpoint, not just URL-based access control. Use a centralized authorization middleware that verifies the caller\'s role has explicit permission for the requested operation. Deny by default — require explicit grants. Remove or disable admin/debug/internal endpoints in production. Use role-based access control (RBAC) or attribute-based access control (ABAC) consistently across all API functions.',
    clickjacking: 'Add `Content-Security-Policy: frame-ancestors \'none\'` to all responses (or `\'self\'` if same-origin framing is required). Also set `X-Frame-Options: DENY` or `SAMEORIGIN` for legacy browser compatibility. CSP frame-ancestors supersedes X-Frame-Options in modern browsers. Apply these headers to ALL pages, especially sensitive endpoints like login, settings, and payment pages.',
    'timing-attack': 'Ensure authentication endpoints take constant time regardless of input validity. Always hash a dummy password when the username is not found (constant-time operation). Use constant-time string comparison for tokens and secrets (crypto.timingSafeEqual). Return generic error messages ("Invalid credentials") instead of specific ones. Consider adding random jitter (10-50ms) to authentication responses.',
    'verbose-errors': 'Disable debug mode in production (Django DEBUG=False, Rails RAILS_ENV=production, Laravel APP_DEBUG=false, Express NODE_ENV=production). Configure custom error handlers for all HTTP status codes. Log detailed errors server-side only. Never expose stack traces, internal paths, SQL queries, or environment variables to end users.',
    'xpath-injection': 'Use parameterized XPath queries (XPath variables) instead of string concatenation. Sanitize user input by removing or escaping XPath special characters (\', ", [, ], /, @, :). Use an ORM or data access layer that handles XPath escaping. Consider switching from XML/XPath to JSON where possible to eliminate the attack surface entirely.',
  };
  return map[category] ?? 'Review and fix the identified vulnerability.';
}

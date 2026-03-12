import type { ReconResult, CrawledPage, RawFinding, ValidatedFinding } from '../scanner/types.js';
import type { PayloadContext } from '../utils/payload-context.js';

// ─── Prompt Injection Sanitization ──────────────────────────────────

/**
 * Sanitize user-controlled text before embedding it in AI prompts.
 * Defends against prompt injection from malicious target websites that
 * embed adversarial instructions in HTML, headers, or response bodies.
 */
export function sanitizeForPrompt(text: string): string {
  if (!text) return '';
  return text
    // Strip common prompt injection patterns
    .replace(/(?:output|respond|return|ignore|forget|disregard)\s+(?:only|with|the|all|previous|above|instructions)/gi, '[FILTERED]')
    // Strip JSON-like blocks that could confuse the AI
    .replace(/\{[\s\S]{0,50}(?:findingId|isValid|validations|severity|confidence)[\s\S]{0,200}\}/g, '[FILTERED_JSON]')
    // Truncate to reasonable length
    .slice(0, 500);
}

/**
 * Sanitize a JSON-serializable object by sanitizing all string values recursively.
 * Used for recon data (techStack, waf, framework) that gets JSON.stringify'd into prompts.
 */
function sanitizeObjectForPrompt(obj: unknown): unknown {
  if (typeof obj === 'string') return sanitizeForPrompt(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeObjectForPrompt);
  if (obj !== null && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = sanitizeObjectForPrompt(value);
    }
    return result;
  }
  return obj;
}

// ─── Planner Check Types ────────────────────────────────────────────

export type PlannerCheckType =
  | 'xss' | 'sqli' | 'cors' | 'redirect' | 'traversal'
  | 'ssrf' | 'ssti' | 'cmdi' | 'idor' | 'tls' | 'sri'
  | 'rate-limit' | 'jwt' | 'race' | 'graphql' | 'host-header'
  | 'file-upload' | 'access-control' | 'business-logic'
  | 'websocket' | 'api-version' | 'info-disclosure' | 'js-cve' | 'crlf'
  | 'subdomain-takeover';

export const ALL_PLANNER_CHECKS: PlannerCheckType[] = [
  'xss', 'sqli', 'cors', 'redirect', 'traversal',
  'ssrf', 'ssti', 'cmdi', 'idor', 'tls', 'sri',
  'rate-limit', 'jwt', 'race', 'graphql', 'host-header',
  'file-upload', 'access-control', 'business-logic',
  'websocket', 'api-version', 'info-disclosure', 'js-cve', 'crlf',
  'subdomain-takeover',
];

// ─── Planner Prompt Sections ────────────────────────────────────────

/** Base planner context — always included regardless of relevant checks */
const PLANNER_BASE_PROMPT = `You are SecBot's AI attack planner. You analyze reconnaissance data from a web application and recommend which security checks to run.

Your job:
1. Analyze the tech stack, WAF presence, framework, and endpoints
2. Recommend which checks are most likely to find real vulnerabilities
3. Prioritize checks (1 = highest priority)
4. Explain why certain checks should be skipped

Rules:
- If a WAF is detected with high confidence, lower priority of checks that WAFs typically block (XSS, SQLi, SSTI, CMDi)
- For "quick" profile, recommend max 3 checks
- For "standard" profile, recommend max 6 checks
- For "deep" profile, recommend all applicable checks

Output ONLY valid JSON matching this schema:
{
  "recommendedChecks": [
    { "name": "string", "priority": number, "reason": "string", "focusAreas": ["string"] }
  ],
  "reasoning": "string - overall analysis",
  "skipReasons": { "checkName": "reason for skipping" }
}`;

/** Per-check description sections for the planner system prompt */
const CHECK_SECTIONS: Record<PlannerCheckType, string> = {
  xss: `- xss: Cross-site scripting — test forms and URL parameters for reflected/stored XSS
  Rule: If no forms exist and no URL parameters, skip. If WAF detected, lower priority.`,

  sqli: `- sqli: SQL injection — test form inputs and URL parameters for SQL injection
  Rule: If no forms exist, skip. If WAF detected, lower priority.`,

  cors: `- cors: CORS misconfiguration — test if cross-origin requests are improperly allowed
  Rule: Always recommend (low cost, high value).`,

  redirect: `- redirect: Open redirect — test redirect parameters for open redirect vulnerabilities
  Rule: If no redirect parameters exist, skip.`,

  traversal: `- traversal: Directory traversal — test file-like parameters for path traversal attacks
  Rule: If no API endpoints exist, skip.`,

  ssrf: `- ssrf: Server-side request forgery — test URL-accepting parameters for internal network access
  Rule: Recommend when URL-accepting parameters are detected (url, link, src, image, proxy).`,

  ssti: `- ssti: Server-side template injection — test inputs for template engine code execution
  Rule: Recommend when a template engine is detected (Jinja, Django, Flask, Express, EJS, Pug) or forms exist. If WAF detected, lower priority.`,

  cmdi: `- cmdi: Command injection — test inputs for OS command injection
  Rule: Recommend when non-static API routes or form inputs exist. If WAF detected, lower priority.`,

  idor: `- idor: Insecure direct object reference — test sequential IDs for unauthorized access
  Rule: Recommend when sequential numeric IDs appear in URLs AND authentication is present.`,

  tls: `- tls: TLS/crypto checks — verify certificate, protocol versions, and cipher strength
  Rule: Recommend always on HTTPS targets.`,

  sri: `- sri: Subresource integrity — check external scripts/stylesheets for missing SRI hashes
  Rule: Recommend when pages have been crawled (external scripts/stylesheets are common).`,

  'rate-limit': `- rate-limit: Brute-force protection — test auth and API endpoints for rate limiting
  Rule: Recommend when forms or API endpoints exist (login forms, signup, password reset, API keys).`,

  jwt: `- jwt: JWT security — analyze tokens for none-algorithm bypass, weak secrets, missing expiry
  Rule: Recommend when JWT-like tokens detected in cookies, headers, or localStorage.`,

  race: `- race: Race condition (TOCTOU) — test state-changing endpoints for concurrent request abuse
  Rule: Recommend when forms with state-changing actions exist (checkout, transfer, coupon, vote).`,

  graphql: `- graphql: GraphQL deep check — test for introspection, depth limits, batch queries, sensitive mutations
  Rule: Recommend when /graphql endpoint discovered during recon.`,

  'host-header': `- host-header: Host header injection — test for Host, X-Forwarded-Host, cache poisoning
  Rule: Recommend always (low cost). Lower priority if CDN/WAF detected.`,

  'file-upload': `- file-upload: File upload vulnerabilities — test for shell upload, polyglot files, MIME bypass
  Rule: Recommend when forms have file inputs (type="file").`,

  'access-control': `- access-control: Broken access control — test admin endpoints as unauthenticated/low-priv user, method override, header bypass
  Rule: Recommend when admin-like URLs detected (admin, dashboard, manage, panel, settings) AND auth is configured.`,

  'business-logic': `- business-logic: Business logic flaws — test price/quantity manipulation, workflow step bypass, negative values
  Rule: Recommend when business-like form fields detected (price, quantity, amount, total, discount, coupon).`,

  websocket: `- websocket: WebSocket security — test for auth bypass, origin validation, message injection
  Rule: Recommend when WebSocket URLs (ws://, wss://) or socket.io references found.`,

  'api-version': `- api-version: API versioning — probe older API version endpoints for exposed/deprecated features
  Rule: Recommend when /api/v{N}/ patterns found in discovered routes.`,

  'info-disclosure': `- info-disclosure: Information disclosure — probe for exposed .git, .env, source maps, debug endpoints, backups
  Rule: Recommend always (low cost, high value). Run on all targets.`,

  'js-cve': `- js-cve: JavaScript library CVEs — scan for known CVEs in client-side JS libraries (jQuery, Angular, Lodash, etc.)
  Rule: Recommend when pages have been crawled (external scripts are common).`,

  crlf: `- crlf: CRLF injection — test for HTTP header injection via CR/LF characters in parameters
  Rule: Recommend when URL parameters or form inputs exist.`,

  'subdomain-takeover': `- subdomain-takeover: Dangling CNAME subdomain takeover — check for dangling CNAME records pointing to unclaimed cloud resources
  Rule: Recommend when subdomain enumeration results are available (--subdomains flag). Skip if no CNAMEs found.`,
};

/**
 * Build a planner system prompt containing only the check descriptions
 * relevant to discovered targets. Reduces token usage by omitting
 * check types that have no applicable targets.
 */
export function buildPlannerPrompt(relevantChecks: PlannerCheckType[]): string {
  const sections: string[] = [PLANNER_BASE_PROMPT];

  if (relevantChecks.length > 0) {
    const checkDescriptions = relevantChecks
      .map((check) => CHECK_SECTIONS[check])
      .join('\n');
    sections.push(`\nAvailable checks (${relevantChecks.length} applicable):\n${checkDescriptions}`);
  } else {
    sections.push('\nNo specific checks are applicable based on discovered targets.');
  }

  return sections.join('\n');
}

/**
 * @deprecated Use buildPlannerPrompt() for dynamic prompts.
 * Kept for backward compatibility — equivalent to buildPlannerPrompt(ALL_PLANNER_CHECKS).
 */
export const PLANNER_SYSTEM_PROMPT = buildPlannerPrompt(ALL_PLANNER_CHECKS);

export function buildPlannerUserPrompt(
  url: string,
  recon: ReconResult,
  pages: CrawledPage[],
  profile: string,
  payloadContext?: PayloadContext,
): string {
  const allForms = pages.flatMap((p) => p.forms);
  const urlsWithParams = pages.map((p) => p.url).filter((u) => u.includes('?'));
  const redirectParams = pages.flatMap((p) => p.links).filter((l) =>
    /[?&](url|redirect|next|return|goto|dest)=/i.test(l),
  );
  const urlAcceptingParams = allForms.filter((f) =>
    f.inputs.some((i) => /url|link|src|image|proxy/i.test(i.name)),
  );
  const numericIdUrls = recon.endpoints.apiRoutes.filter((r) => /\/\d+/.test(r));
  const isHttps = url.startsWith('https://');
  const hasFileInputs = allForms.some((f) => f.inputs.some((i) => i.type === 'file'));
  const hasWebSocket = pages.some((p) =>
    p.scripts.some((s) => /socket\.io|ws:\/\/|wss:\/\//i.test(s)) ||
    p.links.some((l) => /ws:\/\/|wss:\/\//i.test(l)),
  );
  const apiVersionUrls = recon.endpoints.apiRoutes.filter((r) => /\/api\/v\d+/i.test(r));
  const adminUrls = [...recon.endpoints.pages, ...recon.endpoints.apiRoutes].filter((r) =>
    /\/(admin|dashboard|manage|panel|settings)/i.test(r),
  );
  const businessFields = allForms.filter((f) =>
    f.inputs.some((i) => /price|quantity|amount|total|discount|coupon|qty/i.test(i.name)),
  );

  // Sanitize recon data that comes from target website responses
  const safeTechStack = sanitizeObjectForPrompt(recon.techStack);
  const safeWaf = sanitizeObjectForPrompt(recon.waf);
  const safeFramework = sanitizeObjectForPrompt(recon.framework);
  const safeApiRoutes = recon.endpoints.apiRoutes.slice(0, 5).map((r) => sanitizeForPrompt(r));

  // Build technology context section from PayloadContext
  let techContextSection = '';
  if (payloadContext) {
    const parts: string[] = [];
    if (payloadContext.databases[0] !== 'unknown') {
      parts.push(`- Detected databases: ${payloadContext.databases.join(', ')}`);
    }
    if (payloadContext.templateEngines[0] !== 'unknown') {
      parts.push(`- Template engines: ${payloadContext.templateEngines.join(', ')}`);
    }
    if (payloadContext.backendLanguages[0] !== 'unknown') {
      parts.push(`- Backend: ${payloadContext.backendLanguages.join(', ')}`);
    }
    if (payloadContext.osHint !== 'unknown') {
      parts.push(`- OS: ${payloadContext.osHint}`);
    }
    if (payloadContext.wafPresent && payloadContext.wafBypasses.length > 0) {
      parts.push(`- WAF bypasses: ${payloadContext.wafBypasses.slice(0, 5).join(', ')}`);
    }
    if (payloadContext.frameworkHints.length > 0) {
      parts.push(`- Framework hints: ${payloadContext.frameworkHints.slice(0, 3).map((h) => sanitizeForPrompt(h)).join('; ')}`);
    }
    if (payloadContext.preferDomXss) {
      parts.push('- SPA detected: prioritize DOM-based XSS');
    }
    if (parts.length > 0) {
      techContextSection = `\n\nTechnology Context (inferred from recon):\n${parts.join('\n')}`;
    }
  }

  return `Analyze this target and recommend security checks.

Target: ${url}
Profile: ${profile}

Tech Stack: ${JSON.stringify(safeTechStack, null, 2)}
WAF: ${JSON.stringify(safeWaf, null, 2)}
Framework: ${JSON.stringify(safeFramework, null, 2)}

Endpoints:
- Pages: ${recon.endpoints.pages.length}
- API routes: ${recon.endpoints.apiRoutes.length} ${recon.endpoints.apiRoutes.length > 0 ? `(${safeApiRoutes.join(', ')})` : ''}
- Forms: ${allForms.length}
- GraphQL: ${recon.endpoints.graphql.length}
- URLs with params: ${urlsWithParams.length}
- URLs with redirect params: ${redirectParams.length}
- Forms with URL-accepting inputs: ${urlAcceptingParams.length}
- API routes with numeric IDs: ${numericIdUrls.length}
- Forms with file inputs: ${hasFileInputs ? 'yes' : 'no'}
- WebSocket references: ${hasWebSocket ? 'yes' : 'no'}
- API versioned routes: ${apiVersionUrls.length}
- Admin-like URLs: ${adminUrls.length}
- Business logic forms: ${businessFields.length}
- HTTPS: ${isHttps}
- Pages crawled: ${pages.length}${techContextSection}

Available checks: ${ALL_PLANNER_CHECKS.join(', ')}

Output ONLY valid JSON.`;
}

// ─── Validator Prompts ────────────────────────────────────────────────

const VALIDATOR_BASE_PROMPT = `You are SecBot's AI vulnerability validator. You assess whether each raw finding from an automated security scanner is a true vulnerability or a false positive.

For each finding, determine:
1. Is this a real vulnerability? (isValid: true/false)
2. How confident are you? (confidence: high/medium/low)
3. Should the severity be adjusted? (adjustedSeverity: only if different from original)
4. Brief reasoning

Finding categories you may encounter:
- xss: Cross-site scripting — reflected, stored, or DOM-based script injection
- sqli: SQL injection — database query manipulation via user input
- cors-misconfiguration: Overly permissive cross-origin resource sharing
- open-redirect: Redirect parameters that accept arbitrary external URLs
- directory-traversal: Path traversal to read arbitrary server files
- ssrf: Server-side request forgery — forcing the server to make internal requests
- ssti: Server-side template injection — executing code through template engines
- command-injection: OS command injection via user-controlled input
- idor: Insecure direct object references — accessing other users' data via predictable IDs
- tls: TLS/crypto weaknesses — expired certs, weak protocols, missing HSTS
- sri: Subresource integrity — external resources loaded without integrity hashes
- security-headers: Missing or misconfigured HTTP security headers
- cookie-flags: Insecure cookie attributes (missing HttpOnly, Secure, SameSite)
- info-leakage: Exposed server version, stack traces, or debug information
- mixed-content: HTTP resources loaded on HTTPS pages
- sensitive-url-data: Sensitive data exposed in URL parameters
- vuln-chain: Vulnerability chains combining multiple lower-severity findings into attack paths

Common false positives to watch for:
- Missing security headers on static assets or CDN-served content
- CORS "issues" that are actually intentional (public APIs)
- Cookie flags on non-sensitive cookies (analytics, preferences)
- "Info leakage" that's actually standard framework behavior
- XSS/SQLi that was reflected but properly encoded
- SSRF on parameters that only accept whitelisted URLs
- SSTI where template syntax in output is just documentation/examples
- IDOR where resources are intentionally public
- TLS issues on development/localhost targets
- SRI missing on first-party same-origin scripts (lower risk)
- Command injection where input is properly sanitized/escaped

Output ONLY valid JSON matching this schema:
{
  "validations": [
    {
      "findingId": "string",
      "isValid": boolean,
      "confidence": "high|medium|low",
      "reasoning": "string",
      "adjustedSeverity": "critical|high|medium|low|info" // optional
    }
  ]
}`;

/**
 * Build a validator system prompt that optionally includes technology context
 * from recon data. When recon is available, the AI can make stack-specific
 * validation decisions instead of generic ones.
 */
export function buildValidatorSystemPrompt(recon?: ReconResult): string {
  const sections: string[] = [VALIDATOR_BASE_PROMPT];

  if (recon) {
    const techLines: string[] = [];

    if (recon.framework.name) {
      const fw = sanitizeForPrompt(recon.framework.name);
      const ver = recon.framework.version ? ` ${sanitizeForPrompt(recon.framework.version)}` : '';
      techLines.push(`- Framework: ${fw}${ver}`);
    }

    if (recon.waf.detected) {
      const wafName = sanitizeForPrompt(recon.waf.name ?? 'unknown');
      techLines.push(`- WAF: ${wafName} (confidence: ${recon.waf.confidence})`);
      if (recon.waf.recommendedTechniques && recon.waf.recommendedTechniques.length > 0) {
        const techniques = recon.waf.recommendedTechniques
          .slice(0, 5)
          .map((t) => sanitizeForPrompt(t))
          .join(', ');
        techLines.push(`- WAF bypass techniques: ${techniques}`);
      }
    }

    if (recon.techStack.cdn) {
      techLines.push(`- CDN: ${sanitizeForPrompt(recon.techStack.cdn)}`);
    }

    if (recon.techStack.languages.length > 0) {
      const langs = recon.techStack.languages.map((l) => sanitizeForPrompt(l)).join(', ');
      techLines.push(`- Backend language hints: ${langs}`);
    }

    if (techLines.length > 0) {
      sections.push(`\nTechnology Context (use for stack-specific validation decisions):\n${techLines.join('\n')}`);
    }
  }

  sections.push(`\nCategory-specific guidance:
- vuln-chain: Vulnerability chains represent attack paths combining multiple lower-severity findings. Validate that the chain is realistic and the attack steps are feasible.`);

  return sections.join('\n');
}

/**
 * @deprecated Use buildValidatorSystemPrompt() for dynamic prompts.
 * Kept for backward compatibility.
 */
export const VALIDATOR_SYSTEM_PROMPT = buildValidatorSystemPrompt();

export function buildValidatorUserPrompt(
  url: string,
  findings: RawFinding[],
  recon: ReconResult,
): string {
  const compactFindings = findings.map((f) => ({
    id: f.id,
    category: f.category,
    severity: f.severity,
    title: sanitizeForPrompt(f.title),
    description: sanitizeForPrompt(f.description.slice(0, 300)),
    url: f.url,
    evidence: sanitizeForPrompt(f.evidence.slice(0, 200)),
  }));

  return `Validate these security findings for ${url}.

Tech context:
- Framework: ${sanitizeForPrompt(recon.framework.name ?? 'unknown')}
- WAF: ${recon.waf.detected ? sanitizeForPrompt(recon.waf.name ?? 'unknown') : 'none'}
- CDN: ${sanitizeForPrompt(recon.techStack.cdn ?? 'none')}

Findings to validate (${findings.length}):
${JSON.stringify(compactFindings, null, 2)}

Output ONLY valid JSON.`;
}

// ─── Reporter Prompts ─────────────────────────────────────────────────

export const REPORTER_SYSTEM_PROMPT = `You are SecBot's AI security analyst. You receive validated vulnerability findings from an automated web security scanner and your job is to:

1. **Deduplicate**: Group findings that describe the same underlying issue (e.g., missing HSTS on 10 different pages is ONE issue)
2. **Prioritize**: Order by real-world severity and exploitability
3. **Explain**: Describe each vulnerability in plain developer language
4. **Suggest fixes**: Provide specific, actionable code-level fixes

Target: <10 actionable findings. Be aggressive about deduplication.

Finding categories and their typical OWASP mappings:
- xss, sqli, ssti, command-injection → A03:2021 - Injection
- cors-misconfiguration, security-headers, cookie-flags, info-leakage → A05:2021 - Security Misconfiguration
- open-redirect, directory-traversal, idor → A01:2021 - Broken Access Control
- mixed-content, sensitive-url-data, tls → A02:2021 - Cryptographic Failures
- ssrf → A10:2021 - Server-Side Request Forgery
- sri → A08:2021 - Software and Data Integrity Failures

For each finding, assign:
- severity: "critical" | "high" | "medium" | "low" | "info"
- confidence: "high" (definitely real) | "medium" (likely real) | "low" (uncertain)
- owaspCategory: The relevant OWASP Top 10 2021 category

Output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "owaspCategory": "string",
      "description": "string",
      "impact": "string",
      "reproductionSteps": ["string"],
      "suggestedFix": "string",
      "codeExample": "string|null",
      "affectedUrls": ["string"],
      "rawFindingIds": ["string"]
    }
  ],
  "summary": {
    "totalRawFindings": number,
    "totalInterpretedFindings": number,
    "bySeverity": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "topIssues": ["string - top 3 issues to fix first"]
  }
}`;

export function buildReporterUserPrompt(
  url: string,
  rawFindings: RawFinding[],
  validations: ValidatedFinding[],
  recon: ReconResult,
  passedChecks?: string[],
): string {
  // Filter to only validated findings
  const validIds = new Set(validations.filter((v) => v.isValid).map((v) => v.findingId));
  const validFindings = rawFindings.filter((f) => validIds.has(f.id));

  const compactFindings = validFindings.map((f) => {
    const validation = validations.find((v) => v.findingId === f.id);
    return {
      id: f.id,
      category: f.category,
      severity: validation?.adjustedSeverity ?? f.severity,
      title: sanitizeForPrompt(f.title),
      description: sanitizeForPrompt(f.description.slice(0, 300)),
      url: f.url,
      evidence: sanitizeForPrompt(f.evidence.slice(0, 200)),
    };
  });

  // Build technology context section
  const techLines: string[] = [];
  techLines.push(`- Framework: ${sanitizeForPrompt(recon.framework.name ?? 'unknown')}`);
  techLines.push(`- WAF: ${recon.waf.detected ? sanitizeForPrompt(recon.waf.name ?? 'unknown') : 'none'}`);
  if (recon.techStack.cdn) {
    techLines.push(`- CDN: ${sanitizeForPrompt(recon.techStack.cdn)}`);
  }
  if (recon.techStack.languages.length > 0) {
    const langs = recon.techStack.languages.map((l) => sanitizeForPrompt(l)).join(', ');
    techLines.push(`- Backend language hints: ${langs}`);
  }
  if (recon.framework.version) {
    techLines.push(`- Framework version: ${sanitizeForPrompt(recon.framework.version)}`);
  }

  // Build passed checks section
  let passedChecksSection = '';
  if (passedChecks && passedChecks.length > 0) {
    passedChecksSection = `\n\n## Checks That Passed (0 findings)\n${passedChecks.join(', ')}`;
  }

  return `Analyze these validated security findings for ${url}.

Total raw findings: ${rawFindings.length}
Validated as real: ${validFindings.length}

Tech context:
${techLines.join('\n')}${passedChecksSection}

Findings:
${JSON.stringify(compactFindings, null, 2)}

Remember:
- Deduplicate aggressively (same issue on multiple pages = 1 finding)
- Target <10 actionable findings
- Provide specific fix suggestions with code examples
- If checks passed clean, mention them positively in the summary
- Output ONLY valid JSON`;
}

/**
 * Reduced reporter prompt — used as retry when full prompt produces invalid/truncated JSON.
 * Omits code examples and shortens descriptions to reduce output token count.
 */
export function buildReducedReporterUserPrompt(
  url: string,
  rawFindings: RawFinding[],
  validations: ValidatedFinding[],
  recon: ReconResult,
  passedChecks?: string[],
): string {
  const validIds = new Set(validations.filter((v) => v.isValid).map((v) => v.findingId));
  const validFindings = rawFindings.filter((f) => validIds.has(f.id));

  const compactFindings = validFindings.map((f) => {
    const validation = validations.find((v) => v.findingId === f.id);
    return {
      id: f.id,
      category: f.category,
      severity: validation?.adjustedSeverity ?? f.severity,
      title: sanitizeForPrompt(f.title),
      url: f.url,
    };
  });

  // Build passed checks section
  let passedChecksSection = '';
  if (passedChecks && passedChecks.length > 0) {
    passedChecksSection = `\n\n## Checks That Passed (0 findings)\n${passedChecks.join(', ')}`;
  }

  return `Analyze these validated security findings for ${url}.

Total raw findings: ${rawFindings.length}
Validated as real: ${validFindings.length}

Tech context:
- Framework: ${sanitizeForPrompt(recon.framework.name ?? 'unknown')}${passedChecksSection}

Findings:
${JSON.stringify(compactFindings, null, 2)}

IMPORTANT constraints for this response:
- Set "codeExample" to null for ALL findings
- Keep "description" under 200 characters
- Keep "suggestedFix" under 200 characters
- Do NOT include "evidence" field
- Deduplicate aggressively
- Target <10 actionable findings
- Output ONLY valid JSON`;
}

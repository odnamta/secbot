import type { ReconResult, CrawledPage, RawFinding, ValidatedFinding } from '../scanner/types.js';

// ─── Planner Check Types ────────────────────────────────────────────

export type PlannerCheckType =
  | 'xss' | 'sqli' | 'cors' | 'redirect' | 'traversal'
  | 'ssrf' | 'ssti' | 'cmdi' | 'idor' | 'tls' | 'sri';

export const ALL_PLANNER_CHECKS: PlannerCheckType[] = [
  'xss', 'sqli', 'cors', 'redirect', 'traversal',
  'ssrf', 'ssti', 'cmdi', 'idor', 'tls', 'sri',
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

  return `Analyze this target and recommend security checks.

Target: ${url}
Profile: ${profile}

Tech Stack: ${JSON.stringify(recon.techStack, null, 2)}
WAF: ${JSON.stringify(recon.waf, null, 2)}
Framework: ${JSON.stringify(recon.framework, null, 2)}

Endpoints:
- Pages: ${recon.endpoints.pages.length}
- API routes: ${recon.endpoints.apiRoutes.length} ${recon.endpoints.apiRoutes.length > 0 ? `(${recon.endpoints.apiRoutes.slice(0, 5).join(', ')})` : ''}
- Forms: ${allForms.length}
- GraphQL: ${recon.endpoints.graphql.length}
- URLs with params: ${urlsWithParams.length}
- URLs with redirect params: ${redirectParams.length}
- Forms with URL-accepting inputs: ${urlAcceptingParams.length}
- API routes with numeric IDs: ${numericIdUrls.length}
- HTTPS: ${isHttps}
- Pages crawled: ${pages.length}

Available checks: xss, sqli, cors, redirect, traversal, ssrf, ssti, cmdi, idor, tls, sri

Output ONLY valid JSON.`;
}

// ─── Validator Prompts ────────────────────────────────────────────────

export const VALIDATOR_SYSTEM_PROMPT = `You are SecBot's AI vulnerability validator. You assess whether each raw finding from an automated security scanner is a true vulnerability or a false positive.

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

export function buildValidatorUserPrompt(
  url: string,
  findings: RawFinding[],
  recon: ReconResult,
): string {
  const compactFindings = findings.map((f) => ({
    id: f.id,
    category: f.category,
    severity: f.severity,
    title: f.title,
    description: f.description.slice(0, 300),
    url: f.url,
    evidence: f.evidence.slice(0, 200),
  }));

  return `Validate these security findings for ${url}.

Tech context:
- Framework: ${recon.framework.name ?? 'unknown'}
- WAF: ${recon.waf.detected ? recon.waf.name : 'none'}
- CDN: ${recon.techStack.cdn ?? 'none'}

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
      title: f.title,
      description: f.description.slice(0, 300),
      url: f.url,
      evidence: f.evidence.slice(0, 200),
    };
  });

  return `Analyze these validated security findings for ${url}.

Total raw findings: ${rawFindings.length}
Validated as real: ${validFindings.length}

Tech context:
- Framework: ${recon.framework.name ?? 'unknown'}
- WAF: ${recon.waf.detected ? recon.waf.name : 'none'}

Findings:
${JSON.stringify(compactFindings, null, 2)}

Remember:
- Deduplicate aggressively (same issue on multiple pages = 1 finding)
- Target <10 actionable findings
- Provide specific fix suggestions with code examples
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
): string {
  const validIds = new Set(validations.filter((v) => v.isValid).map((v) => v.findingId));
  const validFindings = rawFindings.filter((f) => validIds.has(f.id));

  const compactFindings = validFindings.map((f) => {
    const validation = validations.find((v) => v.findingId === f.id);
    return {
      id: f.id,
      category: f.category,
      severity: validation?.adjustedSeverity ?? f.severity,
      title: f.title,
      url: f.url,
    };
  });

  return `Analyze these validated security findings for ${url}.

Total raw findings: ${rawFindings.length}
Validated as real: ${validFindings.length}

Tech context:
- Framework: ${recon.framework.name ?? 'unknown'}

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

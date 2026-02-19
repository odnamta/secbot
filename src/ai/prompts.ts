import type { ReconResult, CrawledPage, RawFinding, ValidatedFinding } from '../scanner/types.js';

// ─── Planner Prompts ─────────────────────────────────────────────────

export const PLANNER_SYSTEM_PROMPT = `You are SecBot's AI attack planner. You analyze reconnaissance data from a web application and recommend which security checks to run.

Available checks: xss, sqli, cors, redirect, traversal

Your job:
1. Analyze the tech stack, WAF presence, framework, and endpoints
2. Recommend which checks are most likely to find real vulnerabilities
3. Prioritize checks (1 = highest priority)
4. Explain why certain checks should be skipped

Rules:
- If a WAF is detected with high confidence, lower priority of checks that WAFs typically block (XSS, SQLi)
- If no forms exist, skip form-based XSS and SQLi
- If no API endpoints exist, skip directory traversal
- If no redirect parameters exist, skip open redirect
- Always recommend CORS check (low cost, high value)
- For "quick" profile, recommend max 2 checks
- For "standard" profile, recommend max 4 checks
- For "deep" profile, recommend all applicable checks

Output ONLY valid JSON matching this schema:
{
  "recommendedChecks": [
    { "name": "string", "priority": number, "reason": "string", "focusAreas": ["string"] }
  ],
  "reasoning": "string - overall analysis",
  "skipReasons": { "checkName": "reason for skipping" }
}`;

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

Available checks: xss, sqli, cors, redirect, traversal

Output ONLY valid JSON.`;
}

// ─── Validator Prompts ────────────────────────────────────────────────

export const VALIDATOR_SYSTEM_PROMPT = `You are SecBot's AI vulnerability validator. You assess whether each raw finding from an automated security scanner is a true vulnerability or a false positive.

For each finding, determine:
1. Is this a real vulnerability? (isValid: true/false)
2. How confident are you? (confidence: high/medium/low)
3. Should the severity be adjusted? (adjustedSeverity: only if different from original)
4. Brief reasoning

Common false positives to watch for:
- Missing security headers on static assets or CDN-served content
- CORS "issues" that are actually intentional (public APIs)
- Cookie flags on non-sensitive cookies (analytics, preferences)
- "Info leakage" that's actually standard framework behavior
- XSS/SQLi that was reflected but properly encoded

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
    description: f.description,
    url: f.url,
    evidence: f.evidence.slice(0, 500),
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
      description: f.description,
      url: f.url,
      evidence: f.evidence.slice(0, 500),
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

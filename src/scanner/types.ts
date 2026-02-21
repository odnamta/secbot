export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type CheckCategory =
  | 'security-headers'
  | 'cookie-flags'
  | 'info-leakage'
  | 'mixed-content'
  | 'sensitive-url-data'
  | 'xss'
  | 'sqli'
  | 'open-redirect'
  | 'cross-origin-policy'
  | 'cors-misconfiguration'
  | 'directory-traversal'
  | 'ssrf'
  | 'ssti'
  | 'idor'
  | 'command-injection'
  | 'tls'
  | 'sri';

export type ScanProfile = 'quick' | 'standard' | 'deep';

export interface RawFinding {
  id: string;
  category: CheckCategory;
  severity: Severity;
  title: string;
  description: string;
  url: string;
  evidence: string;
  request?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response?: {
    status: number;
    headers?: Record<string, string>;
    bodySnippet?: string;
  };
  timestamp: string;
  affectedUrls?: string[];
}

export interface InterpretedFinding {
  title: string;
  severity: Severity;
  confidence: Confidence;
  owaspCategory: string;
  description: string;
  impact: string;
  reproductionSteps: string[];
  suggestedFix: string;
  codeExample?: string;
  affectedUrls: string[];
  rawFindingIds: string[];
}

export interface ScanConfig {
  targetUrl: string;
  profile: ScanProfile;
  maxPages: number;
  timeout: number;
  respectRobots: boolean;
  authStorageState?: string;
  outputFormat: ('terminal' | 'json' | 'html' | 'bounty')[];
  outputPath?: string;
  concurrency: number;
  requestDelay: number;
  scope?: ScanScope;
  logRequests: boolean;
  useAI: boolean;
  userAgent?: string;
  callbackUrl?: string;
}

export interface CrawledPage {
  url: string;
  status: number;
  headers: Record<string, string>;
  title: string;
  forms: FormInfo[];
  links: string[];
  scripts: string[];
  cookies: CookieInfo[];
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: InputInfo[];
  pageUrl: string;
}

export interface InputInfo {
  name: string;
  type: string;
  value?: string;
}

export interface CookieInfo {
  name: string;
  value: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
}

export interface InterceptedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  postData?: string;
}

export interface InterceptedResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body?: string;
}

export interface ScanResult {
  targetUrl: string;
  profile: ScanProfile;
  startedAt: string;
  completedAt: string;
  pagesScanned: number;
  rawFindings: RawFinding[];
  interpretedFindings: InterpretedFinding[];
  summary: ScanSummary;
  recon?: ReconResult;
  attackPlan?: AttackPlan;
  validatedFindings?: ValidatedFinding[];
  exitCode: number;
  scanDuration: number; // ms
  checksRun: string[];
  tokenUsage?: { inputTokens: number; outputTokens: number; totalTokens: number };
  callbackUrl?: string;
}

export interface ScanSummary {
  totalRawFindings: number;
  totalInterpretedFindings: number;
  bySeverity: Record<Severity, number>;
  topIssues: string[];
  passedChecks: string[]; // check types that ran but found nothing
}

// ─── Scope ─────────────────────────────────────────────────────────

export interface ScanScope {
  includePatterns: string[];
  excludePatterns: string[];
}

// ─── Recon ─────────────────────────────────────────────────────────

export interface ReconResult {
  techStack: TechFingerprint;
  waf: WafDetection;
  framework: FrameworkDetection;
  endpoints: EndpointMap;
}

export interface TechFingerprint {
  server?: string;
  poweredBy?: string;
  cdn?: string;
  languages: string[];
  detected: string[];
}

export interface WafDetection {
  detected: boolean;
  name?: string;
  confidence: Confidence;
  evidence: string[];
}

export interface FrameworkDetection {
  name?: string;
  version?: string;
  confidence: Confidence;
  evidence: string[];
}

export interface EndpointMap {
  pages: string[];
  apiRoutes: string[];
  forms: FormInfo[];
  staticAssets: string[];
  graphql: string[];
}

// ─── Attack Plan ───────────────────────────────────────────────────

export interface AttackPlan {
  recommendedChecks: RecommendedCheck[];
  reasoning: string;
  skipReasons: Record<string, string>;
}

export interface RecommendedCheck {
  name: string;
  priority: number;
  reason: string;
  focusAreas?: string[];
}

// ─── Validation ────────────────────────────────────────────────────

export interface ValidatedFinding {
  findingId: string;
  isValid: boolean;
  confidence: Confidence;
  reasoning: string;
  adjustedSeverity?: Severity;
}

// ─── Bug Bounty ────────────────────────────────────────────────────

export interface BountyReport {
  target: string;
  scanDate: string;
  findings: BountyFinding[];
  summary: { total: number; bySeverity: Record<Severity, number> };
}

export interface BountyFinding {
  title: string;
  severity: Severity;
  cwe: string;
  owaspCategory: string;
  asset: string;
  description: string;
  stepsToReproduce: string[];
  impact: string;
  evidence: string;
  remediation: string;
}

// ─── Request Logging ───────────────────────────────────────────────

export interface RequestLogEntry {
  timestamp: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  responseStatus?: number;
  responseHeaders?: Record<string, string>;
  phase: string;
}

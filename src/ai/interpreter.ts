import Anthropic from '@anthropic-ai/sdk';
import type { RawFinding, InterpretedFinding, ScanSummary, Severity } from '../scanner/types.js';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompts.js';
import { ollamaChat, isOllamaAvailable, listOllamaModels } from './ollama.js';
import { log } from '../utils/logger.js';

export type AIProvider = 'anthropic' | 'ollama' | 'auto' | 'none';

interface AIResponse {
  findings: InterpretedFinding[];
  summary: ScanSummary;
}

interface InterpreterOptions {
  provider: AIProvider;
  ollamaModel?: string;
}

const DEFAULT_OLLAMA_MODEL = 'llama3.2:3b';
const FALLBACK_OLLAMA_MODELS = ['llama3.2:3b', 'llama3.1:8b', 'llama3:8b', 'mistral', 'qwen2.5:7b'];

export async function interpretFindings(
  targetUrl: string,
  rawFindings: RawFinding[],
  options: InterpreterOptions = { provider: 'auto' },
): Promise<{ findings: InterpretedFinding[]; summary: ScanSummary }> {
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

  if (options.provider === 'none') {
    log.info('AI disabled — using rule-based interpretation');
    return fallbackInterpretation(rawFindings);
  }

  const resolvedProvider = await resolveProvider(options);
  const compactFindings = rawFindings.map((f) => ({
    id: f.id,
    category: f.category,
    severity: f.severity,
    title: f.title,
    description: f.description,
    url: f.url,
    evidence: f.evidence,
  }));
  const userPrompt = buildUserPrompt(targetUrl, compactFindings);

  if (resolvedProvider === 'ollama') {
    return interpretWithOllama(targetUrl, rawFindings, userPrompt, options.ollamaModel ?? DEFAULT_OLLAMA_MODEL);
  }

  if (resolvedProvider === 'anthropic') {
    return interpretWithAnthropic(targetUrl, rawFindings, userPrompt);
  }

  // Fallback
  log.warn('No AI provider available — using rule-based interpretation');
  return fallbackInterpretation(rawFindings);
}

async function resolveProvider(options: InterpreterOptions): Promise<'ollama' | 'anthropic' | 'none'> {
  if (options.provider === 'ollama') {
    const model = await resolveOllamaModel(options.ollamaModel);
    if (model) {
      options.ollamaModel = model;
      return 'ollama';
    }
    return 'none';
  }

  if (options.provider === 'anthropic') {
    if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
    log.warn('ANTHROPIC_API_KEY not set');
    return 'none';
  }

  // Auto mode: try Ollama first (free), then Anthropic, then fallback
  if (options.provider === 'auto') {
    const model = await resolveOllamaModel(options.ollamaModel);
    if (model) {
      options.ollamaModel = model;
      log.info(`Auto mode: using Ollama (${model}) — free, local`);
      return 'ollama';
    }

    if (process.env.ANTHROPIC_API_KEY) {
      log.info('Auto mode: Ollama not available, using Anthropic API');
      return 'anthropic';
    }

    log.warn('Auto mode: no AI provider available (no Ollama, no API key)');
    return 'none';
  }

  return 'none';
}

/** Try to find a working Ollama model: user-specified, then default, then any available */
async function resolveOllamaModel(requested?: string): Promise<string | null> {
  const models = await listOllamaModels();
  if (models.length === 0) {
    log.debug('Ollama not running or no models installed');
    return null;
  }

  // If user specified a model, check if it exists
  if (requested) {
    const match = models.find((m) => m === requested || m.startsWith(requested.split(':')[0]));
    if (match) return match;
    log.warn(`Ollama model "${requested}" not found. Available: ${models.join(', ')}`);
  }

  // Try preferred models in order
  for (const preferred of FALLBACK_OLLAMA_MODELS) {
    const match = models.find((m) => m === preferred || m.startsWith(preferred.split(':')[0]));
    if (match) return match;
  }

  // Use whatever is available
  log.info(`Using first available Ollama model: ${models[0]}`);
  return models[0];
}

// ─── Ollama Provider ────────────────────────────────────────────────

async function interpretWithOllama(
  targetUrl: string,
  rawFindings: RawFinding[],
  userPrompt: string,
  model: string,
): Promise<{ findings: InterpretedFinding[]; summary: ScanSummary }> {
  log.info(`Sending ${rawFindings.length} findings to Ollama (${model})...`);

  try {
    const responseText = await ollamaChat(model, SYSTEM_PROMPT, userPrompt);
    const parsed = parseAIResponse(responseText);

    log.info(
      `Ollama interpretation: ${rawFindings.length} raw → ${parsed.findings.length} actionable findings`,
    );
    return parsed;
  } catch (err) {
    log.error(`Ollama interpretation failed: ${(err as Error).message}`);

    // In auto mode, try Anthropic as fallback
    if (process.env.ANTHROPIC_API_KEY) {
      log.info('Falling back to Anthropic API...');
      return interpretWithAnthropic(targetUrl, rawFindings, userPrompt);
    }

    log.info('Falling back to rule-based interpretation');
    return fallbackInterpretation(rawFindings);
  }
}

// ─── Anthropic Provider ─────────────────────────────────────────────

async function interpretWithAnthropic(
  targetUrl: string,
  rawFindings: RawFinding[],
  userPrompt: string,
): Promise<{ findings: InterpretedFinding[]; summary: ScanSummary }> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    log.warn('ANTHROPIC_API_KEY not set');
    return fallbackInterpretation(rawFindings);
  }

  log.info(`Sending ${rawFindings.length} findings to Claude (Sonnet 4.5)...`);

  try {
    const client = new Anthropic({ apiKey });
    const message = await client.messages.create({
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: 4096,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt }],
    });

    const textBlock = message.content.find((b) => b.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
      log.warn('Anthropic returned no text — using fallback');
      return fallbackInterpretation(rawFindings);
    }

    const parsed = parseAIResponse(textBlock.text);

    log.info(
      `Anthropic interpretation: ${rawFindings.length} raw → ${parsed.findings.length} actionable findings`,
    );
    return parsed;
  } catch (err) {
    log.error(`Anthropic interpretation failed: ${(err as Error).message}`);
    log.info('Falling back to rule-based interpretation');
    return fallbackInterpretation(rawFindings);
  }
}

// ─── Shared Utilities ───────────────────────────────────────────────

function parseAIResponse(text: string): AIResponse {
  let jsonStr = text.trim();

  // Handle markdown code blocks
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1].trim();
  }

  // Try to find JSON object if there's text before/after
  if (!jsonStr.startsWith('{')) {
    const start = jsonStr.indexOf('{');
    const end = jsonStr.lastIndexOf('}');
    if (start !== -1 && end !== -1) {
      jsonStr = jsonStr.slice(start, end + 1);
    }
  }

  return JSON.parse(jsonStr) as AIResponse;
}

/** Rule-based fallback when no AI is available */
export function fallbackInterpretation(rawFindings: RawFinding[]): {
  findings: InterpretedFinding[];
  summary: ScanSummary;
} {
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

function severityOrder(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}

function mapToOwasp(category: string): string {
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

function getGenericImpact(category: string): string {
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

function getGenericFix(category: string): string {
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

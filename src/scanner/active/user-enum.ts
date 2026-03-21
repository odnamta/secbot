/**
 * Username Enumeration Check (CWE-204)
 *
 * Tests login/registration/password-reset forms for observable response
 * discrepancies that reveal whether a username/email exists in the system.
 *
 * Detection approach:
 * 1. Submit login with known-invalid username → capture response (body, status, timing, headers)
 * 2. Submit login with common usernames (admin, test, root, info@, etc.) → compare
 * 3. If response differs (body content, timing, status, headers) → enumeration possible
 *
 * Also tests registration and password-reset endpoints for similar discrepancies.
 */

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

// ─── Constants ────────────────────────────────────────────────────────

/** Known-invalid usernames for baseline (very unlikely to exist) */
const BASELINE_USERNAMES = [
  'xq7k9m2p_nonexistent_user_12345',
  'zzz_invalid_account_99999_abc',
];

/** Common usernames to test for existence */
const PROBE_USERNAMES = [
  'admin',
  'administrator',
  'root',
  'test',
  'user',
  'demo',
  'guest',
  'info',
  'support',
  'webmaster',
];

/** Patterns that indicate login/auth forms */
const LOGIN_FORM_RE = /\/(login|signin|sign-in|auth|authenticate|session)\b/i;
const REGISTER_FORM_RE = /\/(register|signup|sign-up|create-account|join)\b/i;
const RESET_FORM_RE = /\/(forgot|reset|recover|password-reset|forgot-password)\b/i;

/** Input names commonly used for username/email */
const USERNAME_INPUT_RE = /^(username|user|email|login|uid|account|name|user_name|user_email|signin_email|log)$/i;

/** Response patterns that indicate "user not found" */
const USER_NOT_FOUND_PATTERNS = [
  /user\s*(not|does\s*not|doesn.t)\s*(exist|found)/i,
  /account\s*(not|does\s*not|doesn.t)\s*(exist|found)/i,
  /no\s*account\s*(found|with|for)/i,
  /email\s*(not|is\s*not)\s*(registered|found|recognized)/i,
  /username\s*(not|is\s*not)\s*(registered|found|recognized)/i,
  /invalid\s*username/i,
  /we\s*couldn.t\s*find\s*(that|your|an)\s*(account|user)/i,
];

/** Response patterns that indicate "user exists" */
const USER_EXISTS_PATTERNS = [
  /invalid\s*password/i,
  /wrong\s*password/i,
  /incorrect\s*password/i,
  /password\s*(is\s*)?(wrong|incorrect|invalid)/i,
  /already\s*(registered|exists|taken|in\s*use)/i,
  /email\s*(already|is\s*already)\s*(registered|taken|in\s*use|exists)/i,
  /username\s*(already|is\s*already)\s*(registered|taken|in\s*use|exists)/i,
];

// ─── Main Check ────────────────────────────────────────────────────────

export const userEnumCheck: ActiveCheck = {
  name: 'user-enum',
  category: 'info-disclosure',
  parallel: false,
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Skip in quick mode
    if (config.profile === 'quick') return findings;

    // Find candidate forms
    const candidates = collectCandidates(targets);
    if (candidates.length === 0) {
      log.info('Username enumeration: no candidate forms found');
      return findings;
    }

    const limit = config.profile === 'deep' ? candidates.length : Math.min(candidates.length, 3);
    const probeLimit = config.profile === 'deep' ? PROBE_USERNAMES.length : 4;

    log.info(`Testing ${Math.min(candidates.length, limit)} endpoints for username enumeration...`);

    for (const candidate of candidates.slice(0, limit)) {
      const formFindings = await testForm(
        context, candidate, probeLimit, config, requestLogger,
      );
      findings.push(...formFindings);
      if (findings.length > 0) break;
      await delay(config.requestDelay);
    }

    return findings;
  },
};

// ─── Candidate Collection ──────────────────────────────────────────────

interface EnumCandidate {
  form: FormInfo;
  usernameField: string;
  passwordField?: string;
  type: 'login' | 'register' | 'reset';
}

function collectCandidates(targets: ScanTargets): EnumCandidate[] {
  const candidates: EnumCandidate[] = [];
  const seen = new Set<string>();

  for (const form of targets.forms) {
    if (!form.action) continue;
    const key = `${form.method}:${form.action}`;
    if (seen.has(key)) continue;

    const usernameInput = form.inputs.find((i) => USERNAME_INPUT_RE.test(i.name));
    if (!usernameInput) continue;

    const passwordInput = form.inputs.find((i) =>
      i.type === 'password' || /^(password|pass|pwd|passwd)$/i.test(i.name),
    );

    let type: 'login' | 'register' | 'reset' = 'login';
    if (REGISTER_FORM_RE.test(form.action) || REGISTER_FORM_RE.test(form.pageUrl)) {
      type = 'register';
    } else if (RESET_FORM_RE.test(form.action) || RESET_FORM_RE.test(form.pageUrl)) {
      type = 'reset';
    } else if (LOGIN_FORM_RE.test(form.action) || LOGIN_FORM_RE.test(form.pageUrl) || passwordInput) {
      type = 'login';
    }

    seen.add(key);
    candidates.push({
      form,
      usernameField: usernameInput.name,
      passwordField: passwordInput?.name,
      type,
    });
  }

  return candidates;
}

// ─── Per-Form Testing ──────────────────────────────────────────────────

interface SubmitResult {
  status: number;
  body: string;
  timing: number;
  headers: Record<string, string>;
}

async function submitForm(
  context: BrowserContext,
  candidate: EnumCandidate,
  username: string,
  config: ScanConfig,
): Promise<SubmitResult | null> {
  const page = await context.newPage();
  try {
    const formData: Record<string, string> = {};
    formData[candidate.usernameField] = username;
    if (candidate.passwordField) {
      formData[candidate.passwordField] = 'WrongPassword123!';
    }
    // Fill other required inputs with dummy values
    for (const input of candidate.form.inputs) {
      if (input.name === candidate.usernameField) continue;
      if (input.name === candidate.passwordField) continue;
      if (!input.name) continue;
      if (input.type === 'hidden' && input.value) {
        formData[input.name] = input.value;
      } else if (input.type === 'email') {
        formData[input.name] = `${username}@example.com`;
      }
    }

    const body = Object.entries(formData)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');

    const start = Date.now();
    const method = candidate.form.method?.toUpperCase() === 'POST' ? 'POST' : 'GET';

    const resp = method === 'POST'
      ? await page.request.fetch(candidate.form.action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          data: body,
          timeout: config.timeout,
        })
      : await page.request.fetch(
          `${candidate.form.action}?${body}`,
          { timeout: config.timeout },
        );

    const timing = Date.now() - start;
    const respBody = await resp.text();
    const headers: Record<string, string> = {};
    for (const { name, value } of resp.headersArray()) {
      headers[name.toLowerCase()] = value;
    }

    return { status: resp.status(), body: respBody, timing, headers };
  } catch {
    return null;
  } finally {
    await page.close();
  }
}

async function testForm(
  context: BrowserContext,
  candidate: EnumCandidate,
  probeLimit: number,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Step 1: Get baseline with known-invalid usernames
  const baselines: SubmitResult[] = [];
  for (const invalid of BASELINE_USERNAMES) {
    const result = await submitForm(context, candidate, invalid, config);
    if (result) baselines.push(result);
    await delay(config.requestDelay);
  }

  if (baselines.length === 0) return findings;

  const baselineBody = baselines[0].body;
  const baselineStatus = baselines[0].status;
  const baselineTiming = baselines.reduce((sum, b) => sum + b.timing, 0) / baselines.length;

  // Step 2: Probe with common usernames
  for (const username of PROBE_USERNAMES.slice(0, probeLimit)) {
    const result = await submitForm(context, candidate, username, config);
    if (!result) continue;

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: candidate.form.method?.toUpperCase() ?? 'POST',
      url: candidate.form.action,
      responseStatus: result.status,
      phase: 'active-user-enum',
    });

    const discrepancies: string[] = [];

    // Check 1: Content-based enumeration
    const baselineNotFound = USER_NOT_FOUND_PATTERNS.some((p) => p.test(baselineBody));
    const probeNotFound = USER_NOT_FOUND_PATTERNS.some((p) => p.test(result.body));
    const probeExists = USER_EXISTS_PATTERNS.some((p) => p.test(result.body));

    if (baselineNotFound && !probeNotFound) {
      discrepancies.push('Different error message for valid vs invalid username');
    }
    if (probeExists) {
      discrepancies.push(`"User exists" pattern detected: ${USER_EXISTS_PATTERNS.find((p) => p.test(result.body))?.source}`);
    }

    // Check 2: Status code difference
    if (result.status !== baselineStatus) {
      discrepancies.push(`Status code differs: baseline=${baselineStatus}, probe=${result.status}`);
    }

    // Check 3: Significant body length difference (>20% and >100 chars)
    const lenDiff = Math.abs(result.body.length - baselineBody.length);
    const pctDiff = baselineBody.length > 0 ? lenDiff / baselineBody.length : 0;
    if (lenDiff > 100 && pctDiff > 0.2) {
      discrepancies.push(`Response size differs: baseline=${baselineBody.length}, probe=${result.body.length} (${Math.round(pctDiff * 100)}% diff)`);
    }

    // Check 4: Timing difference (>200ms and >50% of baseline)
    const timingDiff = Math.abs(result.timing - baselineTiming);
    if (timingDiff > 200 && timingDiff / baselineTiming > 0.5) {
      discrepancies.push(`Response time differs: baseline=${Math.round(baselineTiming)}ms, probe=${result.timing}ms`);
    }

    if (discrepancies.length > 0) {
      const isContentBased = discrepancies.some((d) =>
        d.includes('error message') || d.includes('User exists'),
      );

      findings.push({
        id: randomUUID(),
        category: 'info-disclosure',
        severity: isContentBased ? 'medium' : 'low',
        title: `Username Enumeration — ${candidate.type} form (${isContentBased ? 'content-based' : 'timing/status-based'})`,
        description: `The ${candidate.type} endpoint reveals whether a username/email exists via observable response differences. An attacker can enumerate valid accounts by comparing responses for valid vs invalid usernames. This enables targeted phishing, credential stuffing, and brute-force attacks.`,
        url: candidate.form.action,
        evidence: [
          `Form: ${candidate.form.action}`,
          `Type: ${candidate.type}`,
          `Username field: ${candidate.usernameField}`,
          `Probe username: ${username}`,
          `Discrepancies:`,
          ...discrepancies.map((d) => `  - ${d}`),
        ].join('\n'),
        request: {
          method: candidate.form.method?.toUpperCase() ?? 'POST',
          url: candidate.form.action,
          body: `${candidate.usernameField}=${username}`,
        },
        response: {
          status: result.status,
          bodySnippet: result.body.slice(0, 500),
        },
        timestamp: new Date().toISOString(),
        confidence: isContentBased ? 'high' : 'medium',
        evidencePack: {
          payloadUsed: username,
          responseIndicators: discrepancies,
          detectionMethod: isContentBased ? 'content-comparison' : 'timing-analysis',
        },
      });
      break; // One finding per form is enough
    }

    await delay(config.requestDelay);
  }

  return findings;
}

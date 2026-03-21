/**
 * Mass Assignment / Over-Posting Check (CWE-915)
 *
 * Tests API endpoints for accepting unintended parameters that modify
 * privilege or role fields. Common in REST APIs using frameworks with
 * ORM auto-binding (Rails strong_params bypass, Django, Spring, Express).
 *
 * Detection approach:
 * 1. Find API endpoints that accept POST/PUT/PATCH with JSON bodies
 * 2. Replay the request with extra "privilege" fields (is_admin, role, etc.)
 * 3. Compare response: if extra fields are reflected or status changes → mass assignment
 */

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

// ─── Constants ────────────────────────────────────────────────────────

/** Privilege/role fields to inject */
const PROBE_FIELDS: Array<{ key: string; value: unknown; severity: 'critical' | 'high' | 'medium' }> = [
  // Admin/role escalation
  { key: 'is_admin', value: true, severity: 'critical' },
  { key: 'isAdmin', value: true, severity: 'critical' },
  { key: 'admin', value: true, severity: 'critical' },
  { key: 'role', value: 'admin', severity: 'critical' },
  { key: 'roles', value: ['admin'], severity: 'critical' },
  { key: 'user_role', value: 'administrator', severity: 'critical' },
  { key: 'userRole', value: 'administrator', severity: 'critical' },
  { key: 'privilege', value: 'admin', severity: 'critical' },
  { key: 'permissions', value: ['*'], severity: 'critical' },
  { key: 'access_level', value: 99, severity: 'critical' },
  // Account status
  { key: 'verified', value: true, severity: 'high' },
  { key: 'is_verified', value: true, severity: 'high' },
  { key: 'email_verified', value: true, severity: 'high' },
  { key: 'active', value: true, severity: 'high' },
  { key: 'is_active', value: true, severity: 'high' },
  { key: 'approved', value: true, severity: 'high' },
  // Price/credit manipulation
  { key: 'balance', value: 999999, severity: 'high' },
  { key: 'credits', value: 999999, severity: 'high' },
  { key: 'discount', value: 100, severity: 'medium' },
  { key: 'is_premium', value: true, severity: 'medium' },
  { key: 'isPremium', value: true, severity: 'medium' },
  { key: 'plan', value: 'enterprise', severity: 'medium' },
];

/** API endpoints that commonly accept user data updates */
const MUTABLE_ENDPOINT_RE = /\/(user|profile|account|settings|preferences|register|signup|update|edit|me|self)\b/i;

// ─── Main Check ────────────────────────────────────────────────────────

export const massAssignmentCheck: ActiveCheck = {
  name: 'mass-assignment',
  category: 'broken-access-control',
  parallel: false,
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Skip in quick mode
    if (config.profile === 'quick') return findings;

    // Find candidate endpoints
    const candidates = collectCandidates(targets);
    if (candidates.length === 0) {
      log.info('Mass assignment: no candidate endpoints found');
      return findings;
    }

    const limit = config.profile === 'deep' ? candidates.length : Math.min(candidates.length, 3);
    const probeLimit = config.profile === 'deep' ? PROBE_FIELDS.length : 6;

    log.info(`Testing ${Math.min(candidates.length, limit)} endpoints for mass assignment (${probeLimit} probe fields)...`);

    for (const candidate of candidates.slice(0, limit)) {
      const endpointFindings = await testEndpoint(
        context, candidate, probeLimit, config, requestLogger,
      );
      findings.push(...endpointFindings);
      if (findings.length > 0) break;
      await delay(config.requestDelay);
    }

    return findings;
  },
};

// ─── Candidate Collection ──────────────────────────────────────────────

interface MassAssignCandidate {
  url: string;
  method: 'POST' | 'PUT' | 'PATCH';
  baseFields: Record<string, string>;
  source: 'api' | 'form';
}

function collectCandidates(targets: ScanTargets): MassAssignCandidate[] {
  const candidates: MassAssignCandidate[] = [];
  const seen = new Set<string>();

  // Check API endpoints matching mutable patterns
  for (const url of targets.apiEndpoints) {
    if (!MUTABLE_ENDPOINT_RE.test(url)) continue;
    const key = url.split('?')[0];
    if (seen.has(key)) continue;
    seen.add(key);

    candidates.push({
      url: key,
      method: 'POST',
      baseFields: { name: 'testuser', email: 'test@example.com' },
      source: 'api',
    });
  }

  // Check forms with POST/PUT/PATCH that have user-data fields
  for (const form of targets.forms) {
    if (!form.action) continue;
    const method = form.method?.toUpperCase();
    if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH') continue;

    // Must have user-data fields (not just search/filter)
    const hasUserFields = form.inputs.some((i) =>
      /^(name|email|username|password|phone|address|bio|company|title|first_?name|last_?name|display_?name)$/i.test(i.name),
    );
    if (!hasUserFields) continue;

    const key = `${method}:${form.action}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const baseFields: Record<string, string> = {};
    for (const input of form.inputs) {
      if (!input.name) continue;
      if (input.type === 'hidden' && input.value) {
        baseFields[input.name] = input.value;
      } else if (/email/i.test(input.name) || input.type === 'email') {
        baseFields[input.name] = 'test@example.com';
      } else if (/password|pass|pwd/i.test(input.name) || input.type === 'password') {
        baseFields[input.name] = 'TestPassword123!';
      } else if (/name/i.test(input.name)) {
        baseFields[input.name] = 'testuser';
      } else {
        baseFields[input.name] = 'test';
      }
    }

    candidates.push({
      url: form.action,
      method: method as 'POST' | 'PUT' | 'PATCH',
      baseFields,
      source: 'form',
    });
  }

  // Also check crawled pages for mutable API patterns
  for (const url of targets.pages) {
    if (!MUTABLE_ENDPOINT_RE.test(url)) continue;
    if (!/\/api\//i.test(url)) continue;
    const key = url.split('?')[0];
    if (seen.has(key)) continue;
    seen.add(key);

    candidates.push({
      url: key,
      method: 'PUT',
      baseFields: { name: 'testuser' },
      source: 'api',
    });
  }

  return candidates;
}

// ─── Per-Endpoint Testing ──────────────────────────────────────────────

async function testEndpoint(
  context: BrowserContext,
  candidate: MassAssignCandidate,
  probeLimit: number,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Step 1: Get baseline response with just base fields
  const page = await context.newPage();
  let baselineBody = '';
  let baselineStatus = 0;
  try {
    const isJson = candidate.source === 'api';
    const resp = await page.request.fetch(candidate.url, {
      method: candidate.method,
      headers: isJson
        ? { 'Content-Type': 'application/json' }
        : { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: isJson
        ? JSON.stringify(candidate.baseFields)
        : Object.entries(candidate.baseFields)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&'),
      timeout: config.timeout,
    });
    baselineStatus = resp.status();
    baselineBody = await resp.text();
  } catch {
    await page.close();
    return findings;
  }
  await page.close();

  // Step 2: Send requests with extra privilege fields
  for (const probe of PROBE_FIELDS.slice(0, probeLimit)) {
    const probePage = await context.newPage();
    try {
      const isJson = candidate.source === 'api';
      const probeBody = { ...candidate.baseFields, [probe.key]: probe.value };

      const resp = await probePage.request.fetch(candidate.url, {
        method: candidate.method,
        headers: isJson
          ? { 'Content-Type': 'application/json' }
          : { 'Content-Type': 'application/x-www-form-urlencoded' },
        data: isJson
          ? JSON.stringify(probeBody)
          : Object.entries(probeBody)
              .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
              .join('&'),
        timeout: config.timeout,
      });

      const status = resp.status();
      const body = await resp.text();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: candidate.method,
        url: candidate.url,
        responseStatus: status,
        phase: 'active-mass-assignment',
      });

      // Detection: probe field reflected in response
      const probeValueStr = String(probe.value);
      const bodyLower = body.toLowerCase();

      // Exclude error/rejection responses — these echo the field name in error messages
      const isErrorResponse = status >= 400 ||
        bodyLower.includes('error') || bodyLower.includes('invalid') ||
        bodyLower.includes('not allowed') || bodyLower.includes('forbidden') ||
        bodyLower.includes('unauthorized') || bodyLower.includes('rejected') ||
        bodyLower.includes('unrecognized') || bodyLower.includes('unknown field') ||
        bodyLower.includes('unexpected') || bodyLower.includes('not permitted');

      // Field must appear in a success response that ISN'T an error message
      const fieldReflected = !isErrorResponse &&
        status >= 200 && status < 300 &&
        body.includes(`"${probe.key}"`) &&
        (body.includes(probeValueStr) || body.includes(`"${probeValueStr}"`));

      // Detection: successful status when baseline was error (must be real 2xx, not error page)
      const statusUpgrade = baselineStatus >= 400 && status >= 200 && status < 300 && !isErrorResponse;

      if (fieldReflected || statusUpgrade) {
        findings.push({
          id: randomUUID(),
          category: 'broken-access-control',
          severity: probe.severity,
          title: `Mass Assignment — ${probe.key} field accepted (${candidate.method} ${new URL(candidate.url).pathname})`,
          description: `The endpoint accepts and processes the "${probe.key}" parameter which should not be user-controllable. An attacker can ${probe.severity === 'critical' ? 'escalate privileges to admin' : probe.severity === 'high' ? 'bypass account verification or modify account status' : 'manipulate pricing or subscription tier'} by including this field in the request body.`,
          url: candidate.url,
          evidence: [
            `Endpoint: ${candidate.method} ${candidate.url}`,
            `Injected field: ${probe.key} = ${probeValueStr}`,
            `Field reflected in response: ${fieldReflected}`,
            `Status change: baseline=${baselineStatus}, probe=${status}`,
            `Response snippet: ${body.slice(0, 300)}`,
          ].join('\n'),
          request: {
            method: candidate.method,
            url: candidate.url,
            body: JSON.stringify({ ...candidate.baseFields, [probe.key]: probe.value }),
          },
          response: { status, bodySnippet: body.slice(0, 500) },
          timestamp: new Date().toISOString(),
          confidence: fieldReflected ? 'high' : 'medium',
          evidencePack: {
            payloadUsed: `${probe.key}=${probeValueStr}`,
            responseIndicators: fieldReflected
              ? [`"${probe.key}" reflected in response`]
              : [`Status upgraded from ${baselineStatus} to ${status}`],
            detectionMethod: fieldReflected ? 'reflection' : 'status-change',
          },
        });
        break;
      }

      // Lower confidence path intentionally omitted — only report clear evidence
    } catch (err) {
      log.debug(`Mass assignment ${probe.key} on ${candidate.url}: ${(err as Error).message}`);
    } finally {
      await probePage.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

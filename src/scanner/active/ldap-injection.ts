/**
 * LDAP Injection Check (CWE-90)
 *
 * Tests login forms and search endpoints for LDAP injection vulnerabilities.
 * Common in enterprise apps using Active Directory, OpenLDAP, or FreeIPA.
 *
 * Detection approach:
 * 1. Send syntax-breaking payloads → look for LDAP error messages
 * 2. Send wildcard/tautology payloads → compare response to baseline (blind detection)
 * 3. Send attribute extraction payloads → look for data leakage
 */

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';
import {
  LDAP_PAYLOADS,
  LDAP_PARAM_PATTERNS,
  detectLdapError,
  type LdapPayload,
} from '../../config/payloads/ldap.js';

// ─── Main Check ────────────────────────────────────────────────────────

export const ldapInjectionCheck: ActiveCheck = {
  name: 'ldap-injection',
  category: 'ldap-injection',
  parallel: false,
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Skip in quick mode
    if (config.profile === 'quick') return findings;

    // Find candidate URLs: login forms + search-like params
    const candidates = collectCandidates(targets);

    if (candidates.length === 0) {
      log.info('LDAP injection: no candidate endpoints found');
      return findings;
    }

    const urlLimit = config.profile === 'deep' ? candidates.length : Math.min(candidates.length, 3);
    const payloadLimit = config.profile === 'deep' ? LDAP_PAYLOADS.length : 4;
    const urls = candidates.slice(0, urlLimit);
    const payloads = LDAP_PAYLOADS.slice(0, payloadLimit);

    log.info(`Testing ${urls.length} endpoints for LDAP injection (${payloads.length} payloads)...`);

    for (const candidate of urls) {
      const urlFindings = await testEndpoint(context, candidate, payloads, config, requestLogger);
      findings.push(...urlFindings);
      if (findings.length > 0) break;
      await delay(config.requestDelay);
    }

    return findings;
  },
};

// ─── Candidate Collection ──────────────────────────────────────────────

interface LdapCandidate {
  url: string;
  params: string[];
  method: 'GET' | 'POST';
}

function collectCandidates(targets: ScanTargets): LdapCandidate[] {
  const candidates: LdapCandidate[] = [];
  const seen = new Set<string>();

  // Check URL params matching LDAP-related names
  for (const url of targets.urlsWithParams) {
    try {
      const parsed = new URL(url);
      const matchingParams = [...parsed.searchParams.keys()].filter((k) =>
        LDAP_PARAM_PATTERNS.test(k),
      );
      if (matchingParams.length > 0) {
        const key = parsed.origin + parsed.pathname;
        if (!seen.has(key)) {
          seen.add(key);
          candidates.push({ url, params: matchingParams, method: 'GET' });
        }
      }
    } catch { /* skip */ }
  }

  // Check forms with login-like fields
  for (const form of targets.forms) {
    if (!form.action) continue;
    const matchingInputs = form.inputs
      .filter((i) => i.name && LDAP_PARAM_PATTERNS.test(i.name))
      .map((i) => i.name);
    if (matchingInputs.length > 0 && !seen.has(form.action)) {
      seen.add(form.action);
      candidates.push({
        url: form.action,
        params: matchingInputs,
        method: (form.method?.toUpperCase() === 'POST' ? 'POST' : 'GET') as 'GET' | 'POST',
      });
    }
  }

  return candidates;
}

// ─── Per-Endpoint Testing ──────────────────────────────────────────────

async function testEndpoint(
  context: BrowserContext,
  candidate: LdapCandidate,
  payloads: LdapPayload[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Get baseline response for blind detection
  let baselineBody = '';
  let baselineStatus = 0;
  {
    const page = await context.newPage();
    try {
      const resp = candidate.method === 'POST'
        ? await page.request.fetch(candidate.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: candidate.params.map((p) => `${p}=testuser`).join('&'),
            timeout: config.timeout,
          })
        : await page.request.fetch(
            buildUrl(candidate.url, candidate.params, 'testuser'),
            { timeout: config.timeout },
          );
      baselineStatus = resp.status();
      baselineBody = await resp.text();
    } catch {
      return findings;
    } finally {
      await page.close();
    }
  }

  for (const payload of payloads) {
    const page = await context.newPage();
    try {
      const resp = candidate.method === 'POST'
        ? await page.request.fetch(candidate.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: candidate.params.map((p) => `${p}=${encodeURIComponent(payload.payload)}`).join('&'),
            timeout: config.timeout,
          })
        : await page.request.fetch(
            buildUrl(candidate.url, candidate.params, payload.payload),
            { timeout: config.timeout },
          );

      const status = resp.status();
      const body = await resp.text();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: candidate.method,
        url: candidate.url,
        responseStatus: status,
        phase: 'active-ldap-injection',
      });

      // Check 1: LDAP error patterns in response
      const errorCheck = detectLdapError(body);
      if (errorCheck.detected) {
        findings.push({
          id: randomUUID(),
          category: 'ldap-injection',
          severity: 'high',
          title: `LDAP Injection — Error-Based (${payload.technique})`,
          description: `The endpoint exposes LDAP error messages when given malformed input, confirming that user input is passed directly into LDAP queries. This can be exploited for authentication bypass or data extraction.`,
          url: candidate.url,
          evidence: [
            `Parameter: ${candidate.params.join(', ')}`,
            `Technique: ${payload.technique}`,
            `Payload: ${payload.payload}`,
            `Error pattern: ${errorCheck.pattern}`,
            `Response status: ${status}`,
            `Response snippet: ${body.slice(0, 300)}`,
          ].join('\n'),
          request: {
            method: candidate.method,
            url: candidate.url,
            body: candidate.params.map((p) => `${p}=${payload.payload}`).join('&'),
          },
          response: { status, bodySnippet: body.slice(0, 500) },
          timestamp: new Date().toISOString(),
          confidence: 'high',
          evidencePack: {
            payloadUsed: payload.payload,
            responseIndicators: [errorCheck.pattern],
            detectionMethod: 'error-pattern',
          },
        });
        break;
      }

      // Check 2: Blind detection for auth bypass payloads
      if (payload.blind && baselineStatus !== 200 && status === 200) {
        // Baseline was non-200 but payload got 200 = possible auth bypass
        const hasAuthToken = /token|jwt|session|access_token|bearer/i.test(body);
        const significantlyDifferent = Math.abs(body.length - baselineBody.length) > 100;

        if (hasAuthToken || significantlyDifferent) {
          findings.push({
            id: randomUUID(),
            category: 'ldap-injection',
            severity: 'critical',
            title: `LDAP Injection — Authentication Bypass (${payload.technique})`,
            description: `The endpoint returned a successful authentication response for an LDAP injection payload. The wildcard/tautology query bypassed the LDAP filter, granting access without valid credentials.`,
            url: candidate.url,
            evidence: [
              `Parameter: ${candidate.params.join(', ')}`,
              `Technique: ${payload.technique}`,
              `Payload: ${payload.payload}`,
              `Baseline status: ${baselineStatus}`,
              `Payload status: ${status}`,
              `Response size diff: ${body.length} vs ${baselineBody.length}`,
              `Auth token detected: ${hasAuthToken}`,
            ].join('\n'),
            request: {
              method: candidate.method,
              url: candidate.url,
              body: candidate.params.map((p) => `${p}=${payload.payload}`).join('&'),
            },
            response: { status, bodySnippet: body.slice(0, 500) },
            timestamp: new Date().toISOString(),
            confidence: hasAuthToken ? 'high' : 'medium',
            evidencePack: {
              payloadUsed: payload.payload,
              responseIndicators: hasAuthToken ? ['Auth token in response'] : ['Status change from non-200 to 200'],
              detectionMethod: 'blind-auth-bypass',
            },
          });
          break;
        }
      }
    } catch (err) {
      log.debug(`LDAP injection ${payload.technique} on ${candidate.url}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────────────────

function buildUrl(baseUrl: string, params: string[], value: string): string {
  try {
    const parsed = new URL(baseUrl);
    for (const param of params) {
      parsed.searchParams.set(param, value);
    }
    return parsed.toString();
  } catch {
    return baseUrl;
  }
}

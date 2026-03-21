/**
 * Insecure Deserialization Check (CWE-502)
 *
 * Tests endpoints for unsafe deserialization of untrusted data.
 * Detection approach: send serialized objects in various formats and
 * look for error messages that confirm the server attempted deserialization.
 *
 * Covers: Java (ObjectInputStream), PHP (unserialize), Python (pickle),
 * Node.js (node-serialize), Ruby (Marshal), .NET (BinaryFormatter), YAML.
 *
 * Does NOT send actual exploit gadget chains — detection only.
 */

import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';
import {
  DESERIALIZATION_PAYLOADS,
  DESERIALIZATION_URL_PATTERNS,
  detectDeserializationError,
  type DeserializationPayload,
} from '../../config/payloads/deserialize.js';

// ─── Helpers ───────────────────────────────────────────────────────────

/** Prioritize payloads based on detected tech stack */
function prioritizePayloads(
  payloads: DeserializationPayload[],
  config: ScanConfig,
): DeserializationPayload[] {
  const ctx = config.payloadContext;
  if (!ctx) return payloads;

  const prioritized: DeserializationPayload[] = [];
  const rest: DeserializationPayload[] = [];

  for (const p of payloads) {
    let isPriority = false;
    // Java backend
    if (p.format === 'java' && ctx.backendLanguages.includes('java')) {
      isPriority = true;
    }
    // PHP backend
    if (p.format === 'php' && ctx.backendLanguages.includes('php')) {
      isPriority = true;
    }
    // Python backend
    if ((p.format === 'python-pickle' || p.format === 'yaml') && ctx.backendLanguages.includes('python')) {
      isPriority = true;
    }
    // Node.js backend
    if (p.format === 'node-serialize' && ctx.backendLanguages.includes('node')) {
      isPriority = true;
    }
    // Ruby backend
    if (p.format === 'ruby-marshal' && ctx.backendLanguages.includes('ruby')) {
      isPriority = true;
    }
    // .NET backend
    if ((p.format === 'dotnet' || p.format === 'generic') && ctx.backendLanguages.includes('dotnet')) {
      isPriority = true;
    }

    if (isPriority) {
      prioritized.push(p);
    } else {
      rest.push(p);
    }
  }

  return [...prioritized, ...rest];
}

/** Check if a URL looks like it might accept serialized data */
function isDeserializationCandidate(url: string): boolean {
  return DESERIALIZATION_URL_PATTERNS.some((p) => p.test(url));
}

// ─── Main Check ────────────────────────────────────────────────────────

export const insecureDeserializationCheck: ActiveCheck = {
  name: 'insecure-deserialization',
  category: 'insecure-deserialization',
  parallel: false,
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Skip in quick mode — deserialization testing is noisy
    if (config.profile === 'quick') return findings;

    // Build candidate URL list: API endpoints + pages matching patterns
    const candidates = new Set<string>();
    for (const url of targets.apiEndpoints) candidates.add(url);
    for (const url of targets.pages) {
      if (isDeserializationCandidate(url)) candidates.add(url);
    }
    // Also check forms with POST action
    for (const form of targets.forms) {
      if (form.method?.toLowerCase() === 'post' && form.action) {
        candidates.add(form.action);
      }
    }

    if (candidates.size === 0) {
      log.info('Insecure deserialization: no candidate endpoints found');
      return findings;
    }

    // Profile-based limits
    const urlLimit = config.profile === 'deep' ? candidates.size : Math.min(candidates.size, 5);
    const payloadLimit = config.profile === 'deep' ? DESERIALIZATION_PAYLOADS.length : 4;

    const urls = [...candidates].slice(0, urlLimit);
    const payloads = prioritizePayloads(DESERIALIZATION_PAYLOADS, config).slice(0, payloadLimit);

    log.info(`Testing ${urls.length} endpoints for insecure deserialization (${payloads.length} payloads)...`);

    for (const url of urls) {
      const urlFindings = await testEndpoint(context, url, payloads, config, requestLogger);
      findings.push(...urlFindings);
      // Stop early if we find one — deserialization is critical
      if (findings.length > 0) break;
      await delay(config.requestDelay);
    }

    return findings;
  },
};

// ─── Per-Endpoint Testing ──────────────────────────────────────────────

async function testEndpoint(
  context: BrowserContext,
  url: string,
  payloads: DeserializationPayload[],
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const payload of payloads) {
    const page = await context.newPage();
    try {
      const resp = await page.request.fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': payload.contentType,
          'Accept': '*/*',
        },
        data: payload.payload,
        timeout: config.timeout,
        maxRedirects: 3,
      });

      const status = resp.status();
      const body = await resp.text();

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'POST',
        url,
        responseStatus: status,
        phase: 'active-deserialization',
      });

      // Check 1: payload-specific indicator
      if (payload.indicator.test(body)) {
        findings.push(buildFinding(url, payload, status, body, 'Payload-specific indicator matched'));
        break;
      }

      // Check 2: generic deserialization error patterns
      const errorCheck = detectDeserializationError(body);
      if (errorCheck.detected) {
        findings.push(buildFinding(url, payload, status, body, `Error pattern matched: ${errorCheck.pattern}`));
        break;
      }

      // Check 3: 500 error with deserialization-related content type
      if (status === 500 && (
        payload.contentType === 'application/x-java-serialized-object' ||
        payload.contentType === 'application/octet-stream'
      )) {
        // 500 on binary payload is suspicious but not conclusive — check body
        const suspicious = /exception|error|stack\s*trace|internal\s*server/i.test(body);
        if (suspicious && body.length > 50) {
          // Log as info — needs manual review
          log.debug(`Deserialization: suspicious 500 on ${url} with ${payload.technique}`);
        }
      }
    } catch (err) {
      log.debug(`Deserialization test ${payload.technique} on ${url}: ${(err as Error).message}`);
    } finally {
      await page.close();
    }

    await delay(config.requestDelay);
  }

  return findings;
}

// ─── Finding Builder ───────────────────────────────────────────────────

function buildFinding(
  url: string,
  payload: DeserializationPayload,
  status: number,
  body: string,
  detectionDetail: string,
): RawFinding {
  const formatNames: Record<string, string> = {
    java: 'Java ObjectInputStream',
    php: 'PHP unserialize()',
    'python-pickle': 'Python pickle',
    'node-serialize': 'Node.js node-serialize',
    'ruby-marshal': 'Ruby Marshal.load',
    dotnet: '.NET BinaryFormatter',
    yaml: 'YAML unsafe load',
    generic: 'JSON type confusion',
  };

  return {
    id: randomUUID(),
    category: 'insecure-deserialization',
    severity: 'critical',
    title: `Insecure Deserialization — ${formatNames[payload.format] ?? payload.format}`,
    description: `The endpoint processes serialized data without validation. ${formatNames[payload.format]} deserialization of untrusted input can lead to Remote Code Execution if gadget chains are available in the classpath.`,
    url,
    evidence: [
      `Format: ${payload.format}`,
      `Technique: ${payload.technique}`,
      `Detection: ${detectionDetail}`,
      `Response status: ${status}`,
      `Response snippet: ${body.slice(0, 300)}`,
    ].join('\n'),
    request: {
      method: 'POST',
      url,
      headers: { 'Content-Type': payload.contentType },
      body: payload.payload.length > 200 ? payload.payload.slice(0, 200) + '...' : payload.payload,
    },
    response: {
      status,
      bodySnippet: body.slice(0, 500),
    },
    timestamp: new Date().toISOString(),
    confidence: 'high',
    evidencePack: {
      payloadUsed: payload.payload,
      responseIndicators: [detectionDetail],
      detectionMethod: 'deserialization-indicator',
    },
  };
}

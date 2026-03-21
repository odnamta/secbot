import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';

/**
 * Email Header Injection check (CWE-93 / SMTP Injection).
 *
 * Tests email-sending endpoints (contact, feedback, newsletter, support)
 * for CRLF injection into email headers. An attacker can inject additional
 * headers (Bcc, Cc, Subject) to use the target's mail server as a spam relay
 * or send phishing emails from a trusted domain.
 *
 * Distinct from CRLF injection check which targets HTTP headers —
 * this targets SMTP header injection through web forms.
 */

/** Form actions/page URLs that suggest email-sending functionality */
const EMAIL_FORM_RE = /\/(contact|feedback|support|help|enquiry|inquiry|message|send-?mail|mail|email|subscribe|newsletter|signup|invite|referral|share|tell-?a-?friend|report|notify|complaint)/i;

/** Input names that accept email addresses */
const EMAIL_INPUT_RE = /^(email|e-?mail|from|sender|reply-?to|recipient|to|cc|bcc|mail)$/i;

/** Input names that typically become email subject or headers */
const SUBJECT_INPUT_RE = /^(subject|topic|title|reason|category|regarding|re)$/i;

/** Input names for message body (injection target for headers via body) */
const BODY_INPUT_RE = /^(message|body|content|text|description|comment|inquiry|question|details|feedback|note)$/i;

/** CRLF sequences to test for header injection */
const INJECTION_PAYLOADS = [
  // Basic CRLF newline injection
  { payload: '%0d%0aBcc:secbot-probe@test.invalid', decoded: '\r\nBcc:secbot-probe@test.invalid', name: 'URL-encoded CRLF' },
  // Encoded CR/LF
  { payload: '%0aBcc:secbot-probe@test.invalid', decoded: '\nBcc:secbot-probe@test.invalid', name: 'URL-encoded LF only' },
  // Bare newline (some parsers)
  { payload: '\r\nBcc: secbot-probe@test.invalid', decoded: '\r\nBcc: secbot-probe@test.invalid', name: 'Raw CRLF' },
  // Double encoding
  { payload: '%250d%250aBcc:secbot-probe@test.invalid', decoded: '%0d%0aBcc:secbot-probe@test.invalid', name: 'Double URL-encoded CRLF' },
  // Unicode newlines
  { payload: '\u2028Bcc:secbot-probe@test.invalid', decoded: 'LS Bcc header injection', name: 'Unicode Line Separator' },
] as const;

/** Patterns in responses indicating the injection was reflected or processed */
const INJECTION_INDICATORS = [
  /bcc\s*:\s*secbot/i,
  /additional\s+header/i,
  /invalid\s+header/i,
  /header\s+injection/i,
  /mail\s+sent/i,
  /message\s+sent/i,
  /thank\s*you/i,
  /email\s+sent/i,
  /successfully\s+sent/i,
];

/** Patterns indicating the server rejected the injection attempt */
const REJECTION_PATTERNS = [
  /invalid\s+email/i,
  /email\s+format/i,
  /header\s+not\s+allowed/i,
  /newline\s+not\s+allowed/i,
  /crlf\s+detected/i,
  /injection\s+detected/i,
];

/** Identify email-sending forms from crawled targets */
function findEmailForms(forms: FormInfo[]): Array<{ form: FormInfo; emailField?: string; subjectField?: string; bodyField?: string }> {
  const results: Array<{ form: FormInfo; emailField?: string; subjectField?: string; bodyField?: string }> = [];

  for (const form of forms) {
    const method = (form.method ?? 'get').toLowerCase();
    if (method !== 'post') continue;

    // Check if the form action or page URL suggests email functionality
    const isEmailForm = EMAIL_FORM_RE.test(form.action) || EMAIL_FORM_RE.test(form.pageUrl);

    // Check if the form has email-like inputs
    const emailField = form.inputs.find((i) => EMAIL_INPUT_RE.test(i.name ?? ''));
    const subjectField = form.inputs.find((i) => SUBJECT_INPUT_RE.test(i.name ?? ''));
    const bodyField = form.inputs.find((i) => BODY_INPUT_RE.test(i.name ?? ''));

    // Must have at least email endpoint + email field, or subject/body fields
    if (isEmailForm && (emailField || subjectField || bodyField)) {
      results.push({
        form,
        emailField: emailField?.name,
        subjectField: subjectField?.name,
        bodyField: bodyField?.name,
      });
    }
  }

  return results;
}

export const emailInjectionCheck: ActiveCheck = {
  name: 'email-injection',
  category: 'crlf-injection', // SMTP header injection is a CRLF variant
  parallel: false,

  async run(
    context: BrowserContext,
    targets: ScanTargets,
    config: ScanConfig,
    requestLogger?: RequestLogger,
  ): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    const emailForms = findEmailForms(targets.forms).slice(0, 5);

    if (emailForms.length === 0) {
      log.info('[email-injection] No email-sending forms found');
      return findings;
    }

    log.info(`[email-injection] Testing ${emailForms.length} email forms for SMTP header injection...`);

    const page = await context.newPage();
    try {
      for (const { form, emailField, subjectField, bodyField } of emailForms) {
        let actionUrl: string;
        try {
          actionUrl = new URL(form.action, form.pageUrl).href;
        } catch { continue; }

        // Build baseline form data
        const baseData: Record<string, string> = {};
        for (const input of form.inputs) {
          if (!input.name || input.type === 'submit') continue;
          if (EMAIL_INPUT_RE.test(input.name)) {
            baseData[input.name] = 'secbot@test.invalid';
          } else if (BODY_INPUT_RE.test(input.name)) {
            baseData[input.name] = 'SecBot security test probe';
          } else if (input.type === 'hidden') {
            baseData[input.name] = input.value || '';
          } else {
            baseData[input.name] = input.value || 'test';
          }
        }

        // Step 1: Baseline submission
        let baselineStatus: number;
        let baselineBody: string;
        try {
          const baseResp = await page.request.post(actionUrl, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            data: new URLSearchParams(baseData).toString(),
          });
          baselineStatus = baseResp.status();
          baselineBody = await baseResp.text();
        } catch { continue; }

        // Step 2: Test injection in each injectable field
        const injectableFields = [
          ...(emailField ? [{ name: emailField, type: 'email' }] : []),
          ...(subjectField ? [{ name: subjectField, type: 'subject' }] : []),
          ...(bodyField ? [{ name: bodyField, type: 'body' }] : []),
        ];

        for (const field of injectableFields) {
          for (const probe of INJECTION_PAYLOADS) {
            try {
              const probeData = { ...baseData };
              if (field.type === 'email') {
                probeData[field.name] = `secbot@test.invalid${probe.payload}`;
              } else {
                probeData[field.name] = `test${probe.payload}`;
              }

              const probeResp = await page.request.post(actionUrl, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: new URLSearchParams(probeData).toString(),
              });
              const probeStatus = probeResp.status();
              const probeBody = await probeResp.text();

              requestLogger?.log({
                timestamp: new Date().toISOString(),
                method: 'POST',
                url: actionUrl,
                responseStatus: probeStatus,
                phase: 'active-email-injection',
              });

              // Check for rejection patterns (server detected the injection)
              if (REJECTION_PATTERNS.some((re) => re.test(probeBody))) continue;

              // Check for acceptance indicators
              const injectionReflected = INJECTION_INDICATORS.some((re) => re.test(probeBody));
              const statusAccepted = probeStatus >= 200 && probeStatus < 400;
              const sameAsBaseline = probeStatus === baselineStatus &&
                Math.abs(probeBody.length - baselineBody.length) < 100;

              // Vulnerability detected if:
              // 1. Injection reflected in response (strong signal)
              // 2. Server accepted with same status as baseline (weak signal — payload not sanitized)
              if (injectionReflected || (statusAccepted && sameAsBaseline)) {
                const confidence = injectionReflected ? 'high' : 'medium';

                findings.push({
                  id: randomUUID(),
                  category: 'crlf-injection',
                  severity: 'medium',
                  confidence,
                  title: `Email Header Injection via ${field.name} field (${probe.name})`,
                  timestamp: new Date().toISOString(),
                  description: `The ${field.type} field "${field.name}" on ${actionUrl} ` +
                    `may be vulnerable to SMTP header injection. ` +
                    `Payload: ${probe.decoded.slice(0, 60)} ` +
                    `was ${injectionReflected ? 'reflected in the response' : 'accepted without sanitization'}. ` +
                    `An attacker can inject Bcc/Cc/Subject headers to use the mail server ` +
                    `as a spam relay or send phishing emails from the trusted domain. ` +
                    `CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection').`,
                  url: actionUrl,
                  evidence: `POST ${actionUrl} with ${field.name}=...${probe.name} → ${probeStatus}. ` +
                    `Baseline: ${baselineStatus}. ` +
                    (injectionReflected ? 'Injection indicators found in response.' : 'Response matches baseline (no rejection).'),
                  evidencePack: {
                    payloadUsed: `${field.name}=${probeData[field.name]?.slice(0, 200)}`,
                    detectionMethod: injectionReflected ? 'smtp-header-reflection' : 'smtp-header-acceptance',
                    httpExchange: {
                      request: {
                        method: 'POST',
                        url: actionUrl,
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams(probeData).toString().slice(0, 500),
                      },
                      response: {
                        status: probeStatus,
                        body: probeBody.slice(0, 1000),
                      },
                    },
                    curlCommand: `curl -X POST '${actionUrl}' -d '${new URLSearchParams(probeData).toString().slice(0, 200)}'`,
                  },
                });

                // One finding per field is enough
                break;
              }
            } catch {
              continue;
            }
          }
        }
      }
    } finally {
      await page.close();
    }

    log.info(`[email-injection] ${findings.length} findings`);
    return findings;
  },
};

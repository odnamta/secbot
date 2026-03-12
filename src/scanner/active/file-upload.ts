import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig, FormInfo } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';
import { delay } from '../../utils/shared.js';

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

export interface FileUploadPayload {
  /** Human-readable label */
  label: string;
  /** File name to use in the multipart upload */
  filename: string;
  /** MIME type sent in Content-Type for the part */
  contentType: string;
  /** File body (text — will be converted to Buffer at upload time) */
  body: string;
  /** Severity if accepted */
  severity: 'critical' | 'high' | 'medium';
  /** Short explanation shown in findings */
  risk: string;
}

export const UPLOAD_PAYLOADS: FileUploadPayload[] = [
  {
    label: 'shell-extension',
    filename: 'secbot-test.php',
    contentType: 'application/x-php',
    body: "<?php echo 'secbot-upload-marker'; ?>",
    severity: 'critical',
    risk: 'Server accepted a .php file upload — potential Remote Code Execution (RCE).',
  },
  {
    label: 'double-extension',
    filename: 'secbot-test.php.jpg',
    contentType: 'image/jpeg',
    body: "<?php echo 'secbot-upload-marker'; ?>",
    severity: 'critical',
    risk: 'Server accepted a double-extension (.php.jpg) upload — extension-based filter bypass may allow RCE.',
  },
  {
    label: 'svg-xss',
    filename: 'secbot-test.svg',
    contentType: 'image/svg+xml',
    body: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle r="50"/></svg>',
    severity: 'high',
    risk: 'Server accepted an SVG file with an onload handler — stored XSS possible if served inline.',
  },
  {
    label: 'mime-type-bypass',
    filename: 'secbot-test.php',
    contentType: 'image/jpeg',
    body: "<?php echo 'secbot-upload-marker'; ?>",
    severity: 'medium',
    risk: 'Server accepted a .php file when Content-Type was set to image/jpeg — MIME-type validation bypass.',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Filter forms that contain at least one <input type="file"> */
export function filterFileUploadForms(forms: FormInfo[]): FormInfo[] {
  return forms.filter((f) =>
    f.inputs.some((i) => i.type === 'file'),
  );
}

/** Detect whether the upload response indicates acceptance */
export function isUploadAccepted(status: number, body: string): boolean {
  // 2xx is the primary indicator
  if (status >= 200 && status < 300) {
    // Some apps return 200 with an error message — try to filter those out
    const lower = body.toLowerCase();
    const errorSignals = [
      'file type not allowed',
      'invalid file',
      'upload failed',
      'not permitted',
      'extension not allowed',
      'rejected',
      'disallowed',
      'unsupported file type',
      'error uploading',
    ];
    if (errorSignals.some((sig) => lower.includes(sig))) {
      return false;
    }
    return true;
  }
  return false;
}

/** Build the multipart form data record for Playwright's page.request API */
export function buildMultipartData(
  form: FormInfo,
  fileInputName: string,
  payload: FileUploadPayload,
): Record<string, string | { name: string; mimeType: string; buffer: Buffer }> {
  const data: Record<string, string | { name: string; mimeType: string; buffer: Buffer }> = {};

  // Fill non-file inputs with default values
  for (const input of form.inputs) {
    if (input.type === 'file') continue;
    data[input.name] = input.value || 'test';
  }

  // Attach the file payload as an in-memory buffer
  data[fileInputName] = {
    name: payload.filename,
    mimeType: payload.contentType,
    buffer: Buffer.from(payload.body, 'utf-8'),
  };

  return data;
}

// ---------------------------------------------------------------------------
// Active Check
// ---------------------------------------------------------------------------

export const fileUploadCheck: ActiveCheck = {
  name: 'file-upload',
  category: 'file-upload',
  async run(context: BrowserContext, targets, config: ScanConfig, requestLogger?: RequestLogger): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    const fileUploadForms = filterFileUploadForms(targets.forms);
    if (fileUploadForms.length === 0) {
      log.debug('File upload check: no file upload forms found — skipping');
      return findings;
    }

    log.info(`Testing ${fileUploadForms.length} file upload form(s) for dangerous upload vulnerabilities...`);

    for (const form of fileUploadForms) {
      const fileInputs = form.inputs.filter((i) => i.type === 'file');
      const actionUrl = new URL(form.action || form.pageUrl, form.pageUrl).href;

      for (const fileInput of fileInputs) {
        for (const payload of UPLOAD_PAYLOADS) {
          const multipart = buildMultipartData(form, fileInput.name, payload);
          const page = await context.newPage();

          try {
            const response = await page.request.post(actionUrl, {
              multipart,
            });

            const status = response.status();
            const body = await response.text();

            requestLogger?.log({
              timestamp: new Date().toISOString(),
              method: 'POST',
              url: actionUrl,
              responseStatus: status,
              phase: 'active-file-upload',
            });

            if (isUploadAccepted(status, body)) {
              findings.push({
                id: randomUUID(),
                category: 'file-upload',
                severity: payload.severity,
                title: `Dangerous File Upload Accepted: ${payload.label} ("${fileInput.name}" input)`,
                description: payload.risk,
                url: form.pageUrl,
                evidence: [
                  `Payload: ${payload.label}`,
                  `Filename: ${payload.filename}`,
                  `Content-Type: ${payload.contentType}`,
                  `Form action: ${actionUrl}`,
                  `HTTP ${status}`,
                  `Response snippet: ${body.slice(0, 300)}`,
                ].join('\n'),
                request: {
                  method: 'POST',
                  url: actionUrl,
                  headers: { 'Content-Type': 'multipart/form-data' },
                  body: `[file: ${payload.filename} (${payload.contentType})]`,
                },
                response: { status, bodySnippet: body.slice(0, 200) },
                timestamp: new Date().toISOString(),
              });

              // One finding per payload type per form is enough — move to next payload
              log.debug(`File upload accepted: ${payload.label} on ${actionUrl}`);
            }
          } catch (err) {
            log.debug(`File upload test (${payload.label}): ${(err as Error).message}`);
          } finally {
            await page.close();
          }

          await delay(config.requestDelay);
        }
      }
    }

    return findings;
  },
};

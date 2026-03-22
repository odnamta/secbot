/**
 * Bugcrowd API client for automated submission.
 *
 * Requires BUGCROWD_API_TOKEN environment variable.
 * This is opt-in only — never auto-submits without the --auto-submit flag.
 */

import { log } from '../../utils/logger.js';

const BC_API_BASE = 'https://api.bugcrowd.com';

export interface BugcrowdCredentials {
  apiToken: string;
}

export interface BCSubmission {
  programId: string; // Bugcrowd program UUID
  title: string;
  description: string; // markdown
  severity: 1 | 2 | 3 | 4 | 5; // P1-P5
  vulnerabilityRefs: string[]; // CWE references
}

export interface BCSubmissionResponse {
  id: string;
  type: string;
  attributes: {
    title: string;
    state: string;
    severity: number;
    submitted_at: string;
  };
}

/**
 * Submit a report to Bugcrowd.
 * Requires BUGCROWD_API_TOKEN env var.
 */
export async function submitReport(
  submission: BCSubmission,
  credentials?: BugcrowdCredentials,
): Promise<{ success: boolean; submissionId?: string; submissionUrl?: string; error?: string }> {
  const creds = credentials ?? getCredentialsFromEnv();
  if (!creds) {
    return { success: false, error: 'Bugcrowd credentials not found. Set BUGCROWD_API_TOKEN.' };
  }

  const body = {
    data: {
      type: 'submission',
      attributes: {
        title: submission.title,
        description: submission.description,
        severity: submission.severity,
        vulnerability_references: submission.vulnerabilityRefs.map(ref => ({ type: 'cwe', reference: ref })),
      },
      relationships: {
        program: { data: { type: 'program', id: submission.programId } },
      },
    },
  };

  log.debug(`Submitting report to Bugcrowd: ${submission.programId} — ${submission.title}`);

  try {
    const resp = await fetch(`${BC_API_BASE}/submissions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.bugcrowd+json',
        'Authorization': `Token ${creds.apiToken}`,
        'Accept': 'application/vnd.bugcrowd+json',
      },
      body: JSON.stringify(body),
    });

    if (resp.ok) {
      const data = await resp.json() as { data: BCSubmissionResponse };
      const submissionId = data.data.id;
      log.info(`Bugcrowd submission created: ${submissionId}`);
      return {
        success: true,
        submissionId,
        submissionUrl: `https://bugcrowd.com/submissions/${submissionId}`,
      };
    }

    const errorText = await resp.text();
    log.warn(`BC API error ${resp.status}: ${errorText.slice(0, 200)}`);
    return { success: false, error: `BC API ${resp.status}: ${errorText.slice(0, 500)}` };
  } catch (err) {
    log.error(`BC API request failed: ${(err as Error).message}`);
    return { success: false, error: `BC API error: ${(err as Error).message}` };
  }
}

/**
 * Check the status of a submitted Bugcrowd submission.
 */
export async function checkSubmissionStatus(
  submissionId: string,
  credentials?: BugcrowdCredentials,
): Promise<{ state: string; severity?: number; error?: string }> {
  const creds = credentials ?? getCredentialsFromEnv();
  if (!creds) return { state: 'unknown', error: 'No credentials' };

  try {
    const resp = await fetch(`${BC_API_BASE}/submissions/${submissionId}`, {
      headers: {
        'Authorization': `Token ${creds.apiToken}`,
        'Accept': 'application/vnd.bugcrowd+json',
      },
    });

    if (!resp.ok) return { state: 'unknown', error: `BC API ${resp.status}` };

    const data = await resp.json() as {
      data?: {
        attributes?: { state?: string; severity?: number };
      };
    };
    return {
      state: data.data?.attributes?.state ?? 'unknown',
      severity: data.data?.attributes?.severity,
    };
  } catch (err) {
    return { state: 'unknown', error: (err as Error).message };
  }
}

/**
 * Read Bugcrowd credentials from environment variables.
 */
export function getCredentialsFromEnv(): BugcrowdCredentials | null {
  const token = process.env.BUGCROWD_API_TOKEN;
  if (!token) return null;
  return { apiToken: token };
}

/**
 * Map a severity string to Bugcrowd priority (P1-P5).
 * P1=critical, P2=high, P3=medium, P4=low, P5=info
 */
export function mapSeverityToBC(severity: string): 1 | 2 | 3 | 4 | 5 {
  const map: Record<string, 1 | 2 | 3 | 4 | 5> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 5,
  };
  return map[severity] ?? 3;
}

/**
 * Map a CheckCategory to CWE reference string for Bugcrowd.
 * Returns undefined for categories without a direct mapping.
 */
export function mapCategoryToCWE(category: string): string | undefined {
  const map: Record<string, string> = {
    'xss': 'CWE-79',
    'sqli': 'CWE-89',
    'ssrf': 'CWE-918',
    'csrf': 'CWE-352',
    'open-redirect': 'CWE-601',
    'idor': 'CWE-639',
    'cors-misconfiguration': 'CWE-942',
    'command-injection': 'CWE-78',
    'xxe': 'CWE-611',
    'directory-traversal': 'CWE-22',
    'ssti': 'CWE-1336',
    'clickjacking': 'CWE-1021',
    'jwt': 'CWE-345',
    'broken-access-control': 'CWE-284',
    'info-disclosure': 'CWE-200',
    'prototype-pollution': 'CWE-1321',
    'request-smuggling': 'CWE-444',
    'race-condition': 'CWE-362',
    'crlf-injection': 'CWE-93',
    'ldap-injection': 'CWE-90',
    'insecure-deserialization': 'CWE-502',
    'graphql': 'CWE-200',
    'host-header': 'CWE-644',
    'cache-poisoning': 'CWE-349',
  };
  return map[category];
}

export { getCredentialsFromEnv as getBCCredentials };

/**
 * HackerOne API client for automated report submission.
 *
 * Requires HACKERONE_USERNAME and HACKERONE_API_TOKEN environment variables.
 * This is opt-in only — never auto-submits without the --auto-submit flag.
 */

import { log } from '../../utils/logger.js';

const H1_API_BASE = 'https://api.hackerone.com/v1';

export interface H1Credentials {
  username: string; // HackerOne API username
  apiToken: string; // HackerOne API token
}

export interface H1ReportSubmission {
  programHandle: string; // e.g., "security" for HackerOne's own program
  title: string;
  vulnerabilityInfo: string; // markdown description
  impact: string;
  severity: { rating: 'none' | 'low' | 'medium' | 'high' | 'critical' };
  weaknessId?: number; // CWE ID mapped to H1 weakness
  structuredScope?: { assetIdentifier: string; assetType: string };
}

export interface H1ReportResponse {
  id: string;
  type: string;
  attributes: {
    title: string;
    state: string;
    created_at: string;
    vulnerability_information: string;
  };
}

/**
 * Submit a report to HackerOne.
 * Requires HACKERONE_USERNAME and HACKERONE_API_TOKEN env vars.
 */
export async function submitReport(
  submission: H1ReportSubmission,
  credentials?: H1Credentials,
): Promise<{ success: boolean; reportId?: string; reportUrl?: string; error?: string }> {
  const creds = credentials ?? getCredentialsFromEnv();
  if (!creds) {
    return { success: false, error: 'HackerOne credentials not found. Set HACKERONE_USERNAME and HACKERONE_API_TOKEN.' };
  }

  const authHeader = 'Basic ' + Buffer.from(`${creds.username}:${creds.apiToken}`).toString('base64');

  const body = {
    data: {
      type: 'report',
      attributes: {
        team_handle: submission.programHandle,
        title: submission.title,
        vulnerability_information: submission.vulnerabilityInfo,
        impact: submission.impact,
        severity_rating: submission.severity.rating,
        weakness_id: submission.weaknessId,
      },
    },
  };

  log.debug(`Submitting report to H1: ${submission.programHandle} — ${submission.title}`);

  try {
    const resp = await fetch(`${H1_API_BASE}/reporters/reports`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
        'Accept': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (resp.ok) {
      const data = await resp.json() as { data: H1ReportResponse };
      const reportId = data.data.id;
      log.info(`H1 report submitted: ${reportId}`);
      return {
        success: true,
        reportId,
        reportUrl: `https://hackerone.com/reports/${reportId}`,
      };
    }

    const errorText = await resp.text();
    log.warn(`H1 API error ${resp.status}: ${errorText.slice(0, 200)}`);
    return { success: false, error: `H1 API ${resp.status}: ${errorText.slice(0, 500)}` };
  } catch (err) {
    log.error(`H1 API request failed: ${(err as Error).message}`);
    return { success: false, error: `H1 API error: ${(err as Error).message}` };
  }
}

/**
 * Check the status of a submitted report.
 */
export async function checkReportStatus(
  reportId: string,
  credentials?: H1Credentials,
): Promise<{ state: string; bountyAmount?: number; error?: string }> {
  const creds = credentials ?? getCredentialsFromEnv();
  if (!creds) return { state: 'unknown', error: 'No credentials' };

  const authHeader = 'Basic ' + Buffer.from(`${creds.username}:${creds.apiToken}`).toString('base64');

  try {
    const resp = await fetch(`${H1_API_BASE}/reports/${reportId}`, {
      headers: { 'Authorization': authHeader, 'Accept': 'application/json' },
    });

    if (!resp.ok) return { state: 'unknown', error: `H1 API ${resp.status}` };

    const data = await resp.json() as {
      data?: {
        attributes?: { state?: string };
        relationships?: {
          bounties?: { data?: Array<{ attributes?: { amount?: number } }> };
        };
      };
    };
    return {
      state: data.data?.attributes?.state ?? 'unknown',
      bountyAmount: data.data?.relationships?.bounties?.data?.[0]?.attributes?.amount,
    };
  } catch (err) {
    return { state: 'unknown', error: (err as Error).message };
  }
}

/**
 * Read HackerOne credentials from environment variables.
 */
export function getCredentialsFromEnv(): H1Credentials | null {
  const username = process.env.HACKERONE_USERNAME;
  const apiToken = process.env.HACKERONE_API_TOKEN;
  if (!username || !apiToken) return null;
  return { username, apiToken };
}

/**
 * Map a CheckCategory to HackerOne weakness ID (CWE-based).
 * Returns undefined for categories without a direct mapping.
 */
export function mapCategoryToH1Weakness(category: string): number | undefined {
  const map: Record<string, number> = {
    'xss': 60,                    // Cross-site Scripting (XSS) - Reflected
    'sqli': 67,                   // SQL Injection
    'ssrf': 918,                  // Server-Side Request Forgery
    'csrf': 352,                  // Cross-Site Request Forgery
    'open-redirect': 601,         // Open Redirect
    'idor': 639,                  // Authorization Bypass Through User-Controlled Key
    'cors-misconfiguration': 942, // Permissive CORS
    'command-injection': 78,      // OS Command Injection
    'xxe': 611,                   // XML External Entities
    'directory-traversal': 22,    // Path Traversal
    'ssti': 1336,                 // Server Side Template Injection
    'clickjacking': 1021,         // UI Redressing
    'jwt': 345,                   // Insufficient Verification of Data Authenticity
    'broken-access-control': 284, // Improper Access Control
    'info-disclosure': 200,       // Information Exposure
    'prototype-pollution': 1321,  // Improperly Controlled Modification of Object Prototype Attributes
    'request-smuggling': 444,     // HTTP Request Smuggling
    'race-condition': 362,        // Concurrent Execution using Shared Resource with Improper Synchronization
    'crlf-injection': 93,         // CRLF Injection
    'ldap-injection': 90,         // LDAP Injection
    'insecure-deserialization': 502, // Deserialization of Untrusted Data
    'graphql': 200,               // Information Exposure (introspection)
    'host-header': 644,           // Improper Neutralization of HTTP Headers
    'cache-poisoning': 349,       // Acceptance of Extraneous Untrusted Data With Trusted Data
  };
  return map[category];
}

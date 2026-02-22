import { randomUUID } from 'node:crypto';
import type { CallbackHit } from './callback-server.js';
import type { RawFinding, CheckCategory, Severity } from '../types.js';

interface HitClassification {
  category: CheckCategory;
  severity: Severity;
  title: string;
}

/** Parse the payload ID prefix to determine the source check type. */
function classifyHit(hit: CallbackHit): HitClassification {
  const pid = hit.payloadId;

  if (pid.startsWith('bxss-')) {
    return { category: 'xss', severity: 'high', title: 'Blind XSS — OOB Callback Received' };
  }
  if (pid.startsWith('bsqli-')) {
    return { category: 'sqli', severity: 'critical', title: 'Blind SQL Injection — OOB Callback Received' };
  }
  if (pid.startsWith('bssrf-')) {
    return { category: 'ssrf', severity: 'high', title: 'Blind SSRF — OOB Callback Received' };
  }

  // Unknown prefix — generic finding
  return { category: 'ssrf', severity: 'medium', title: 'OOB Callback Received — Unknown Source' };
}

/** Convert OOB callback hits into RawFinding objects for the report pipeline. */
export function convertHitsToFindings(hits: CallbackHit[]): RawFinding[] {
  return hits.map((hit) => {
    const { category, severity, title } = classifyHit(hit);

    return {
      id: `oob-${randomUUID()}`,
      category,
      severity,
      title,
      description: `Out-of-band callback received from payload ${hit.payloadId}. ` +
        `The target server made an outbound request to our callback server, confirming the vulnerability.`,
      url: hit.path,
      evidence: `OOB hit: ${hit.method} ${hit.path} from ${hit.sourceIp} at ${hit.timestamp} (payload: ${hit.payloadId})`,
      request: {
        method: hit.method,
        url: hit.path,
        headers: hit.headers,
        body: hit.body || undefined,
      },
      timestamp: hit.timestamp,
    };
  });
}

import { randomUUID } from 'node:crypto';
import * as tls from 'node:tls';
import * as https from 'node:https';
import type { RawFinding } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck } from './index.js';

/** Minimum HSTS max-age for preload eligibility: 1 year in seconds */
const HSTS_PRELOAD_MIN_AGE = 31536000;

/** Days before cert expiry to flag as "expiring soon" */
const CERT_EXPIRY_WARNING_DAYS = 30;

/** Connection timeout in milliseconds */
const TLS_CONNECT_TIMEOUT = 10_000;

/**
 * TLS/Crypto security check.
 *
 * Unlike other active checks, this does NOT use Playwright/BrowserContext.
 * It connects directly using Node.js tls module to inspect:
 * - TLS protocol version
 * - Certificate validity and expiry
 * - Self-signed certificate detection
 * - HSTS preload eligibility
 */
export const tlsCheck: ActiveCheck = {
  name: 'tls',
  category: 'tls',
  async run(_context, targets, config, requestLogger) {
    const targetUrl = config.targetUrl;

    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      log.debug('TLS check: invalid target URL, skipping');
      return [];
    }

    // Only run on HTTPS targets
    if (parsed.protocol !== 'https:') {
      log.info('TLS check: target is HTTP, skipping TLS analysis');
      return [];
    }

    const host = parsed.hostname;
    const port = parsed.port ? parseInt(parsed.port, 10) : 443;

    log.info(`TLS check: connecting to ${host}:${port}...`);

    const findings: RawFinding[] = [];

    try {
      const tlsInfo = await getTlsInfo(host, port);

      requestLogger?.log({
        timestamp: new Date().toISOString(),
        method: 'CONNECT',
        url: `tls://${host}:${port}`,
        responseStatus: 0,
        phase: 'active-tls',
      });

      // Check 1: TLS version
      if (tlsInfo.protocol) {
        const deprecatedVersions = ['TLSv1', 'TLSv1.1', 'SSLv3'];
        if (deprecatedVersions.includes(tlsInfo.protocol)) {
          findings.push({
            id: randomUUID(),
            category: 'tls',
            severity: 'high',
            title: 'Deprecated TLS Version',
            description: `The server negotiated ${tlsInfo.protocol}, which is deprecated and vulnerable to known attacks (POODLE, BEAST). Modern browsers may refuse connections.`,
            url: targetUrl,
            evidence: `Negotiated protocol: ${tlsInfo.protocol}`,
            timestamp: new Date().toISOString(),
          });
        } else {
          log.debug(`TLS version: ${tlsInfo.protocol} (OK)`);
        }
      }

      // Check 2: Certificate validity / expiry
      if (tlsInfo.validTo) {
        const expiryDate = new Date(tlsInfo.validTo);
        const now = new Date();
        const daysUntilExpiry = Math.floor(
          (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
        );

        if (daysUntilExpiry < 0) {
          findings.push({
            id: randomUUID(),
            category: 'tls',
            severity: 'high',
            title: 'Expired TLS Certificate',
            description: `The TLS certificate expired on ${tlsInfo.validTo} (${Math.abs(daysUntilExpiry)} days ago). Browsers will show security warnings and may block access.`,
            url: targetUrl,
            evidence: `Certificate valid to: ${tlsInfo.validTo}\nExpired ${Math.abs(daysUntilExpiry)} days ago`,
            timestamp: new Date().toISOString(),
          });
        } else if (daysUntilExpiry <= CERT_EXPIRY_WARNING_DAYS) {
          findings.push({
            id: randomUUID(),
            category: 'tls',
            severity: 'medium',
            title: 'TLS Certificate Expiring Soon',
            description: `The TLS certificate expires on ${tlsInfo.validTo} (in ${daysUntilExpiry} days). Renew the certificate before it expires to avoid service disruption.`,
            url: targetUrl,
            evidence: `Certificate valid to: ${tlsInfo.validTo}\nExpires in ${daysUntilExpiry} days`,
            timestamp: new Date().toISOString(),
          });
        } else {
          log.debug(`Certificate expires in ${daysUntilExpiry} days (OK)`);
        }
      }

      // Check 3: Self-signed certificate
      if (tlsInfo.selfSigned) {
        findings.push({
          id: randomUUID(),
          category: 'tls',
          severity: 'medium',
          title: 'Self-Signed TLS Certificate',
          description:
            'The server uses a self-signed certificate, which is not trusted by browsers and may indicate a misconfigured or development environment.',
          url: targetUrl,
          evidence: `Issuer: ${tlsInfo.issuer ?? 'unknown'}\nSubject: ${tlsInfo.subject ?? 'unknown'}`,
          timestamp: new Date().toISOString(),
        });
      }

      // Check 4: HSTS preload eligibility
      const hstsInfo = await getHstsHeader(host, port);
      if (hstsInfo !== null) {
        const hasIncludeSubDomains = /includeSubDomains/i.test(hstsInfo);
        const maxAgeMatch = hstsInfo.match(/max-age\s*=\s*(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

        if (!hasIncludeSubDomains || maxAge < HSTS_PRELOAD_MIN_AGE) {
          const issues: string[] = [];
          if (!hasIncludeSubDomains) issues.push('missing includeSubDomains');
          if (maxAge < HSTS_PRELOAD_MIN_AGE)
            issues.push(`max-age=${maxAge} (need >= ${HSTS_PRELOAD_MIN_AGE})`);

          findings.push({
            id: randomUUID(),
            category: 'tls',
            severity: 'info',
            title: 'HSTS Not Eligible for Preload',
            description: `The HSTS header is present but does not meet preload requirements: ${issues.join(', ')}. Consider adding includeSubDomains and setting max-age to at least 1 year for HSTS preload list eligibility.`,
            url: targetUrl,
            evidence: `Strict-Transport-Security: ${hstsInfo}`,
            timestamp: new Date().toISOString(),
          });
        }
      } else {
        // No HSTS header at all — this is already covered by passive checks,
        // but we note it for completeness in TLS context
        log.debug('No HSTS header found (passive check handles this)');
      }
    } catch (err) {
      log.warn(`TLS check failed for ${host}:${port}: ${(err as Error).message}`);
      // Graceful degradation — don't crash, just return what we have
    }

    log.info(`TLS check: ${findings.length} finding(s)`);
    return findings;
  },
};

/** TLS connection information extracted from the handshake */
export interface TlsInfo {
  protocol: string | null;
  validTo: string | null;
  validFrom: string | null;
  selfSigned: boolean;
  issuer: string | null;
  subject: string | null;
}

/**
 * Connect to a host via TLS and extract certificate/protocol information.
 * Exported for testing.
 */
export function getTlsInfo(host: string, port: number): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        rejectUnauthorized: false, // We want to inspect even invalid certs
        timeout: TLS_CONNECT_TIMEOUT,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();

        const issuerCN = cert.issuer?.CN ?? cert.issuer?.O ?? null;
        const subjectCN = cert.subject?.CN ?? cert.subject?.O ?? null;

        // Self-signed: issuer matches subject
        const selfSigned = !!(
          cert.issuer &&
          cert.subject &&
          cert.issuer.CN === cert.subject.CN &&
          cert.issuer.O === cert.subject.O
        );

        socket.destroy();

        resolve({
          protocol: protocol ?? null,
          validTo: cert.valid_to ?? null,
          validFrom: cert.valid_from ?? null,
          selfSigned,
          issuer: issuerCN,
          subject: subjectCN,
        });
      },
    );

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`TLS connection to ${host}:${port} timed out`));
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

/**
 * Fetch the HSTS header from the target via HTTPS request.
 * Returns the header value or null if not present.
 * Exported for testing.
 */
export function getHstsHeader(host: string, port: number): Promise<string | null> {
  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: host,
        port,
        path: '/',
        method: 'HEAD',
        rejectUnauthorized: false,
        timeout: TLS_CONNECT_TIMEOUT,
      },
      (res) => {
        const hsts = res.headers['strict-transport-security'] ?? null;
        res.resume(); // Drain the response
        resolve(hsts);
      },
    );

    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.on('error', () => {
      resolve(null); // Gracefully handle errors
    });

    req.end();
  });
}

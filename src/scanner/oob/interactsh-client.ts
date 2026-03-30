import { log } from '../../utils/logger.js';
import { randomBytes } from 'node:crypto';

const DEFAULT_INTERACTSH_SERVER = 'https://oast.fun';

export interface InteractshOptions {
  /** Interactsh server URL (default: https://oast.fun) */
  serverUrl?: string;
  /** Polling interval in ms (default: 5000) */
  pollInterval?: number;
  /** Optional auth token for self-hosted Interactsh servers */
  token?: string;
}

export interface Interaction {
  /** Protocol that was hit (http, dns, smtp) */
  protocol: string;
  /** Full URL or query that was received */
  fullId: string;
  /** Raw request data if available */
  rawRequest?: string;
  /** Timestamp of the interaction */
  timestamp: string;
  /** Client IP that made the request */
  remoteAddress?: string;
}

/**
 * Interactsh OOB client — generates unique callback URLs and polls for interactions.
 *
 * Interactsh provides publicly-reachable callback domains that real targets can
 * hit, unlike the built-in CallbackServer which binds to 127.0.0.1.
 *
 * Flow:
 *   1. Register with the Interactsh server -> get a unique subdomain
 *   2. Inject that subdomain into payloads (SSRF, XSS, SQLi, CMDi, etc.)
 *   3. Poll the server for interactions (HTTP/DNS/SMTP hits)
 *   4. If hits arrive -> blind vulnerability confirmed
 *   5. Deregister on cleanup
 *
 * Usage:
 *   const client = new InteractshClient();
 *   await client.register();
 *   const url = client.getUrl();        // e.g. "abc123def456abcd.oast.fun"
 *   const httpUrl = client.getHttpUrl(); // e.g. "http://abc123def456abcd.oast.fun"
 *   // ... inject url into payloads, run checks ...
 *   const interactions = await client.poll();
 *   await client.deregister();
 */
export class InteractshClient {
  private serverUrl: string;
  private correlationId: string;
  private secretKey: string;
  private registered = false;
  private pollInterval: number;
  private token?: string;

  constructor(options: InteractshOptions = {}) {
    this.serverUrl = (options.serverUrl ?? DEFAULT_INTERACTSH_SERVER).replace(/\/+$/, '');
    this.pollInterval = options.pollInterval ?? 5000;
    this.token = options.token;
    // 20-char hex correlation ID — Interactsh uses this as the subdomain prefix
    this.correlationId = randomBytes(10).toString('hex').slice(0, 20);
    this.secretKey = randomBytes(16).toString('hex');
  }

  /**
   * Register with the Interactsh server.
   * Returns true on success, false on failure (non-throwing).
   */
  async register(): Promise<boolean> {
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (this.token) {
        headers['Authorization'] = this.token;
      }

      const resp = await fetch(`${this.serverUrl}/register`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          'public-key': this.secretKey,
          'secret-key': this.secretKey,
          'correlation-id': this.correlationId,
        }),
        signal: AbortSignal.timeout(10_000),
      });

      this.registered = resp.ok;
      if (this.registered) {
        log.info(`Interactsh registered: ${this.getUrl()}`);
      } else {
        log.warn(`Interactsh registration returned ${resp.status}: ${resp.statusText}`);
      }
      return this.registered;
    } catch (err) {
      log.warn(`Interactsh registration failed: ${(err as Error).message}`);
      return false;
    }
  }

  /**
   * Get the unique OOB domain for payload injection (no protocol prefix).
   * Example: "abc123def456abcd.oast.fun"
   */
  getUrl(): string {
    const host = new URL(this.serverUrl).hostname;
    return `${this.correlationId}.${host}`;
  }

  /**
   * Get a full HTTP URL for injection.
   * Example: "http://abc123def456abcd.oast.fun"
   */
  getHttpUrl(): string {
    return `http://${this.getUrl()}`;
  }

  /**
   * Generate a tagged sub-URL for correlating a specific injection point.
   * The tag becomes a subdomain prefix, allowing you to tell which payload triggered the hit.
   *
   * Example: getTaggedUrl("bssrf-01") => "http://bssrf-01.abc123def456abcd.oast.fun"
   */
  getTaggedUrl(tag: string): string {
    // Sanitize tag for DNS label safety: lowercase, alphanum + hyphen, max 63 chars
    const safeTag = tag
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 63);
    return `http://${safeTag}.${this.getUrl()}`;
  }

  /**
   * Poll the Interactsh server for interactions.
   * Returns an empty array if not registered or on error.
   */
  async poll(): Promise<Interaction[]> {
    if (!this.registered) return [];

    try {
      const headers: Record<string, string> = {};
      if (this.token) {
        headers['Authorization'] = this.token;
      }

      const resp = await fetch(
        `${this.serverUrl}/poll?id=${this.correlationId}&secret=${this.secretKey}`,
        {
          headers,
          signal: AbortSignal.timeout(10_000),
        },
      );

      if (!resp.ok) return [];

      const data = (await resp.json()) as Record<string, unknown>;

      if (!data.data || !Array.isArray(data.data)) return [];

      return (data.data as Record<string, unknown>[]).map((d) => ({
        protocol: (d.protocol as string) ?? 'unknown',
        fullId: (d['full-id'] as string) ?? (d.fullId as string) ?? '',
        rawRequest: (d['raw-request'] as string) ?? (d.rawRequest as string) ?? undefined,
        timestamp: (d.timestamp as string) ?? new Date().toISOString(),
        remoteAddress: (d['remote-address'] as string) ?? (d.remoteAddress as string) ?? undefined,
      }));
    } catch {
      return [];
    }
  }

  /**
   * Wait and poll multiple times for delayed callbacks.
   * Collects all interactions received during the wait window.
   *
   * @param totalWaitMs - Total time to wait (default: 30s)
   * @returns All interactions collected across all poll cycles
   */
  async waitForInteractions(totalWaitMs: number = 30_000): Promise<Interaction[]> {
    const allInteractions: Interaction[] = [];
    const startTime = Date.now();

    while (Date.now() - startTime < totalWaitMs) {
      const hits = await this.poll();
      allInteractions.push(...hits);
      if (hits.length > 0) {
        log.info(`Interactsh: received ${hits.length} interaction(s)`);
      }
      await new Promise((r) => setTimeout(r, this.pollInterval));
    }

    return allInteractions;
  }

  /**
   * Deregister from the Interactsh server (cleanup).
   * Best-effort — does not throw on failure.
   */
  async deregister(): Promise<void> {
    if (!this.registered) return;

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (this.token) {
        headers['Authorization'] = this.token;
      }

      await fetch(`${this.serverUrl}/deregister`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          'correlation-id': this.correlationId,
          'secret-key': this.secretKey,
        }),
        signal: AbortSignal.timeout(5_000),
      });
      this.registered = false;
      log.info('Interactsh deregistered');
    } catch {
      // Best effort — server may already be gone
      this.registered = false;
    }
  }

  /** Whether the client is currently registered with the server. */
  isRegistered(): boolean {
    return this.registered;
  }

  /** The correlation ID used as the subdomain prefix. */
  getCorrelationId(): string {
    return this.correlationId;
  }
}

/**
 * Convert Interactsh interactions into CallbackHit-compatible objects
 * so they flow through the existing hit-converter pipeline.
 */
export function interactionsToCallbackHits(
  interactions: Interaction[],
): Array<{
  payloadId: string;
  timestamp: string;
  sourceIp: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
}> {
  return interactions.map((i) => {
    // Extract the tag (payload ID) from the fullId subdomain prefix
    // fullId format: "tag.correlationId.server" or just "correlationId.server"
    const parts = i.fullId.split('.');
    const payloadId = parts.length > 2 ? parts[0] : i.fullId;

    return {
      payloadId,
      timestamp: i.timestamp,
      sourceIp: i.remoteAddress ?? 'unknown',
      method: i.protocol.toUpperCase() === 'DNS' ? 'DNS' : 'GET',
      path: `/${i.fullId}`,
      headers: {},
      body: i.rawRequest ?? '',
    };
  });
}

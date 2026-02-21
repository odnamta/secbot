import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { log } from '../../utils/logger.js';

export interface CallbackHit {
  payloadId: string;
  timestamp: string;
  sourceIp: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
}

export class CallbackServer {
  private server: Server | null = null;
  private hits: CallbackHit[] = [];
  private host: string;
  private port = 0;

  constructor(host?: string) {
    this.host = host ?? '0.0.0.0';
  }

  /**
   * Start the HTTP callback listener on the specified port.
   */
  async start(port: number): Promise<void> {
    if (this.server) {
      throw new Error('Callback server is already running');
    }

    this.port = port;

    return new Promise<void>((resolve, reject) => {
      const srv = createServer((req: IncomingMessage, res: ServerResponse) => {
        this.handleRequest(req, res);
      });

      srv.on('error', (err) => {
        reject(err);
      });

      srv.listen(port, this.host, () => {
        this.server = srv;
        // When port 0 is requested, read the actual assigned port
        const addr = srv.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        log.info(`OOB callback server listening on ${this.host}:${this.port}`);
        resolve();
      });
    });
  }

  /**
   * Gracefully shut down the callback server.
   */
  async stop(): Promise<void> {
    if (!this.server) return;

    return new Promise<void>((resolve, reject) => {
      this.server!.close((err) => {
        this.server = null;
        if (err) {
          reject(err);
        } else {
          log.info('OOB callback server stopped');
          resolve();
        }
      });
    });
  }

  /**
   * Generate a callback URL for a given payload ID.
   */
  generateCallbackUrl(payloadId: string): string {
    return `http://${this.host === '0.0.0.0' ? '127.0.0.1' : this.host}:${this.port}/cb/${payloadId}`;
  }

  /**
   * Return all received callback hits.
   */
  getHits(): CallbackHit[] {
    return [...this.hits];
  }

  /**
   * Check whether the server is currently running.
   */
  isRunning(): boolean {
    return this.server !== null;
  }

  /**
   * Return the port the server is listening on.
   */
  getPort(): number {
    return this.port;
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const chunks: Buffer[] = [];

    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf-8');
      const path = req.url ?? '/';

      // Extract payloadId from path: /cb/<payloadId>
      const match = path.match(/^\/cb\/(.+)/);
      const payloadId = match ? match[1] : path;

      const sourceIp =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ??
        req.socket.remoteAddress ??
        'unknown';

      const headers: Record<string, string> = {};
      for (const [key, val] of Object.entries(req.headers)) {
        if (typeof val === 'string') {
          headers[key] = val;
        } else if (Array.isArray(val)) {
          headers[key] = val.join(', ');
        }
      }

      const hit: CallbackHit = {
        payloadId,
        timestamp: new Date().toISOString(),
        sourceIp,
        method: req.method ?? 'GET',
        path,
        headers,
        body,
      };

      this.hits.push(hit);

      log.info(
        `OOB callback received: ${hit.method} ${hit.path} from ${hit.sourceIp} (payload: ${hit.payloadId})`,
      );

      // Always respond 200 OK — we want the caller to think it succeeded
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });
  }
}

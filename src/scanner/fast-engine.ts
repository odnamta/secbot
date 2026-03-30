import { log } from '../utils/logger.js';

export interface FastRequestOptions {
  method?: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE';
  headers?: Record<string, string>;
  body?: string;
  timeout?: number; // ms, default 10000
  followRedirects?: boolean; // default true
  maxRedirects?: number; // default 5
  proxy?: string;
}

export interface FastResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  redirected: boolean;
  timeMs: number;
}

export interface FastEngineOptions {
  concurrency: number; // max concurrent requests, default 50
  requestDelay: number; // ms between requests, default 0
  userAgent: string;
  proxy?: string;
  defaultHeaders?: Record<string, string>;
  rateLimitRps?: number; // max requests per second
  onResponse?: (resp: FastResponse) => void; // callback per response
}

/**
 * Fast HTTP engine — uses Node fetch for 100-1000x throughput vs Playwright.
 * Designed for content discovery, subdomain probing, and template scanning.
 */
export class FastEngine {
  private options: FastEngineOptions;
  private activeRequests = 0;
  private totalRequests = 0;
  private totalErrors = 0;
  private startTime = 0;
  private lastRequestTime = 0;

  constructor(options: Partial<FastEngineOptions> = {}) {
    this.options = {
      concurrency: options.concurrency ?? 50,
      requestDelay: options.requestDelay ?? 0,
      userAgent: options.userAgent ?? 'Mozilla/5.0 (compatible; SecBot/2.0)',
      proxy: options.proxy,
      defaultHeaders: options.defaultHeaders ?? {},
      rateLimitRps: options.rateLimitRps,
      onResponse: options.onResponse,
    };
  }

  /**
   * Send a single HTTP request.
   */
  async request(url: string, opts: FastRequestOptions = {}): Promise<FastResponse> {
    // Rate limiting — enforce minimum interval between requests
    if (this.options.rateLimitRps) {
      const minInterval = 1000 / this.options.rateLimitRps;
      const elapsed = Date.now() - this.lastRequestTime;
      if (elapsed < minInterval) {
        await new Promise(r => setTimeout(r, minInterval - elapsed));
      }
    }

    // Per-request delay (e.g. stealth mode)
    if (this.options.requestDelay > 0) {
      await new Promise(r => setTimeout(r, this.options.requestDelay));
    }

    this.lastRequestTime = Date.now();
    if (this.startTime === 0) this.startTime = this.lastRequestTime;
    this.totalRequests++;
    this.activeRequests++;

    const start = Date.now();

    try {
      const controller = new AbortController();
      const timeoutMs = opts.timeout ?? 10000;
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const resp = await fetch(url, {
        method: opts.method ?? 'GET',
        headers: {
          'User-Agent': this.options.userAgent,
          ...this.options.defaultHeaders,
          ...opts.headers,
        },
        body: opts.body,
        redirect: opts.followRedirects !== false ? 'follow' : 'manual',
        signal: controller.signal,
      });

      clearTimeout(timer);

      const headers: Record<string, string> = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });

      const body = await resp.text();
      const result: FastResponse = {
        url: resp.url,
        status: resp.status,
        headers,
        body,
        redirected: resp.redirected,
        timeMs: Date.now() - start,
      };

      this.options.onResponse?.(result);
      return result;
    } catch (err) {
      this.totalErrors++;
      throw err;
    } finally {
      this.activeRequests--;
    }
  }

  /**
   * Convenience: send a GET request.
   */
  async get(url: string, opts?: Omit<FastRequestOptions, 'method'>): Promise<FastResponse> {
    return this.request(url, { ...opts, method: 'GET' });
  }

  /**
   * Convenience: send a POST request with a body.
   */
  async post(url: string, body: string, opts?: Omit<FastRequestOptions, 'method' | 'body'>): Promise<FastResponse> {
    return this.request(url, { ...opts, method: 'POST', body });
  }

  /**
   * Convenience: send a HEAD request (no body download).
   */
  async head(url: string, opts?: Omit<FastRequestOptions, 'method'>): Promise<FastResponse> {
    return this.request(url, { ...opts, method: 'HEAD' });
  }

  /**
   * Send multiple requests with concurrency control.
   * Returns results in same order as input URLs.
   */
  async batch(
    urls: string[],
    opts: FastRequestOptions = {},
  ): Promise<Array<FastResponse | null>> {
    const results: Array<FastResponse | null> = new Array(urls.length).fill(null);
    let nextIndex = 0;

    const worker = async () => {
      while (nextIndex < urls.length) {
        const i = nextIndex++;
        try {
          results[i] = await this.request(urls[i], opts);
        } catch (err) {
          log.debug(`fast-engine: request failed for ${urls[i]}: ${err}`);
          results[i] = null;
        }
      }
    };

    // Launch concurrent workers up to concurrency limit or URL count
    const workerCount = Math.min(this.options.concurrency, urls.length);
    const workers = Array.from({ length: workerCount }, () => worker());
    await Promise.all(workers);
    return results;
  }

  /**
   * Probe a list of URLs — return only those that respond with specific status codes.
   * Uses HEAD by default for speed (no body download).
   */
  async probe(
    urls: string[],
    acceptStatuses: number[] = [200, 201, 301, 302, 403],
    method: 'GET' | 'HEAD' = 'HEAD',
  ): Promise<FastResponse[]> {
    const results = await this.batch(urls, { method, timeout: 5000 });
    return results.filter((r): r is FastResponse =>
      r !== null && acceptStatuses.includes(r.status),
    );
  }

  /**
   * Get engine statistics.
   */
  getStats(): { total: number; errors: number; active: number; rps: number } {
    const elapsed = this.startTime > 0 ? (Date.now() - this.startTime) / 1000 : 0;
    return {
      total: this.totalRequests,
      errors: this.totalErrors,
      active: this.activeRequests,
      rps: elapsed > 0 ? Math.round(this.totalRequests / elapsed) : 0,
    };
  }
}

import type {
  RequestMiddleware,
  ResponseMiddleware,
  MiddlewareRequest,
  MiddlewareResponse,
} from './types.js';
import { log } from '../utils/logger.js';

/**
 * Pipeline that processes HTTP requests and responses through a chain of
 * middleware functions. Request middlewares transform the request object
 * sequentially; response middlewares observe (but do not modify) responses.
 */
export class MiddlewarePipeline {
  private requestMiddlewares: RequestMiddleware[] = [];
  private responseMiddlewares: ResponseMiddleware[] = [];

  addRequestMiddleware(mw: RequestMiddleware): void {
    this.requestMiddlewares.push(mw);
  }

  addResponseMiddleware(mw: ResponseMiddleware): void {
    this.responseMiddlewares.push(mw);
  }

  /** Run all request middlewares in order, returning the (possibly modified) request. */
  processRequest(req: MiddlewareRequest): MiddlewareRequest {
    let current = req;
    for (const mw of this.requestMiddlewares) {
      current = mw(current);
    }
    return current;
  }

  /** Run all response middlewares in order (observation only, no return value). */
  processResponse(resp: MiddlewareResponse): void {
    for (const mw of this.responseMiddlewares) {
      mw(resp);
    }
  }

  get requestCount(): number {
    return this.requestMiddlewares.length;
  }

  get responseCount(): number {
    return this.responseMiddlewares.length;
  }
}

// ─── Built-in Middleware Factories ──────────────────────────────────

/** Merges custom headers into every request. */
export function createCustomHeaderMiddleware(
  headers: Record<string, string>,
): RequestMiddleware {
  return (req: MiddlewareRequest): MiddlewareRequest => ({
    ...req,
    headers: { ...req.headers, ...headers },
  });
}

/** Logs every response at debug level for troubleshooting. */
export function createResponseLoggerMiddleware(): ResponseMiddleware {
  return (resp: MiddlewareResponse): void => {
    log.debug(`[middleware] ${resp.status} ${resp.url}`);
  };
}

/**
 * Common WAF block page patterns. These appear in the response body or
 * are paired with a 403 status to indicate the request was blocked.
 */
const WAF_BLOCK_PATTERNS = [
  /access denied/i,
  /forbidden/i,
  /blocked by/i,
  /web application firewall/i,
  /cloudflare/i,
  /akamai/i,
  /incapsula/i,
  /sucuri/i,
  /mod_security/i,
  /request rejected/i,
  /this request has been blocked/i,
  /security policy/i,
];

export interface WafBlockEvent {
  url: string;
  status: number;
  matchedPattern: string;
}

/**
 * Detects WAF block pages (403 + common block patterns).
 * Returns a middleware and an array that accumulates detected blocks.
 */
export function createWafBlockDetector(): {
  middleware: ResponseMiddleware;
  detections: WafBlockEvent[];
} {
  const detections: WafBlockEvent[] = [];

  const middleware: ResponseMiddleware = (resp: MiddlewareResponse): void => {
    if (resp.status !== 403 || !resp.body) return;

    for (const pattern of WAF_BLOCK_PATTERNS) {
      if (pattern.test(resp.body)) {
        const event: WafBlockEvent = {
          url: resp.url,
          status: resp.status,
          matchedPattern: pattern.source,
        };
        detections.push(event);
        log.warn(`WAF block detected on ${resp.url}: matched "${pattern.source}"`);
        break; // one detection per response is enough
      }
    }
  };

  return { middleware, detections };
}

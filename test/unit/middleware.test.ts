import { describe, it, expect, vi } from 'vitest';
import {
  MiddlewarePipeline,
  createCustomHeaderMiddleware,
  createResponseLoggerMiddleware,
  createWafBlockDetector,
} from '../../src/scanner/middleware.js';
import { log } from '../../src/utils/logger.js';
import type {
  MiddlewareRequest,
  MiddlewareResponse,
  RequestMiddleware,
  ResponseMiddleware,
} from '../../src/scanner/types.js';

function makeRequest(overrides: Partial<MiddlewareRequest> = {}): MiddlewareRequest {
  return {
    url: 'https://example.com/api/test',
    method: 'GET',
    headers: { 'content-type': 'application/json' },
    ...overrides,
  };
}

function makeResponse(overrides: Partial<MiddlewareResponse> = {}): MiddlewareResponse {
  return {
    url: 'https://example.com/api/test',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html><body>OK</body></html>',
    ...overrides,
  };
}

describe('MiddlewarePipeline', () => {
  it('runs request middlewares in order', () => {
    const pipeline = new MiddlewarePipeline();
    const order: number[] = [];

    pipeline.addRequestMiddleware((req) => {
      order.push(1);
      return { ...req, headers: { ...req.headers, 'x-first': 'true' } };
    });
    pipeline.addRequestMiddleware((req) => {
      order.push(2);
      return { ...req, headers: { ...req.headers, 'x-second': 'true' } };
    });
    pipeline.addRequestMiddleware((req) => {
      order.push(3);
      return { ...req, headers: { ...req.headers, 'x-third': 'true' } };
    });

    const result = pipeline.processRequest(makeRequest());

    expect(order).toEqual([1, 2, 3]);
    expect(result.headers['x-first']).toBe('true');
    expect(result.headers['x-second']).toBe('true');
    expect(result.headers['x-third']).toBe('true');
  });

  it('runs response middlewares in order', () => {
    const pipeline = new MiddlewarePipeline();
    const order: number[] = [];

    pipeline.addResponseMiddleware(() => { order.push(1); });
    pipeline.addResponseMiddleware(() => { order.push(2); });
    pipeline.addResponseMiddleware(() => { order.push(3); });

    pipeline.processResponse(makeResponse());

    expect(order).toEqual([1, 2, 3]);
  });

  it('empty pipeline passes request through unchanged', () => {
    const pipeline = new MiddlewarePipeline();
    const req = makeRequest({ headers: { 'x-original': 'yes' } });
    const result = pipeline.processRequest(req);

    expect(result.url).toBe(req.url);
    expect(result.method).toBe(req.method);
    expect(result.headers).toEqual(req.headers);
    expect(result.body).toBe(req.body);
  });

  it('empty pipeline processes response without error', () => {
    const pipeline = new MiddlewarePipeline();
    expect(() => pipeline.processResponse(makeResponse())).not.toThrow();
  });

  it('tracks middleware counts', () => {
    const pipeline = new MiddlewarePipeline();
    expect(pipeline.requestCount).toBe(0);
    expect(pipeline.responseCount).toBe(0);

    pipeline.addRequestMiddleware((req) => req);
    pipeline.addResponseMiddleware(() => {});

    expect(pipeline.requestCount).toBe(1);
    expect(pipeline.responseCount).toBe(1);
  });

  it('request middleware modifies headers cumulatively', () => {
    const pipeline = new MiddlewarePipeline();

    pipeline.addRequestMiddleware((req) => ({
      ...req,
      headers: { ...req.headers, 'x-step': '1' },
    }));
    pipeline.addRequestMiddleware((req) => ({
      ...req,
      headers: { ...req.headers, 'x-step': req.headers['x-step'] + ',2' },
    }));

    const result = pipeline.processRequest(makeRequest());
    expect(result.headers['x-step']).toBe('1,2');
  });

  it('response middleware receives response data', () => {
    const pipeline = new MiddlewarePipeline();
    let captured: MiddlewareResponse | null = null;

    pipeline.addResponseMiddleware((resp) => {
      captured = resp;
    });

    const resp = makeResponse({ status: 404, body: 'Not found' });
    pipeline.processResponse(resp);

    expect(captured).not.toBeNull();
    expect(captured!.status).toBe(404);
    expect(captured!.body).toBe('Not found');
    expect(captured!.url).toBe('https://example.com/api/test');
  });
});

describe('createCustomHeaderMiddleware', () => {
  it('adds custom headers', () => {
    const mw = createCustomHeaderMiddleware({
      'x-api-key': 'abc123',
      'x-tenant': 'secbot',
    });
    const result = mw(makeRequest());

    expect(result.headers['x-api-key']).toBe('abc123');
    expect(result.headers['x-tenant']).toBe('secbot');
  });

  it('merges with existing headers', () => {
    const mw = createCustomHeaderMiddleware({ 'x-new': 'header' });
    const req = makeRequest({ headers: { 'x-existing': 'stays' } });
    const result = mw(req);

    expect(result.headers['x-existing']).toBe('stays');
    expect(result.headers['x-new']).toBe('header');
  });

  it('overrides conflicting headers', () => {
    const mw = createCustomHeaderMiddleware({ 'content-type': 'text/xml' });
    const req = makeRequest({ headers: { 'content-type': 'application/json' } });
    const result = mw(req);

    expect(result.headers['content-type']).toBe('text/xml');
  });
});

describe('createResponseLoggerMiddleware', () => {
  it('logs response at debug level', () => {
    const debugSpy = vi.spyOn(log, 'debug');

    const mw = createResponseLoggerMiddleware();
    mw(makeResponse({ status: 200, url: 'https://example.com/page' }));

    expect(debugSpy).toHaveBeenCalledWith(
      expect.stringContaining('200 https://example.com/page'),
    );

    debugSpy.mockRestore();
  });
});

describe('createWafBlockDetector', () => {
  it('detects WAF block on 403 with "Access Denied" body', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      body: '<html><body><h1>Access Denied</h1><p>You are blocked.</p></body></html>',
    }));

    expect(detections).toHaveLength(1);
    expect(detections[0].matchedPattern).toBe('access denied');
    expect(detections[0].status).toBe(403);
  });

  it('detects Cloudflare WAF block page', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      body: '<html><body>Attention Required! | Cloudflare</body></html>',
    }));

    expect(detections).toHaveLength(1);
    expect(detections[0].matchedPattern).toBe('cloudflare');
  });

  it('detects Akamai WAF block page', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      body: '<html><body>Access is blocked by Akamai security policy</body></html>',
    }));

    expect(detections).toHaveLength(1);
    // Should match "blocked by" before "akamai"
    expect(detections[0].matchedPattern).toBe('blocked by');
  });

  it('detects "request rejected" pattern', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      body: '<html><body><p>Your request has been rejected by our web application firewall.</p></body></html>',
    }));

    expect(detections).toHaveLength(1);
  });

  it('ignores 403 without WAF patterns in body', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      body: '<html><body>You do not have permission to view this page.</body></html>',
    }));

    expect(detections).toHaveLength(0);
  });

  it('ignores non-403 even with WAF-like body', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 200,
      body: '<html><body>Cloudflare CDN serves this page</body></html>',
    }));

    expect(detections).toHaveLength(0);
  });

  it('ignores 403 without body', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      body: undefined,
    }));

    expect(detections).toHaveLength(0);
  });

  it('accumulates multiple detections', () => {
    const { middleware, detections } = createWafBlockDetector();

    middleware(makeResponse({
      status: 403,
      url: 'https://example.com/page1',
      body: '<html><body>Access Denied</body></html>',
    }));
    middleware(makeResponse({
      status: 403,
      url: 'https://example.com/page2',
      body: '<html><body>Request Rejected by security policy</body></html>',
    }));

    expect(detections).toHaveLength(2);
    expect(detections[0].url).toBe('https://example.com/page1');
    expect(detections[1].url).toBe('https://example.com/page2');
  });

  it('only records one detection per response', () => {
    const { middleware, detections } = createWafBlockDetector();

    // Body contains multiple WAF patterns — should only match once
    middleware(makeResponse({
      status: 403,
      body: '<html><body>Access Denied - Blocked by Cloudflare Web Application Firewall</body></html>',
    }));

    expect(detections).toHaveLength(1);
  });
});

describe('middleware pipeline integration', () => {
  it('combines custom headers + response logger', () => {
    const pipeline = new MiddlewarePipeline();
    const logged: MiddlewareResponse[] = [];

    pipeline.addRequestMiddleware(createCustomHeaderMiddleware({ authorization: 'Bearer token', 'x-scan-id': '123' }));
    pipeline.addResponseMiddleware((resp) => { logged.push(resp); });

    const req = pipeline.processRequest(makeRequest());
    expect(req.headers.authorization).toBe('Bearer token');
    expect(req.headers['x-scan-id']).toBe('123');

    pipeline.processResponse(makeResponse());
    expect(logged).toHaveLength(1);
  });

  it('combines WAF detector with custom response middleware', () => {
    const pipeline = new MiddlewarePipeline();
    const { middleware: wafMw, detections } = createWafBlockDetector();
    const allStatuses: number[] = [];

    pipeline.addResponseMiddleware(wafMw);
    pipeline.addResponseMiddleware((resp) => { allStatuses.push(resp.status); });

    pipeline.processResponse(makeResponse({ status: 403, body: 'Forbidden by WAF' }));
    // "forbidden" pattern matched
    pipeline.processResponse(makeResponse({ status: 200, body: 'OK' }));

    expect(detections).toHaveLength(1);
    expect(allStatuses).toEqual([403, 200]);
  });
});

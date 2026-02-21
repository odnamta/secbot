import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RequestLogEntry } from '../scanner/types.js';
import { log } from '../utils/logger.js';

const harPkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'));

/**
 * HAR 1.2 types (subset used by SecBot).
 */
interface HarLog {
  log: {
    version: string;
    creator: { name: string; version: string };
    entries: HarEntry[];
  };
}

interface HarEntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    cookies: HarCookie[];
    headers: HarHeader[];
    queryString: HarQueryParam[];
    headersSize: number;
    bodySize: number;
    postData?: { mimeType: string; text: string };
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    cookies: HarCookie[];
    headers: HarHeader[];
    content: { size: number; mimeType: string; text?: string };
    redirectURL: string;
    headersSize: number;
    bodySize: number;
  };
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

interface HarHeader {
  name: string;
  value: string;
}

interface HarCookie {
  name: string;
  value: string;
}

interface HarQueryParam {
  name: string;
  value: string;
}

/**
 * Simple status text mapping for common codes.
 */
function statusText(status: number): string {
  const map: Record<number, string> = {
    200: 'OK',
    201: 'Created',
    204: 'No Content',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
  };
  return map[status] ?? 'Unknown';
}

/**
 * Convert headers Record to HAR header array.
 */
function toHarHeaders(headers?: Record<string, string>): HarHeader[] {
  if (!headers) return [];
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

/**
 * Extract query parameters from a URL.
 */
function toQueryString(url: string): HarQueryParam[] {
  try {
    const parsed = new URL(url);
    const params: HarQueryParam[] = [];
    parsed.searchParams.forEach((value, name) => {
      params.push({ name, value });
    });
    return params;
  } catch {
    return [];
  }
}

/**
 * Compute serialized headers size (rough estimate).
 */
function computeHeadersSize(headers: HarHeader[]): number {
  if (headers.length === 0) return -1;
  return headers.reduce((sum, h) => sum + h.name.length + 2 + h.value.length + 2, 0);
}

/**
 * Convert a RequestLogEntry to a HAR entry.
 */
function toHarEntry(entry: RequestLogEntry): HarEntry {
  const requestHeaders = toHarHeaders(entry.headers);
  const responseHeaders = toHarHeaders(entry.responseHeaders);
  const queryString = toQueryString(entry.url);
  const bodySize = entry.body ? Buffer.byteLength(entry.body, 'utf-8') : 0;

  const contentType = entry.responseHeaders
    ? (entry.responseHeaders['content-type'] ?? entry.responseHeaders['Content-Type'] ?? 'text/plain')
    : 'text/plain';

  const harEntry: HarEntry = {
    startedDateTime: entry.timestamp,
    time: 0,
    request: {
      method: entry.method,
      url: entry.url,
      httpVersion: 'HTTP/1.1',
      cookies: [],
      headers: requestHeaders,
      queryString,
      headersSize: computeHeadersSize(requestHeaders),
      bodySize,
    },
    response: {
      status: entry.responseStatus ?? 0,
      statusText: statusText(entry.responseStatus ?? 0),
      httpVersion: 'HTTP/1.1',
      cookies: [],
      headers: responseHeaders,
      content: {
        size: 0,
        mimeType: contentType,
      },
      redirectURL: '',
      headersSize: computeHeadersSize(responseHeaders),
      bodySize: -1,
    },
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
  };

  if (entry.body) {
    const reqContentType = entry.headers
      ? (entry.headers['content-type'] ?? entry.headers['Content-Type'] ?? 'application/x-www-form-urlencoded')
      : 'application/x-www-form-urlencoded';
    harEntry.request.postData = {
      mimeType: reqContentType,
      text: entry.body,
    };
  }

  return harEntry;
}

/**
 * Build a HAR 1.2 log object from captured request log entries.
 */
export function buildHarLog(entries: RequestLogEntry[]): HarLog {
  return {
    log: {
      version: '1.2',
      creator: {
        name: 'SecBot',
        version: harPkg.version,
      },
      entries: entries.map(toHarEntry),
    },
  };
}

/**
 * Write a HAR 1.2 export file from captured request log entries.
 */
export function writeHarExport(entries: RequestLogEntry[], outputPath: string): void {
  const harLog = buildHarLog(entries);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(harLog, null, 2), 'utf-8');
  log.info(`HAR export written to: ${outputPath}`);
}

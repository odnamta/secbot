import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RequestLogEntry } from '../scanner/types.js';
import { log } from '../utils/logger.js';

/**
 * Escape XML special characters.
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Reconstruct a raw HTTP request string from a RequestLogEntry.
 */
function buildRawRequest(entry: RequestLogEntry): string {
  const url = new URL(entry.url);
  const path = url.pathname + url.search;
  const lines: string[] = [];

  lines.push(`${entry.method} ${path} HTTP/1.1`);
  lines.push(`Host: ${url.host}`);

  if (entry.headers) {
    for (const [key, value] of Object.entries(entry.headers)) {
      if (key.toLowerCase() === 'host') continue; // already added
      lines.push(`${key}: ${value}`);
    }
  }

  lines.push(''); // blank line before body

  if (entry.body) {
    lines.push(entry.body);
  }

  return lines.join('\r\n');
}

/**
 * Reconstruct a raw HTTP response string from a RequestLogEntry.
 */
function buildRawResponse(entry: RequestLogEntry): string {
  const lines: string[] = [];
  const status = entry.responseStatus ?? 0;
  lines.push(`HTTP/1.1 ${status} ${statusText(status)}`);

  if (entry.responseHeaders) {
    for (const [key, value] of Object.entries(entry.responseHeaders)) {
      lines.push(`${key}: ${value}`);
    }
  }

  lines.push(''); // blank line (no body captured in request log)

  return lines.join('\r\n');
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
 * Build a Burp Suite XML export string from captured request log entries.
 */
export function buildBurpXml(entries: RequestLogEntry[]): string {
  const exportTime = new Date().toISOString();
  const lines: string[] = [];

  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<items burpVersion="0.0" exportTime="${escapeXml(exportTime)}">`);

  for (const entry of entries) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(entry.url);
    } catch {
      continue; // skip invalid URLs
    }

    const protocol = parsedUrl.protocol.replace(':', '');
    const host = parsedUrl.hostname;
    const port = parsedUrl.port || (protocol === 'https' ? '443' : '80');
    const path = parsedUrl.pathname + parsedUrl.search;

    const rawRequest = buildRawRequest(entry);
    const rawResponse = buildRawResponse(entry);

    const requestBase64 = Buffer.from(rawRequest, 'utf-8').toString('base64');
    const responseBase64 = Buffer.from(rawResponse, 'utf-8').toString('base64');

    lines.push('  <item>');
    lines.push(`    <time>${escapeXml(entry.timestamp)}</time>`);
    lines.push(`    <url>${escapeXml(entry.url)}</url>`);
    lines.push(`    <host ip="">${escapeXml(host)}</host>`);
    lines.push(`    <port>${escapeXml(String(port))}</port>`);
    lines.push(`    <protocol>${escapeXml(protocol)}</protocol>`);
    lines.push(`    <method>${escapeXml(entry.method)}</method>`);
    lines.push(`    <path>${escapeXml(path)}</path>`);
    lines.push(`    <request base64="true">${requestBase64}</request>`);
    lines.push(`    <status>${entry.responseStatus ?? 0}</status>`);
    lines.push(`    <responselength>${rawResponse.length}</responselength>`);
    lines.push(`    <response base64="true">${responseBase64}</response>`);
    lines.push('  </item>');
  }

  lines.push('</items>');
  return lines.join('\n');
}

/**
 * Write a Burp Suite XML export file from captured request log entries.
 */
export function writeBurpExport(entries: RequestLogEntry[], outputPath: string): void {
  const xml = buildBurpXml(entries);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, xml, 'utf-8');
  log.info(`Burp XML export written to: ${outputPath}`);
}

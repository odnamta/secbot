import type { ScanScope } from '../scanner/types.js';

/**
 * Parse a scope pattern string into a ScanScope object.
 * Format: "*.example.com,api.example.com,-admin.example.com"
 * Prefix with `-` to exclude.
 */
export function parseScopePatterns(input: string): ScanScope {
  const parts = input.split(',').map((s) => s.trim()).filter(Boolean);
  const includePatterns: string[] = [];
  const excludePatterns: string[] = [];

  for (const part of parts) {
    if (part.startsWith('-')) {
      excludePatterns.push(part.slice(1));
    } else {
      includePatterns.push(part);
    }
  }

  return { includePatterns, excludePatterns };
}

/**
 * Check if a URL is within the allowed scope.
 * If no scope is provided, defaults to same-origin matching.
 */
export function isInScope(url: string, targetUrl: string, scope?: ScanScope): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return false;
  }

  // If no scope specified, default to same-origin
  if (!scope || scope.includePatterns.length === 0) {
    try {
      return new URL(url).origin === new URL(targetUrl).origin;
    } catch {
      return false;
    }
  }

  // Check excludes first
  for (const pattern of scope.excludePatterns) {
    if (matchesGlob(hostname, pattern)) {
      return false;
    }
  }

  // Check includes
  for (const pattern of scope.includePatterns) {
    if (matchesGlob(hostname, pattern)) {
      return true;
    }
  }

  return false;
}

/** Simple glob matching for hostnames. Supports `*` as wildcard prefix. */
function matchesGlob(hostname: string, pattern: string): boolean {
  // Exact match
  if (hostname === pattern) return true;

  // Wildcard: *.example.com matches sub.example.com and example.com
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    return hostname === suffix || hostname.endsWith('.' + suffix);
  }

  return false;
}

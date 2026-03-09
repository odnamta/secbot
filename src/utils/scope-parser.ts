/**
 * Bug Bounty Scope Parser
 *
 * Parses HackerOne/Bugcrowd-style program scope from text files or URL lists.
 * Supports domain patterns, URL patterns, out-of-scope markers, and comments.
 */

export interface BountyScope {
  inScope: string[];
  outOfScope: string[];
  programName?: string;
}

/**
 * Parse a bug bounty scope file (HackerOne/Bugcrowd format).
 *
 * Supported formats:
 * - Domain patterns: `*.example.com`, `example.com`, `api.example.com`
 * - URL patterns: `https://example.com/*`, `https://api.example.com/v1/*`
 * - Out-of-scope markers: Lines starting with `-` or lines under "Out of Scope" section
 * - Comments: Lines starting with `#`
 * - Program name: First `# Program:` comment line
 */
export function parseScopeFile(content: string): BountyScope {
  const lines = content.split('\n');
  const inScope: string[] = [];
  const outOfScope: string[] = [];
  let programName: string | undefined;
  let inOutOfScopeSection = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines
    if (!line) continue;

    // Handle comments — extract program name from `# Program: <name>`
    if (line.startsWith('#')) {
      const programMatch = line.match(/^#\s*Program:\s*(.+)/i);
      if (programMatch && !programName) {
        programName = programMatch[1].trim();
      }
      continue;
    }

    // Detect "Out of Scope" section header (case-insensitive)
    if (/^out\s+of\s+scope/i.test(line) || /^out-of-scope/i.test(line)) {
      inOutOfScopeSection = true;
      continue;
    }

    // Detect "In Scope" section header — resets back to in-scope mode
    if (/^in\s+scope/i.test(line) || /^in-scope/i.test(line)) {
      inOutOfScopeSection = false;
      continue;
    }

    // Lines starting with `-` are out-of-scope (regardless of section)
    if (line.startsWith('-')) {
      const pattern = line.slice(1).trim();
      if (pattern) {
        outOfScope.push(pattern);
      }
      continue;
    }

    // Add to appropriate list based on current section
    if (inOutOfScopeSection) {
      outOfScope.push(line);
    } else {
      inScope.push(line);
    }
  }

  return {
    inScope,
    outOfScope,
    ...(programName ? { programName } : {}),
  };
}

/**
 * Convert a BountyScope to SecBot's ScanScope format (includePatterns / excludePatterns).
 *
 * Normalizes URL patterns to domain patterns:
 * - `https://example.com/*` → `example.com`
 * - `https://*.example.com/v1/*` → `*.example.com`
 * - `*.example.com` → `*.example.com` (passthrough)
 * - `example.com` → `example.com` (passthrough)
 */
export function scopeToScanConfig(scope: BountyScope): { includePatterns: string[]; excludePatterns: string[] } {
  const includePatterns = scope.inScope.map(normalizeToHostPattern);
  const excludePatterns = scope.outOfScope.map(normalizeToHostPattern);

  // Deduplicate
  return {
    includePatterns: [...new Set(includePatterns)],
    excludePatterns: [...new Set(excludePatterns)],
  };
}

/**
 * Normalize a scope entry (domain or URL pattern) to a hostname pattern.
 * - `https://example.com/path` → `example.com`
 * - `https://*.example.com/*` → `*.example.com`
 * - `*.example.com` → `*.example.com`
 * - `example.com` → `example.com`
 */
function normalizeToHostPattern(entry: string): string {
  // If it looks like a URL (has protocol), extract hostname
  if (/^https?:\/\//i.test(entry)) {
    try {
      // Handle wildcard in URL by temporarily replacing it
      const sanitized = entry.replace('://*.', '://WILDCARD.');
      const url = new URL(sanitized);
      const hostname = url.hostname.replace('wildcard.', '*.');
      return hostname;
    } catch {
      // If URL parsing fails, return as-is
      return entry;
    }
  }

  // Already a domain pattern — return as-is
  return entry;
}

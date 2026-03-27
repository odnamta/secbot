import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { VulnTemplate } from './engine.js';
import { log } from '../../utils/logger.js';

/**
 * Simple YAML-like parser for Nuclei-format templates.
 * Handles both structured (method: / path:) and raw request blocks.
 *
 * Nuclei template anatomy:
 *   id: <string>
 *   info:
 *     name: <string>
 *     severity: critical|high|medium|low|info
 *     description: <string or multiline>
 *     tags: <comma-separated or YAML array>
 *     reference: [list]
 *     classification:
 *       cwe-id: CWE-xxx
 *   http:
 *     - method: GET|POST|...
 *       path:
 *         - "{{BaseURL}}/some/path"
 *       matchers-condition: and|or
 *       matchers: [...]
 *   OR:
 *     - raw:
 *         - |
 *           GET /path HTTP/1.1
 *           Host: {{Hostname}}
 */
export function parseNucleiTemplate(content: string): VulnTemplate | null {
  try {
    // Skip templates that use code: blocks (Ruby, Python, etc.) — not HTTP-based
    if (/^\s*code:\s*$/m.test(content) || /^\s*- engine:/m.test(content)) return null;

    // Extract fields using regex (simple YAML subset)
    const id = extractField(content, 'id');
    const name = extractField(content, 'name');
    const severity = extractField(content, 'severity') as VulnTemplate['info']['severity'];

    if (!id || !name || !severity) return null;

    // Description: handle multiline (pipe |) or simple scalar
    const description = extractMultilineOrScalar(content, 'description') ?? name;

    // Tags: handle comma-separated string or YAML array format
    const tags = extractTags(content);

    // Extract request method + path from either structured or raw format
    const { method, path, headers: rawHeaders, body: rawBody } = extractRequest(content);
    if (!path) return null;

    // Strip {{BaseURL}} and {{RootURL}} placeholders — our engine prepends baseUrl
    const cleanPath = path
      .replace(/\{\{BaseURL\}\}/gi, '')
      .replace(/\{\{RootURL\}\}/gi, '');

    // Extract headers if present (from structured format)
    const headers = rawHeaders ?? extractHeaders(content);

    // Extract body if present (from structured format)
    const body = rawBody ?? extractField(content, 'body');

    // Extract matchers with full Nuclei support
    const matchers = extractMatchers(content);

    // Extract top-level match condition: matchers-condition or condition
    const conditionRaw = extractField(content, 'matchers-condition')
      ?? extractField(content, 'condition');
    const matchCondition = conditionRaw === 'or' ? 'or' as const : 'and' as const;

    // Extract reference URLs
    const reference = extractListItems(content, 'reference');

    // Extract CWE — Nuclei uses cwe-id under classification:
    const cwe = extractField(content, 'cwe-id') ?? extractField(content, 'cwe');

    // Infer tech match from tags (common Nuclei tag patterns)
    const tech = inferTechFromTags(tags);

    return {
      id,
      info: {
        name,
        severity,
        description,
        tags,
        ...(reference && reference.length > 0 ? { reference } : {}),
        ...(cwe ? { cwe } : {}),
      },
      ...(tech ? { match: { tech } } : {}),
      requests: [{
        method: method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD',
        path: cleanPath || '/',
        ...(headers && Object.keys(headers).length > 0 ? { headers } : {}),
        ...(body ? { body } : {}),
        matchers,
        matchCondition,
      }],
    };
  } catch {
    return null;
  }
}

// ─── Request Extraction ──────────────────────────────────────────

interface ExtractedRequest {
  method: string;
  path: string | undefined;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * Extract request info from either structured (path:) or raw request blocks.
 * Handles:
 *   - path: array with {{BaseURL}}/... entries
 *   - raw: block with HTTP request lines
 *   - payloads: with {{paths}} variable expansion (uses first payload path)
 */
function extractRequest(content: string): ExtractedRequest {
  // Detect if template uses raw: request blocks vs structured path:
  // Important: check for raw: BEFORE path:, because some templates have
  // "path:" under "payloads:" which would be a false match.
  const hasRawBlock = /^\s+- raw:|^\s+raw:/m.test(content);
  const hasStructuredPath = /^\s+path:\s*\n\s+-\s+["']?\{\{BaseURL\}\}|^\s+- method:/m.test(content);

  // If raw block exists and no structured path, try raw first
  if (hasRawBlock && !hasStructuredPath) {
    const rawRequest = extractRawRequest(content);
    if (rawRequest) return rawRequest;
  }

  // Try structured path: array (under http: > - method: block)
  const pathItems = extractListItems(content, 'path');
  if (pathItems && pathItems.length > 0) {
    let firstPath = pathItems[0];

    // Validate this is an HTTP path, not a payloads path
    // HTTP paths typically start with {{BaseURL}}, {{RootURL}}, /, or a URL scheme
    const looksLikeHttpPath = firstPath.includes('{{BaseURL}}') ||
      firstPath.includes('{{RootURL}}') ||
      firstPath.startsWith('/') ||
      firstPath.startsWith('http');

    if (looksLikeHttpPath) {
      // Handle payload variable in path: "{{BaseURL}}{{paths}}" — expand from payloads section
      if (/\{\{[a-zA-Z_]+\}\}/.test(firstPath.replace(/\{\{BaseURL\}\}/gi, ''))) {
        const payloadPath = extractFirstPayloadPath(content);
        if (payloadPath) {
          firstPath = firstPath.replace(/\{\{[a-zA-Z_]+\}\}/g, (match) => {
            if (match.toLowerCase() === '{{baseurl}}') return match;
            return payloadPath;
          });
        }
      }

      const method = extractField(content, 'method') ?? 'GET';
      return { method, path: firstPath };
    }
  }

  // Try scalar path: field (only if it looks like an HTTP path)
  const scalarPath = extractField(content, 'path');
  if (scalarPath && (scalarPath.startsWith('/') || scalarPath.startsWith('http'))) {
    const method = extractField(content, 'method') ?? 'GET';
    return { method, path: scalarPath };
  }

  // Try raw: request block (fallback if not already tried)
  if (!hasRawBlock || hasStructuredPath) {
    const rawRequest = extractRawRequest(content);
    if (rawRequest) return rawRequest;
  }

  return { method: 'GET', path: undefined };
}

/**
 * Extract the first payload path from a payloads: section.
 * Nuclei format:
 *   payloads:
 *     paths:
 *       - "/v2/api-docs"
 *       - "/swagger.json"
 */
function extractFirstPayloadPath(content: string): string | undefined {
  // Find payloads block and extract first list item under any key
  const payloadsMatch = content.match(
    /payloads:\s*\n\s+\w+:\s*\n((?:\s+-\s+.+\n?)+)/m,
  );
  if (!payloadsMatch) return undefined;

  const firstItem = payloadsMatch[1].match(/^\s+-\s+["']?(.+?)["']?\s*$/m);
  return firstItem?.[1];
}

/**
 * Parse raw HTTP request blocks to extract method, path, headers, and body.
 * Nuclei format:
 *   - raw:
 *       - |
 *         POST /path HTTP/1.1
 *         Host: {{Hostname}}
 *         Content-Type: application/x-www-form-urlencoded
 *
 *         body=data
 */
function extractRawRequest(content: string): ExtractedRequest | undefined {
  // Instead of trying to regex-capture the entire raw block (which breaks on multi-line bodies),
  // find the raw: section start, then scan forward for the HTTP request line.
  const rawIdx = content.search(/raw:\s*\n/m);
  if (rawIdx === -1) return undefined;

  // Get everything after "raw:" until the matchers/extractors section
  const afterRaw = content.slice(rawIdx);

  // Find the pipe line: "- |", "- |+", "- | #comment"
  const pipeMatch = afterRaw.match(/^\s+-\s+\|[+-]?[^\n]*/m);
  if (!pipeMatch) return undefined;

  const pipeEnd = afterRaw.indexOf(pipeMatch[0]) + pipeMatch[0].length;
  const blockStart = afterRaw.indexOf('\n', pipeEnd);
  if (blockStart === -1) return undefined;

  // Scan lines after the pipe until we hit a line that's clearly outside the raw block
  const remainingLines = afterRaw.slice(blockStart + 1).split('\n');

  let method: string | undefined;
  let path: string | undefined;
  const headers: Record<string, string> = {};
  const bodyLines: string[] = [];
  let pastRequestLine = false;
  let pastHeaders = false;
  let rawBlockIndent = -1;

  for (const rawLine of remainingLines) {
    const stripped = rawLine.replace(/^\s+/, '');

    // Detect end of raw block: unindented line that starts a new YAML key
    // Raw block content is typically indented 8+ spaces
    if (rawBlockIndent > 0) {
      const currentIndent = rawLine.length - rawLine.trimStart().length;
      // If indent drops significantly and line looks like a YAML key, we're done
      if (currentIndent < rawBlockIndent && /^\s{2,6}\S/.test(rawLine) && /^\s*(matchers|extractors|payloads|unsafe|stop-at-first-match|cookie-reuse|redirects|host-redirects|max-redirects)\b/.test(rawLine)) {
        break;
      }
    }

    // Skip directives and empty lines before the request line
    if (!pastRequestLine) {
      if (stripped === '' || stripped.startsWith('@') || stripped.startsWith('#')) continue;
    }

    // Look for HTTP request line: "GET /path HTTP/1.1" or "POST /path HTTP/1.1"
    if (!pastRequestLine) {
      const reqMatch = stripped.match(/^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+(\S+)/);
      if (reqMatch) {
        method = reqMatch[1];
        path = reqMatch[2];
        pastRequestLine = true;
        rawBlockIndent = rawLine.length - rawLine.trimStart().length;
        continue;
      }
    }

    if (!pastRequestLine) continue;

    // After request line: parse headers until empty line, then body
    if (stripped === '') {
      if (!pastHeaders) {
        pastHeaders = true;
        continue;
      }
      // Second empty line in body section — could be end of raw block
      continue;
    }

    if (!pastHeaders) {
      const headerMatch = stripped.match(/^([\w-]+):\s*(.+)$/);
      if (headerMatch) {
        if (headerMatch[1].toLowerCase() !== 'host') {
          headers[headerMatch[1]] = headerMatch[2].replace(
            /\{\{Hostname\}\}/gi, '',
          ).trim();
        }
      }
    } else {
      bodyLines.push(stripped);
    }
  }

  if (!method || !path) return undefined;

  // Handle payload variable in path
  if (/\{\{\w+\}\}/.test(path) && !/\{\{BaseURL\}\}/i.test(path)) {
    const payloadPath = extractFirstPayloadPath(content);
    if (payloadPath) {
      path = path.replace(/\{\{\w+\}\}/g, payloadPath);
    }
  }

  // Clean up body
  let body: string | undefined;
  if (bodyLines.length > 0) {
    body = bodyLines.join('\n').trim();
    // Skip bodies with interactsh or complex template variables
    if (/\{\{interactsh/.test(body)) body = undefined;
  }

  return {
    method,
    path,
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
    ...(body ? { body } : {}),
  };
}

// ─── Tag Extraction ──────────────────────────────────────────────

/**
 * Extract tags from either comma-separated string or YAML array format.
 * Handles: `tags: api,swagger,discovery` and `tags: [api, swagger]`
 */
function extractTags(content: string): string[] {
  const tagsLine = content.match(/^\s*tags:\s*(.+)$/m);
  if (!tagsLine) return [];

  const raw = tagsLine[1].trim();

  // YAML array format: [tag1, tag2]
  if (raw.startsWith('[') && raw.endsWith(']')) {
    return raw.slice(1, -1).split(',').map(t => t.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
  }

  // Comma-separated string (most common Nuclei format)
  return raw.split(',').map(t => t.trim()).filter(Boolean);
}

// ─── Tech Inference ──────────────────────────────────────────────

/** Map common Nuclei tags to tech stack identifiers for filtering */
const TAG_TO_TECH: Record<string, string> = {
  wordpress: 'wordpress', wp: 'wordpress', 'wp-plugin': 'wordpress',
  joomla: 'joomla', drupal: 'drupal',
  php: 'php', phpmyadmin: 'php',
  java: 'java', spring: 'java', springboot: 'java', tomcat: 'java', struts: 'java',
  apache: 'apache', nginx: 'nginx', iis: 'iis',
  nodejs: 'node', express: 'node', nextjs: 'node',
  python: 'python', django: 'python', flask: 'python',
  ruby: 'ruby', rails: 'ruby',
  dotnet: 'dotnet', aspnet: 'dotnet',
  jenkins: 'jenkins', grafana: 'grafana', gitlab: 'gitlab',
  docker: 'docker', kubernetes: 'kubernetes', k8s: 'kubernetes',
};

function inferTechFromTags(tags: string[]): string[] | undefined {
  const techs = new Set<string>();
  for (const tag of tags) {
    const tech = TAG_TO_TECH[tag.toLowerCase()];
    if (tech) techs.add(tech);
  }
  return techs.size > 0 ? [...techs] : undefined;
}

// ─── Field Extraction ────────────────────────────────────────────

/**
 * Extract a simple scalar field value from YAML content.
 * Matches lines like `  key: value` or `  key: "value"`.
 */
export function extractField(yaml: string, key: string): string | undefined {
  const re = new RegExp(`^\\s*${key}:\\s*(.+)$`, 'm');
  const match = yaml.match(re);
  if (!match) return undefined;
  let val = match[1].trim();
  // Skip YAML block indicators (|, >) — these are multiline markers, not values
  if (val === '|' || val === '>') return undefined;
  val = val.replace(/^["']|["']$/g, '');
  return val || undefined;
}

/**
 * Extract a multiline (pipe |) or scalar field value.
 * Nuclei descriptions often use:
 *   description: |
 *     Multi-line text here.
 *     More text.
 */
function extractMultilineOrScalar(yaml: string, key: string): string | undefined {
  // Try multiline block (| or >) first — check before scalar to avoid
  // matching the pipe character as a scalar value
  const blockMatch = yaml.match(
    new RegExp(`^\\s*${key}:\\s*[|>]\\s*\\n((?:[ \\t]+.+\\n?)+)`, 'm'),
  );
  if (blockMatch) {
    // Join indented lines, trimming leading whitespace
    return blockMatch[1]
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean)
      .join(' ')
      .trim();
  }

  // Try scalar (single line value that is not a block indicator)
  const scalarMatch = yaml.match(new RegExp(`^\\s*${key}:\\s*([^|>\\n].+)$`, 'm'));
  if (scalarMatch) {
    const val = scalarMatch[1].trim().replace(/^["']|["']$/g, '');
    if (val && val !== '|' && val !== '>') return val;
  }

  return undefined;
}

/**
 * Extract list items under a YAML key.
 * Matches patterns like:
 *   reference:
 *     - "https://example.com"
 *     - 'https://other.com'
 *     - https://plain.com
 */
export function extractListItems(yaml: string, key: string): string[] | undefined {
  const re = new RegExp(`^\\s*${key}:\\s*\\n((?:\\s+-\\s+.+\\n?)+)`, 'm');
  const match = yaml.match(re);
  if (!match) return undefined;

  const items = match[1]
    .split('\n')
    .map(line => {
      // Handle double-quoted, single-quoted, or unquoted items
      const itemMatch = line.match(/^\s+-\s+["']?(.+?)["']?\s*$/);
      if (!itemMatch) return undefined;
      let val = itemMatch[1];
      // Strip trailing inline comments (e.g., # some comment)
      val = val.replace(/\s+#\s+.*$/, '');
      return val;
    })
    .filter((item): item is string => !!item);

  return items.length > 0 ? items : undefined;
}

/**
 * Extract header key-value pairs from a YAML headers block.
 */
function extractHeaders(yaml: string): Record<string, string> | undefined {
  const headersBlock = yaml.match(/^\s*headers:\s*\n((?:\s+[\w-]+:\s*.+\n?)+)/m);
  if (!headersBlock) return undefined;

  const headers: Record<string, string> = {};
  const lines = headersBlock[1].split('\n');
  for (const line of lines) {
    const kv = line.match(/^\s+([\w-]+):\s*(.+)$/);
    if (kv) {
      headers[kv[1].trim()] = kv[2].trim().replace(/^["']|["']$/g, '');
    }
  }

  return Object.keys(headers).length > 0 ? headers : undefined;
}

// ─── Matcher Extraction ──────────────────────────────────────────

/**
 * Extract matchers from a YAML template.
 * Supports Nuclei matcher format:
 *   - type: status + status: [200] or status: list
 *   - type: word + words: list + part: body|header + condition: and|or + negative: true
 *   - type: regex + regex: list + part: body|header
 *   - type: dsl (skipped — too complex for simple parser)
 *
 * Splits the matchers section into individual matcher blocks, then parses each.
 */
export function extractMatchers(yaml: string): VulnTemplate['requests'][0]['matchers'] {
  const matchers: VulnTemplate['requests'][0]['matchers'] = [];

  // Find the matchers: section — capture everything from "matchers:" until
  // we hit extractors:, # digest:, or end of string.
  // Use two-step approach: try with terminators first, then fall back to greedy.
  const matchersSection =
    yaml.match(/\bmatchers:\s*\n([\s\S]*?)(?=\n\s{4}extractors:|\n# digest:)/m)
    ?? yaml.match(/\bmatchers:\s*\n([\s\S]+)/m);

  if (!matchersSection) {
    // Fallback: try old-style inline parsing
    return extractMatchersFallback(yaml);
  }

  const section = matchersSection[1];

  // Only proceed with block parsing if we have "- type:" entries
  if (!/\s+-\s+type:/m.test(section)) {
    return extractMatchersFallback(yaml);
  }

  // Split into individual matcher blocks by "- type:"
  const matcherBlocks = section.split(/(?=\s+-\s+type:)/g).filter(b => b.trim());

  for (const block of matcherBlocks) {
    const typeMatch = block.match(/type:\s*(\w+)/);
    if (!typeMatch) continue;

    const type = typeMatch[1].toLowerCase();
    const negative = /negative:\s*true/i.test(block);
    const part = block.match(/part:\s*(\w+)/)?.[1]?.toLowerCase();
    const condition = block.match(/condition:\s*(\w+)/)?.[1]?.toLowerCase();

    if (type === 'status') {
      const statuses = extractStatusCodes(block);
      if (statuses.length > 0) {
        matchers.push({ type: 'status', status: statuses, ...(negative ? { negative: true } : {}) });
      }
    } else if (type === 'word') {
      const words = extractWordList(block);
      if (words.length > 0) {
        if (part === 'header') {
          // Header word matcher — convert to header type for engine compatibility
          // In Nuclei, "part: header" with words means check the full header string
          matchers.push({
            type: 'header',
            header: '_raw',
            value: words[0], // Use first word for header matching
            words, // Preserve all words for the engine
            ...(negative ? { negative: true } : {}),
          });
        } else {
          // Default: body word matcher
          matchers.push({
            type: 'body',
            words,
            ...(negative ? { negative: true } : {}),
          });
        }
      }
    } else if (type === 'regex') {
      const patterns = extractRegexPatterns(block);
      for (const pattern of patterns) {
        if (part === 'header') {
          matchers.push({
            type: 'header',
            header: '_regex',
            value: pattern,
            regex: pattern,
            ...(negative ? { negative: true } : {}),
          });
        } else {
          matchers.push({
            type: 'regex',
            regex: pattern,
            ...(negative ? { negative: true } : {}),
          });
        }
      }
    }
    // Skip type: dsl — requires expression evaluation we don't support
  }

  // Fallback: if no matchers found, default to status 200
  return matchers.length > 0 ? matchers : [{ type: 'status', status: [200] }];
}

/**
 * Extract status codes from either inline array [200, 301] or YAML list format.
 */
function extractStatusCodes(block: string): number[] {
  // Inline array: status: [200, 301]
  const inlineMatch = block.match(/status:\s*\[([^\]]+)\]/);
  if (inlineMatch) {
    return inlineMatch[1].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
  }

  // YAML list format:
  //   status:
  //     - 200
  //     - 301
  // NOTE: Use [ \t]* instead of \s+ for leading whitespace — \s includes \n which
  // causes the regex to consume newlines between list items, breaking the repetition.
  const listMatch = block.match(/status:\s*\n((?:[ \t]*-\s+\d+[ \t]*\n?)+)/);
  if (listMatch) {
    return listMatch[1]
      .split('\n')
      .map(line => {
        const m = line.match(/^\s+-\s+(\d+)/);
        return m ? parseInt(m[1], 10) : NaN;
      })
      .filter(n => !isNaN(n));
  }

  return [];
}

/**
 * Extract word list from a matcher block.
 * Handles double-quoted, single-quoted, and unquoted words.
 */
function extractWordList(block: string): string[] {
  const wordsSection = block.match(/words:\s*\n((?:\s+-\s+.+\n?)+)/);
  if (!wordsSection) return [];

  return wordsSection[1]
    .split('\n')
    .map(line => {
      // Double-quoted
      const dq = line.match(/^\s+-\s+"([^"]+)"/);
      if (dq) return dq[1];
      // Single-quoted
      const sq = line.match(/^\s+-\s+'([^']+)'/);
      if (sq) return sq[1];
      // Unquoted (trim trailing whitespace/comments)
      const uq = line.match(/^\s+-\s+([^\s#"'][^\n#]*)/);
      if (uq) return uq[1].trim();
      return undefined;
    })
    .filter((w): w is string => !!w);
}

/**
 * Extract regex patterns from a matcher block.
 * Handles quoted and unquoted patterns.
 */
function extractRegexPatterns(block: string): string[] {
  const regexSection = block.match(/regex:\s*\n((?:\s+-\s+.+\n?)+)/);
  if (!regexSection) return [];

  return regexSection[1]
    .split('\n')
    .map(line => {
      // Double-quoted
      const dq = line.match(/^\s+-\s+"(.+)"/);
      if (dq) return dq[1];
      // Single-quoted
      const sq = line.match(/^\s+-\s+'(.+)'/);
      if (sq) return sq[1];
      // Unquoted
      const uq = line.match(/^\s+-\s+(.+)/);
      if (uq) return uq[1].trim();
      return undefined;
    })
    .filter((p): p is string => !!p);
}

/**
 * Fallback matcher extraction (legacy path — handles basic inline patterns).
 */
function extractMatchersFallback(yaml: string): VulnTemplate['requests'][0]['matchers'] {
  const matchers: VulnTemplate['requests'][0]['matchers'] = [];

  // Status matcher: status: [200, 301] or status: list
  const statusInline = yaml.match(/status:\s*\[([^\]]+)\]/);
  if (statusInline) {
    const statuses = statusInline[1].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    if (statuses.length > 0) matchers.push({ type: 'status', status: statuses });
  }
  const statusList = yaml.match(/status:\s*\n((?:[ \t]*-\s+\d+[ \t]*\n?)+)/);
  if (!statusInline && statusList) {
    const statuses = statusList[1].split('\n')
      .map(l => { const m = l.match(/^\s+-\s+(\d+)/); return m ? parseInt(m[1], 10) : NaN; })
      .filter(n => !isNaN(n));
    if (statuses.length > 0) matchers.push({ type: 'status', status: statuses });
  }

  // Word matchers
  const wordBlocks = yaml.matchAll(/words:\s*\n((?:\s+-\s+.+\n?)+)/g);
  for (const block of wordBlocks) {
    const words = block[1].split('\n')
      .map(line => {
        const dq = line.match(/^\s+-\s+"([^"]+)"/);
        if (dq) return dq[1];
        const sq = line.match(/^\s+-\s+'([^']+)'/);
        if (sq) return sq[1];
        return undefined;
      })
      .filter((w): w is string => !!w);
    if (words.length > 0) matchers.push({ type: 'body', words });
  }

  // Regex matchers
  const regexBlocks = yaml.matchAll(/regex:\s*\n((?:\s+-\s+.+\n?)+)/g);
  for (const block of regexBlocks) {
    const patterns = block[1].split('\n')
      .map(line => {
        const m = line.match(/^\s+-\s+["'](.+)["']/);
        return m?.[1];
      })
      .filter((p): p is string => !!p);
    for (const pattern of patterns) matchers.push({ type: 'regex', regex: pattern });
  }

  return matchers.length > 0 ? matchers : [{ type: 'status', status: [200] }];
}

// ─── Template Loading ────────────────────────────────────────────

/**
 * Load all YAML templates from a directory (non-recursive — single level only).
 * Skips invalid files silently.
 */
export function loadTemplatesFromDir(dir: string): VulnTemplate[] {
  if (!existsSync(dir)) return [];

  const templates: VulnTemplate[] = [];

  let files: string[];
  try {
    files = readdirSync(dir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    return [];
  }

  for (const file of files) {
    try {
      const content = readFileSync(join(dir, file), 'utf-8');
      const template = parseNucleiTemplate(content);
      if (template) templates.push(template);
    } catch { /* skip invalid */ }
  }

  if (templates.length > 0) {
    log.info(`Loaded ${templates.length} templates from ${dir}`);
  }
  return templates;
}

/**
 * Recursively load all YAML templates from a directory tree.
 * Walks subdirectories and collects all .yaml/.yml files.
 */
export function loadTemplatesFromDirRecursive(dir: string): VulnTemplate[] {
  if (!existsSync(dir)) return [];

  const templates: VulnTemplate[] = [];

  function walk(currentDir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(currentDir);
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
          const content = readFileSync(fullPath, 'utf-8');
          const template = parseNucleiTemplate(content);
          if (template) templates.push(template);
        }
      } catch { /* skip entries we can't read */ }
    }
  }

  walk(dir);

  if (templates.length > 0) {
    log.info(`Loaded ${templates.length} templates (recursive) from ${dir}`);
  }
  return templates;
}

/**
 * Load templates from specific Nuclei subdirectories, filtered by detected tech.
 * This avoids loading all 7,274 templates at startup.
 *
 * Strategy:
 *   - exposures/ and misconfiguration/ are always loaded (universal checks)
 *   - technologies/ is always loaded (detection templates)
 *   - cves/ and vulnerabilities/ are only loaded if tech is detected, then filtered by tags
 *   - If no tech detected, skip cves/ and vulnerabilities/ entirely
 */
export function loadTemplatesFiltered(
  nucleiDir: string,
  detectedTech?: string[],
): VulnTemplate[] {
  if (!existsSync(nucleiDir)) return [];

  const templates: VulnTemplate[] = [];

  // Always load universal directories
  const universalDirs = ['exposures', 'misconfiguration', 'technologies'];
  for (const sub of universalDirs) {
    const subDir = join(nucleiDir, sub);
    if (existsSync(subDir)) {
      const loaded = loadTemplatesFromDirRecursive(subDir);
      templates.push(...loaded);
    }
  }

  // Only load CVE/vulnerability templates if we have tech to filter by
  if (detectedTech && detectedTech.length > 0) {
    const normalizedTech = new Set(detectedTech.map(t => t.toLowerCase()));

    // Build expanded tech set including reverse-mapped names
    // e.g., if 'wordpress' detected, also match 'wp', 'wp-plugin'
    const expandedTech = new Set(normalizedTech);
    const TECH_ALIASES: Record<string, string[]> = {
      wordpress: ['wp', 'wp-plugin', 'wp-theme', 'wpscan'],
      php: ['phpmyadmin', 'laravel', 'symfony', 'codeigniter'],
      java: ['spring', 'springboot', 'tomcat', 'struts', 'weblogic', 'jboss'],
      apache: ['httpd', 'apache-httpd'],
      nginx: ['nginx-proxy'],
      node: ['nodejs', 'express', 'nextjs'],
      python: ['django', 'flask', 'fastapi'],
      ruby: ['rails', 'rack'],
      dotnet: ['aspnet', 'iis'],
    };
    for (const tech of normalizedTech) {
      const aliases = TECH_ALIASES[tech];
      if (aliases) for (const alias of aliases) expandedTech.add(alias);
    }

    const techDirs = ['cves', 'vulnerabilities'];

    for (const sub of techDirs) {
      const subDir = join(nucleiDir, sub);
      if (!existsSync(subDir)) continue;

      // Load all, then filter: only include templates that have at least one
      // tag matching the detected tech stack (direct match or alias)
      const allInDir = loadTemplatesFromDirRecursive(subDir);
      const relevant = allInDir.filter(t => {
        const templateTags = t.info.tags.map(tag => tag.toLowerCase());
        return templateTags.some(tag => expandedTech.has(tag));
      });
      templates.push(...relevant);
    }
  }

  log.info(`Filtered template load: ${templates.length} templates from ${nucleiDir} (tech: ${detectedTech?.join(', ') ?? 'none'})`);
  return templates;
}

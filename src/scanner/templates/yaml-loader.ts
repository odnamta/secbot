import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { VulnTemplate } from './engine.js';
import { log } from '../../utils/logger.js';

/**
 * Simple YAML-like parser for Nuclei-format templates.
 * Doesn't need a full YAML library — Nuclei templates use a simple subset.
 */
export function parseNucleiTemplate(content: string): VulnTemplate | null {
  try {
    // Extract fields using regex (simple YAML subset)
    const id = extractField(content, 'id');
    const name = extractField(content, 'name');
    const severity = extractField(content, 'severity') as VulnTemplate['info']['severity'];
    const description = extractField(content, 'description') ?? name ?? '';
    const tags = extractField(content, 'tags')?.split(',').map(t => t.trim()) ?? [];

    if (!id || !name || !severity) return null;

    // Extract request method + path
    const method = extractField(content, 'method') ?? 'GET';
    const path = extractListItems(content, 'path')?.[0] ?? extractField(content, 'path');
    if (!path) return null;

    // Extract headers if present
    const headers = extractHeaders(content);

    // Extract body if present
    const body = extractField(content, 'body');

    // Extract matchers
    const matchers = extractMatchers(content);

    // Extract match condition
    const conditionRaw = extractField(content, 'condition');
    const matchCondition = conditionRaw === 'or' ? 'or' as const : 'and' as const;

    // Extract reference URLs
    const reference = extractListItems(content, 'reference');

    // Extract CWE
    const cwe = extractField(content, 'cwe');

    // Extract tech match tags
    const techField = extractField(content, 'tech');
    const tech = techField ? techField.split(',').map(t => t.trim()) : undefined;

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
        path,
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

/**
 * Extract a simple scalar field value from YAML content.
 * Matches lines like `  key: value` or `  key: "value"`.
 */
export function extractField(yaml: string, key: string): string | undefined {
  const re = new RegExp(`^\\s*${key}:\\s*(.+)$`, 'm');
  const match = yaml.match(re);
  if (!match) return undefined;
  return match[1].trim().replace(/^["']|["']$/g, '');
}

/**
 * Extract list items under a YAML key.
 * Matches patterns like:
 *   reference:
 *     - "https://example.com"
 *     - "https://other.com"
 */
function extractListItems(yaml: string, key: string): string[] | undefined {
  const re = new RegExp(`^\\s*${key}:\\s*\\n((?:\\s+-\\s+.+\\n?)+)`, 'm');
  const match = yaml.match(re);
  if (!match) return undefined;

  const items = match[1]
    .split('\n')
    .map(line => {
      const itemMatch = line.match(/^\s+-\s+["']?(.+?)["']?\s*$/);
      return itemMatch?.[1];
    })
    .filter((item): item is string => !!item);

  return items.length > 0 ? items : undefined;
}

/**
 * Extract header key-value pairs from a YAML headers block.
 */
function extractHeaders(yaml: string): Record<string, string> | undefined {
  const headersBlock = yaml.match(/^\s*headers:\s*\n((?:\s+\w[\w-]*:\s*.+\n?)+)/m);
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

/**
 * Extract matchers from a YAML template.
 * Supports status (array), word (list), header, and regex matchers.
 */
export function extractMatchers(yaml: string): VulnTemplate['requests'][0]['matchers'] {
  const matchers: VulnTemplate['requests'][0]['matchers'] = [];

  // Status matcher: status: [200, 301]
  const statusMatch = yaml.match(/status:\s*\[([^\]]+)\]/);
  if (statusMatch) {
    const statuses = statusMatch[1].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    if (statuses.length > 0) {
      matchers.push({ type: 'status', status: statuses });
    }
  }

  // Word matcher: words: block with list items
  const wordBlocks = yaml.matchAll(/words:\s*\n((?:\s+-\s+.+\n?)+)/g);
  for (const block of wordBlocks) {
    const words = block[1]
      .split('\n')
      .map(line => {
        const m = line.match(/^\s+-\s+"([^"]+)"/);
        return m?.[1];
      })
      .filter((w): w is string => !!w);
    if (words.length > 0) {
      matchers.push({ type: 'body', words });
    }
  }

  // Regex matcher: regex: block with list items
  const regexBlocks = yaml.matchAll(/regex:\s*\n((?:\s+-\s+.+\n?)+)/g);
  for (const block of regexBlocks) {
    const patterns = block[1]
      .split('\n')
      .map(line => {
        const m = line.match(/^\s+-\s+"([^"]+)"/);
        return m?.[1];
      })
      .filter((p): p is string => !!p);
    for (const pattern of patterns) {
      matchers.push({ type: 'regex', regex: pattern });
    }
  }

  // Fallback: if no matchers found, default to status 200
  return matchers.length > 0 ? matchers : [{ type: 'status', status: [200] }];
}

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

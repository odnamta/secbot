import type { WafDetection } from '../scanner/types.js';

export type EncodingStrategy = 'none' | 'url' | 'double-url' | 'html-entity' | 'unicode' | 'mixed';

/**
 * Mutate a payload using various encoding strategies to bypass WAFs.
 * Returns the original + encoded variants.
 */
export function mutatePayload(payload: string, strategies: EncodingStrategy[]): string[] {
  const results = new Set<string>();
  results.add(payload); // always include original

  for (const strategy of strategies) {
    const mutated = applyEncoding(payload, strategy);
    if (mutated !== payload) {
      results.add(mutated);
    }
  }

  return [...results];
}

/**
 * Pick encoding strategies based on WAF detection results.
 * No WAF = just original. WAF detected = add encoding variants.
 */
export function pickStrategies(waf: WafDetection | undefined): EncodingStrategy[] {
  if (!waf?.detected) return ['none'];

  const strategies: EncodingStrategy[] = ['none', 'url', 'double-url'];

  switch (waf.name?.toLowerCase()) {
    case 'cloudflare':
      // Cloudflare is aggressive on common patterns — use unicode + mixed
      strategies.push('unicode', 'mixed');
      break;
    case 'aws waf':
    case 'unknown waf':
      // Generic WAFs — try all encodings
      strategies.push('html-entity', 'unicode', 'mixed');
      break;
    case 'akamai':
    case 'imperva':
      // Enterprise WAFs — double-encode often works
      strategies.push('double-url', 'html-entity');
      break;
    default:
      strategies.push('html-entity', 'unicode');
  }

  return [...new Set(strategies)];
}

function applyEncoding(payload: string, strategy: EncodingStrategy): string {
  switch (strategy) {
    case 'none':
      return payload;

    case 'url':
      return urlEncode(payload);

    case 'double-url':
      return urlEncode(urlEncode(payload));

    case 'html-entity':
      return htmlEntityEncode(payload);

    case 'unicode':
      return unicodeEncode(payload);

    case 'mixed':
      return mixedEncode(payload);

    default:
      return payload;
  }
}

/** URL-encode special characters that WAFs look for */
function urlEncode(input: string): string {
  return input.replace(/[<>"'&;()=\s/\\]/g, (ch) =>
    `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`
  );
}

/** HTML entity encode angle brackets and quotes */
function htmlEntityEncode(input: string): string {
  // Encode & first to avoid re-encoding entities
  return input
    .replace(/&/g, '&#38;')
    .replace(/</g, '&#60;')
    .replace(/>/g, '&#62;')
    .replace(/"/g, '&#34;')
    .replace(/'/g, '&#39;');
}

/** Unicode escape sequences for key characters */
function unicodeEncode(input: string): string {
  return input
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/"/g, '\\u0022')
    .replace(/'/g, '\\u0027')
    .replace(/\(/g, '\\u0028')
    .replace(/\)/g, '\\u0029');
}

/** Mixed encoding — alternates between URL and HTML entity */
function mixedEncode(input: string): string {
  let result = '';
  let useUrl = true;
  for (const ch of input) {
    if ('<>"\'&;()=/\\'.includes(ch)) {
      if (useUrl) {
        result += `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`;
      } else {
        result += `&#${ch.charCodeAt(0)};`;
      }
      useUrl = !useUrl;
    } else {
      result += ch;
    }
  }
  return result;
}

// Insert SQL comments to break up keywords that WAFs pattern-match.
// e.g., "UNION SELECT" → "UN[comment]ION SEL[comment]ECT"
export function sqlCommentObfuscate(payload: string): string {
  const keywords = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'SLEEP', 'WAITFOR', 'BENCHMARK'];
  let result = payload;
  for (const kw of keywords) {
    const re = new RegExp(kw, 'gi');
    result = result.replace(re, (match) => {
      if (match.length <= 3) return match;
      const mid = Math.floor(match.length / 2);
      return match.slice(0, mid) + '/**/' + match.slice(mid);
    });
  }
  return result;
}

/**
 * Case randomize a payload to bypass case-sensitive WAF rules.
 * e.g., "<script>" → "<ScRiPt>"
 */
export function caseRandomize(payload: string): string {
  let result = '';
  let insideTag = false;
  for (let i = 0; i < payload.length; i++) {
    const ch = payload[i];
    if (ch === '<') insideTag = true;
    if (ch === '>') insideTag = false;

    if (insideTag && /[a-zA-Z]/.test(ch)) {
      result += i % 2 === 0 ? ch.toUpperCase() : ch.toLowerCase();
    } else {
      result += ch;
    }
  }
  return result;
}

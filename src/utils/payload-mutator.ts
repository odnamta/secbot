import type { WafDetection } from '../scanner/types.js';

export type EncodingStrategy = 'none' | 'url' | 'double-url' | 'html-entity' | 'unicode' | 'mixed' | 'from-char-code' | 'json-unicode';

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
      // Cloudflare is aggressive on common patterns — use unicode + mixed + fromCharCode
      strategies.push('unicode', 'mixed', 'from-char-code');
      break;
    case 'aws waf':
    case 'unknown waf':
      // Generic WAFs — try all encodings including JSON unicode
      strategies.push('html-entity', 'unicode', 'mixed', 'json-unicode');
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

    case 'from-char-code':
      return fromCharCodeEncode(payload);

    case 'json-unicode':
      return jsonUnicodeEncode(payload);

    default:
      return payload;
  }
}

/** Convert to String.fromCharCode() — bypasses string-matching WAFs */
export function fromCharCodeEncode(input: string): string {
  const codes = [...input].map((ch) => ch.charCodeAt(0));
  return `String.fromCharCode(${codes.join(',')})`;
}

/** JSON Unicode escape — bypasses WAFs that don't decode JSON unicode */
export function jsonUnicodeEncode(input: string): string {
  return input
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/"/g, '\\u0022')
    .replace(/'/g, '\\u0027')
    .replace(/&/g, '\\u0026')
    .replace(/\//g, '\\u002f');
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

// ─── Adaptive Encoder (v1.0) ────────────────────────────────────────

/**
 * Adaptive encoding strategy that automatically switches encoding
 * when the current one gets blocked (403/406).
 * Cycles through all strategies, skipping blocked ones.
 */
export class AdaptiveEncoder {
  private strategies: EncodingStrategy[];
  private index = 0;
  private blocked = new Set<EncodingStrategy>();

  constructor(initial?: EncodingStrategy[]) {
    this.strategies = initial ?? ['none', 'url', 'double-url', 'html-entity', 'unicode', 'mixed', 'from-char-code', 'json-unicode'];
  }

  /** Current encoding strategy. */
  currentStrategy(): EncodingStrategy {
    return this.strategies[this.index];
  }

  /** Record that the current strategy was blocked — advance to next unblocked. */
  recordBlock(): void {
    this.blocked.add(this.strategies[this.index]);
    this.advance();
  }

  /** Record that the current strategy succeeded — stay on it. */
  recordSuccess(): void {
    // Keep current strategy
  }

  /** Whether all strategies have been blocked. */
  allBlocked(): boolean {
    return this.blocked.size >= this.strategies.length;
  }

  /** Encode a payload with the current strategy. */
  encode(payload: string): string {
    return applyEncoding(payload, this.strategies[this.index]);
  }

  /** Number of strategies still available. */
  remaining(): number {
    return this.strategies.length - this.blocked.size;
  }

  private advance(): void {
    const start = this.index;
    do {
      this.index = (this.index + 1) % this.strategies.length;
      if (!this.blocked.has(this.strategies[this.index])) return;
    } while (this.index !== start);
    // All blocked — stays at current
  }
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

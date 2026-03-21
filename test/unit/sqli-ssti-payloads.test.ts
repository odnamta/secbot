import { describe, it, expect } from 'vitest';
import {
  SQLI_TIME_PAYLOADS,
  SQLI_PAYLOADS,
  SQLI_BOOLEAN_PAYLOADS,
  SQL_ERROR_PATTERNS,
  SQLI_STACKED_PAYLOADS,
  NOSQL_PAYLOADS,
  NOSQL_TIMING_PAYLOADS,
  NOSQL_JSON_PAYLOADS,
} from '../../src/config/payloads/sqli.js';
import { SSTI_PAYLOADS, SSTI_CONTROL_PAYLOADS, SSTI_RCE_PROBES } from '../../src/config/payloads/ssti.js';
import { TRAVERSAL_PAYLOADS, TRAVERSAL_SUCCESS_PATTERNS } from '../../src/config/payloads/traversal.js';
import { CMDI_PAYLOADS_TIMING, CMDI_PAYLOADS_OUTPUT } from '../../src/config/payloads/cmdi.js';
import { prioritizeTimedPayloads } from '../../src/scanner/active/sqli.js';
import { prioritizeSstiPayloads } from '../../src/scanner/active/ssti.js';

describe('SQLi Time Payloads', () => {
  it('has conditional timing payloads for MySQL', () => {
    const mysql = SQLI_TIME_PAYLOADS.filter((p) => p.dbType === 'mysql');
    const conditional = mysql.filter((p) => p.payload.includes('IF('));
    expect(conditional.length).toBeGreaterThanOrEqual(3);
    // Verify the conditional pattern: IF(condition, SLEEP, 0)
    for (const p of conditional) {
      expect(p.payload).toMatch(/IF\(1=1,\s*SLEEP\(5\),\s*0\)/);
    }
  });

  it('has conditional timing payloads for MSSQL', () => {
    const mssql = SQLI_TIME_PAYLOADS.filter((p) => p.dbType === 'mssql');
    const conditional = mssql.filter((p) => p.payload.includes('IF(1=1)'));
    expect(conditional.length).toBeGreaterThanOrEqual(2);
    for (const p of conditional) {
      expect(p.payload).toContain('WAITFOR DELAY');
    }
  });

  it('has conditional timing payloads for PostgreSQL', () => {
    const pg = SQLI_TIME_PAYLOADS.filter((p) => p.dbType === 'postgres');
    const conditional = pg.filter((p) => p.payload.includes('CASE WHEN'));
    expect(conditional.length).toBeGreaterThanOrEqual(2);
    for (const p of conditional) {
      expect(p.payload).toContain('pg_sleep(5)');
      expect(p.payload).toContain('pg_sleep(0)');
    }
  });

  it('has MySQL inline-comment WAF bypass payload', () => {
    const bypass = SQLI_TIME_PAYLOADS.filter((p) => p.payload.includes('/*!'));
    expect(bypass.length).toBeGreaterThanOrEqual(1);
    expect(bypass[0].dbType).toBe('mysql');
  });

  it('covers all 5 database types', () => {
    const dbTypes = new Set(SQLI_TIME_PAYLOADS.map((p) => p.dbType));
    expect(dbTypes).toContain('mysql');
    expect(dbTypes).toContain('mssql');
    expect(dbTypes).toContain('postgres');
    expect(dbTypes).toContain('sqlite');
    expect(dbTypes).toContain('oracle');
  });

  it('has Oracle time-based payloads using DBMS_PIPE', () => {
    const oracle = SQLI_TIME_PAYLOADS.filter((p) => p.dbType === 'oracle');
    expect(oracle.length).toBeGreaterThanOrEqual(2);
    expect(oracle[0].payload).toContain('DBMS_PIPE');
  });

  it('every payload is a non-empty string', () => {
    for (const p of SQLI_TIME_PAYLOADS) {
      expect(p.payload.length).toBeGreaterThan(0);
      expect(typeof p.payload).toBe('string');
    }
  });
});

describe('prioritizeTimedPayloads', () => {
  it('puts MySQL payloads first when MySQL detected', () => {
    const ordered = prioritizeTimedPayloads(['mysql']);
    const firstMysql = ordered.findIndex((p) => p.dbType === 'mysql');
    const firstNonMysql = ordered.findIndex((p) => p.dbType !== 'mysql');
    expect(firstMysql).toBeLessThan(firstNonMysql);
  });

  it('puts PostgreSQL payloads first when postgres detected', () => {
    const ordered = prioritizeTimedPayloads(['postgres']);
    const firstPg = ordered.findIndex((p) => p.dbType === 'postgres');
    const firstNonPg = ordered.findIndex((p) => p.dbType !== 'postgres');
    expect(firstPg).toBeLessThan(firstNonPg);
  });

  it('returns all payloads when unknown', () => {
    const ordered = prioritizeTimedPayloads(['unknown']);
    expect(ordered.length).toBe(SQLI_TIME_PAYLOADS.length);
  });
});

describe('SQLi Boolean Payloads', () => {
  it('has CASE WHEN subquery variants', () => {
    const caseWhen = SQLI_BOOLEAN_PAYLOADS.filter((p) => p.truePayload.includes('CASE WHEN'));
    expect(caseWhen.length).toBeGreaterThanOrEqual(2);
    // True condition uses 1=1, false uses 1=2
    for (const p of caseWhen) {
      expect(p.truePayload).toContain('1=1');
      expect(p.falsePayload).toContain('1=2');
    }
  });

  it('all pairs have different true/false payloads', () => {
    for (const p of SQLI_BOOLEAN_PAYLOADS) {
      expect(p.truePayload).not.toBe(p.falsePayload);
    }
  });
});

describe('NoSQL Payloads', () => {
  it('has $where JavaScript injection payloads', () => {
    const wherePayloads = NOSQL_PAYLOADS.filter((p) => p.includes('return true') || p.includes('$where'));
    expect(wherePayloads.length).toBeGreaterThanOrEqual(3);
  });

  it('has operator injection payloads', () => {
    const operators = NOSQL_PAYLOADS.filter((p) => p.includes('$ne') || p.includes('$gt') || p.includes('$or'));
    expect(operators.length).toBeGreaterThanOrEqual(4);
  });

  it('has $exists probe', () => {
    expect(NOSQL_PAYLOADS.some((p) => p.includes('$exists'))).toBe(true);
  });

  it('has timing payloads for $where sleep', () => {
    expect(NOSQL_TIMING_PAYLOADS.length).toBeGreaterThanOrEqual(3);
    for (const p of NOSQL_TIMING_PAYLOADS) {
      expect(p.payload).toContain('sleep');
      expect(p.delay).toBe(5);
    }
  });

  it('timing payloads include JSON $where variant', () => {
    expect(NOSQL_TIMING_PAYLOADS.some((p) => p.payload.includes('$where'))).toBe(true);
  });
});

describe('SSTI Payloads', () => {
  it('has Thymeleaf payloads', () => {
    const thymeleaf = SSTI_PAYLOADS.filter((p) => p.engine.toLowerCase().includes('thymeleaf'));
    expect(thymeleaf.length).toBeGreaterThanOrEqual(2);
    // Standard expression
    expect(thymeleaf.some((p) => p.payload.includes('[[${'))).toBe(true);
    // Preprocessing expression
    expect(thymeleaf.some((p) => p.payload.includes('__${'))).toBe(true);
  });

  it('has Smarty payload', () => {
    const smarty = SSTI_PAYLOADS.filter((p) => p.engine.toLowerCase().includes('smarty'));
    expect(smarty.length).toBeGreaterThanOrEqual(1);
    // Smarty uses {expression} without double braces
    expect(smarty[0].payload).toMatch(/^\{[^{]/);
  });

  it('has Handlebars payload', () => {
    const hbs = SSTI_PAYLOADS.filter((p) => p.engine.toLowerCase().includes('handlebars'));
    expect(hbs.length).toBeGreaterThanOrEqual(1);
  });

  it('all payloads have non-empty expected values', () => {
    for (const p of SSTI_PAYLOADS) {
      expect(p.expected.length).toBeGreaterThan(0);
      expect(p.engine.length).toBeGreaterThan(0);
      expect(p.payload.length).toBeGreaterThan(0);
    }
  });

  it('has control payloads for Thymeleaf and Smarty', () => {
    const controlEngines = SSTI_CONTROL_PAYLOADS.map((p) => p.engine.toLowerCase());
    expect(controlEngines.some((e) => e.includes('thymeleaf'))).toBe(true);
    expect(controlEngines.some((e) => e.includes('smarty'))).toBe(true);
  });

  it('control payloads use addition (not multiplication) for distinct results', () => {
    for (const p of SSTI_CONTROL_PAYLOADS) {
      // Control payloads should produce 143658 (71829+71829), not 5159405241
      expect(p.expected).toBe('143658');
    }
  });
});

describe('SSTI RCE Probes', () => {
  it('has RCE probes for major engines', () => {
    const engines = new Set(SSTI_RCE_PROBES.map((p) => p.engine));
    expect(engines.has('Jinja2/Twig')).toBe(true);
    expect(engines.has('ERB/EJS')).toBe(true);
    expect(engines.has('Thymeleaf')).toBe(true);
    expect(engines.has('Smarty')).toBe(true);
  });

  it('all RCE probes expect secbot-rce-confirmed marker', () => {
    for (const probe of SSTI_RCE_PROBES) {
      expect(probe.expected).toBe('secbot-rce-confirmed');
    }
  });

  it('RCE probes use non-destructive commands only', () => {
    for (const probe of SSTI_RCE_PROBES) {
      // Should only echo a marker — no rm, no write, no network
      expect(probe.payload).not.toMatch(/\brm\b/);
      expect(probe.payload).not.toMatch(/\bwget\b/);
      expect(probe.payload).not.toMatch(/\bcurl\b/);
    }
  });

  it('has at least 2 Jinja2 RCE variants (class traversal diversity)', () => {
    const jinja = SSTI_RCE_PROBES.filter((p) => p.engine === 'Jinja2/Twig');
    expect(jinja.length).toBeGreaterThanOrEqual(2);
  });
});

describe('prioritizeSstiPayloads', () => {
  it('puts Thymeleaf first when detected', () => {
    const ordered = prioritizeSstiPayloads(['thymeleaf']);
    const first = ordered[0];
    expect(first.engine.toLowerCase()).toContain('thymeleaf');
  });

  it('puts Jinja2 first when detected', () => {
    const ordered = prioritizeSstiPayloads(['jinja2']);
    expect(ordered[0].engine.toLowerCase()).toContain('jinja2');
  });

  it('returns all payloads for unknown engines', () => {
    const ordered = prioritizeSstiPayloads(['unknown']);
    expect(ordered.length).toBe(SSTI_PAYLOADS.length);
  });
});

describe('Traversal Payloads', () => {
  it('has Tomcat/Spring ..;/ bypass', () => {
    expect(TRAVERSAL_PAYLOADS.some((p) => p.includes('..;/'))).toBe(true);
  });

  it('has UTF-8 overlong encoding bypass', () => {
    expect(TRAVERSAL_PAYLOADS.some((p) => p.includes('%c0%af'))).toBe(true);
  });

  it('has URL-encoded backslash for Windows', () => {
    expect(TRAVERSAL_PAYLOADS.some((p) => p.includes('%5c'))).toBe(true);
  });

  it('has /proc/self/environ payload', () => {
    expect(TRAVERSAL_PAYLOADS.some((p) => p.includes('proc/self/environ'))).toBe(true);
  });

  it('has PHP wrapper payloads', () => {
    const php = TRAVERSAL_PAYLOADS.filter((p) => p.startsWith('php://'));
    expect(php.length).toBeGreaterThanOrEqual(2);
  });

  it('success patterns detect /proc/self/environ output', () => {
    const envBody = 'PATH=/usr/bin HOME=/root USER=www-data';
    expect(TRAVERSAL_SUCCESS_PATTERNS.some((p) => p.test(envBody))).toBe(true);
  });
});

describe('CMDi Payload Coverage', () => {
  it('has at least 8 unix timing payloads', () => {
    const unix = CMDI_PAYLOADS_TIMING.filter((p) => p.os === 'unix');
    expect(unix.length).toBeGreaterThanOrEqual(8);
  });

  it('has at least 3 windows timing payloads', () => {
    const windows = CMDI_PAYLOADS_TIMING.filter((p) => p.os === 'windows');
    expect(windows.length).toBeGreaterThanOrEqual(3);
  });

  it('has at least 9 unix output payloads', () => {
    const unix = CMDI_PAYLOADS_OUTPUT.filter((p) => p.os === 'unix');
    expect(unix.length).toBeGreaterThanOrEqual(9);
  });

  it('has at least 4 windows output payloads', () => {
    const windows = CMDI_PAYLOADS_OUTPUT.filter((p) => p.os === 'windows');
    expect(windows.length).toBeGreaterThanOrEqual(4);
  });
});

describe('NoSQL JSON Body Payloads', () => {
  it('has at least 8 payloads', () => {
    expect(NOSQL_JSON_PAYLOADS.length).toBeGreaterThanOrEqual(8);
  });

  it('all payloads have valueJson, technique, and description', () => {
    for (const p of NOSQL_JSON_PAYLOADS) {
      expect(p.valueJson).toBeTruthy();
      expect(p.technique).toBeTruthy();
      expect(p.description).toBeTruthy();
    }
  });

  it('all valueJson strings are valid JSON', () => {
    for (const p of NOSQL_JSON_PAYLOADS) {
      expect(() => JSON.parse(p.valueJson)).not.toThrow();
    }
  });

  it('includes $ne null auth bypass', () => {
    const ne = NOSQL_JSON_PAYLOADS.filter(p => p.valueJson.includes('$ne'));
    expect(ne.length).toBeGreaterThanOrEqual(1);
  });

  it('includes $gt empty string bypass', () => {
    const gt = NOSQL_JSON_PAYLOADS.filter(p => p.valueJson.includes('$gt'));
    expect(gt.length).toBeGreaterThanOrEqual(1);
  });

  it('includes $regex wildcard', () => {
    const regex = NOSQL_JSON_PAYLOADS.filter(p => p.valueJson.includes('$regex'));
    expect(regex.length).toBeGreaterThanOrEqual(1);
  });

  it('includes $where JavaScript eval', () => {
    const where = NOSQL_JSON_PAYLOADS.filter(p => p.valueJson.includes('$where'));
    expect(where.length).toBeGreaterThanOrEqual(1);
  });

  it('includes $exists probe', () => {
    const exists = NOSQL_JSON_PAYLOADS.filter(p => p.valueJson.includes('$exists'));
    expect(exists.length).toBeGreaterThanOrEqual(1);
  });

  it('includes $or logic bypass', () => {
    const or = NOSQL_JSON_PAYLOADS.filter(p => p.valueJson.includes('$or'));
    expect(or.length).toBeGreaterThanOrEqual(1);
  });

  it('techniques are all unique', () => {
    const techniques = NOSQL_JSON_PAYLOADS.map(p => p.technique);
    expect(new Set(techniques).size).toBe(techniques.length);
  });

  it('parsed values are MongoDB operators (objects with $ keys)', () => {
    for (const p of NOSQL_JSON_PAYLOADS) {
      const parsed = JSON.parse(p.valueJson);
      // Each payload should be an object with at least one $ key
      expect(typeof parsed).toBe('object');
      const keys = Object.keys(parsed);
      const hasDollarKey = keys.some(k => k.startsWith('$'));
      expect(hasDollarKey).toBe(true);
    }
  });
});

describe('Stacked Query SQLi Payloads', () => {
  it('has at least 10 stacked query payloads', () => {
    expect(SQLI_STACKED_PAYLOADS.length).toBeGreaterThanOrEqual(10);
  });

  it('all payloads have required fields', () => {
    for (const p of SQLI_STACKED_PAYLOADS) {
      expect(p.payload).toBeTruthy();
      expect(p.dbType).toBeTruthy();
      expect(p.technique).toBeTruthy();
    }
  });

  it('all payloads contain semicolons (multi-statement delimiter)', () => {
    for (const p of SQLI_STACKED_PAYLOADS) {
      expect(p.payload).toContain(';');
    }
  });

  it('has MSSQL WAITFOR stacked payloads', () => {
    const mssql = SQLI_STACKED_PAYLOADS.filter(p => p.dbType === 'mssql');
    expect(mssql.length).toBeGreaterThanOrEqual(3);
    expect(mssql.some(p => p.payload.includes('WAITFOR DELAY'))).toBe(true);
  });

  it('has MSSQL DECLARE stacked payload (multi-statement proof)', () => {
    const declare = SQLI_STACKED_PAYLOADS.filter(p => p.payload.includes('DECLARE'));
    expect(declare.length).toBeGreaterThanOrEqual(1);
    expect(declare[0].dbType).toBe('mssql');
  });

  it('has PostgreSQL pg_sleep stacked payloads', () => {
    const pg = SQLI_STACKED_PAYLOADS.filter(p => p.dbType === 'postgres');
    expect(pg.length).toBeGreaterThanOrEqual(2);
    expect(pg.some(p => p.payload.includes('pg_sleep'))).toBe(true);
  });

  it('has PostgreSQL CREATE TEMP TABLE stacked payload (DDL proof)', () => {
    const create = SQLI_STACKED_PAYLOADS.filter(p => p.payload.includes('CREATE TEMP TABLE'));
    expect(create.length).toBeGreaterThanOrEqual(1);
    expect(create[0].dbType).toBe('postgres');
  });

  it('has MySQL stacked payloads', () => {
    const mysql = SQLI_STACKED_PAYLOADS.filter(p => p.dbType === 'mysql');
    expect(mysql.length).toBeGreaterThanOrEqual(2);
    expect(mysql.some(p => p.payload.includes('SLEEP'))).toBe(true);
  });

  it('has generic stacked payloads for unknown DB', () => {
    const generic = SQLI_STACKED_PAYLOADS.filter(p => p.dbType === 'generic');
    expect(generic.length).toBeGreaterThanOrEqual(1);
  });

  it('techniques are all unique', () => {
    const techniques = SQLI_STACKED_PAYLOADS.map(p => p.technique);
    expect(new Set(techniques).size).toBe(techniques.length);
  });

  it('covers both string and numeric injection contexts', () => {
    const stringContext = SQLI_STACKED_PAYLOADS.filter(p => p.payload.startsWith("'"));
    const numericContext = SQLI_STACKED_PAYLOADS.filter(p => /^\d/.test(p.payload));
    expect(stringContext.length).toBeGreaterThanOrEqual(3);
    expect(numericContext.length).toBeGreaterThanOrEqual(3);
  });
});

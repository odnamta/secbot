import { describe, it, expect } from 'vitest';
import {
  LDAP_PAYLOADS,
  LDAP_ERROR_PATTERNS,
  LDAP_PARAM_PATTERNS,
  detectLdapError,
} from '../../src/config/payloads/ldap.js';

describe('LDAP Injection Payloads', () => {
  it('has at least 10 payloads', () => {
    expect(LDAP_PAYLOADS.length).toBeGreaterThanOrEqual(10);
  });

  it('covers both error-based and blind techniques', () => {
    const errorBased = LDAP_PAYLOADS.filter((p) => !p.blind);
    const blind = LDAP_PAYLOADS.filter((p) => p.blind);
    expect(errorBased.length).toBeGreaterThanOrEqual(3);
    expect(blind.length).toBeGreaterThanOrEqual(4);
  });

  it('all payloads have required fields', () => {
    for (const p of LDAP_PAYLOADS) {
      expect(p.payload).toBeTruthy();
      expect(p.technique).toBeTruthy();
      expect(p.indicator).toBeInstanceOf(RegExp);
      expect(typeof p.blind).toBe('boolean');
    }
  });

  it('all payloads have unique techniques', () => {
    const techniques = LDAP_PAYLOADS.map((p) => p.technique);
    expect(new Set(techniques).size).toBe(techniques.length);
  });

  it('includes wildcard filter break payload', () => {
    const wfb = LDAP_PAYLOADS.find((p) => p.technique === 'wildcard-filter-break');
    expect(wfb).toBeDefined();
    expect(wfb!.payload).toContain('objectClass');
    expect(wfb!.blind).toBe(false);
  });

  it('includes wildcard bypass for auth', () => {
    const wb = LDAP_PAYLOADS.find((p) => p.technique === 'wildcard-bypass');
    expect(wb).toBeDefined();
    expect(wb!.payload).toBe('*');
    expect(wb!.blind).toBe(true);
  });

  it('includes attribute extraction payloads', () => {
    const mail = LDAP_PAYLOADS.find((p) => p.technique === 'attribute-extraction-mail');
    const phone = LDAP_PAYLOADS.find((p) => p.technique === 'attribute-extraction-phone');
    expect(mail).toBeDefined();
    expect(phone).toBeDefined();
    expect(mail!.payload).toContain('mail');
    expect(phone!.payload).toContain('telephoneNumber');
  });
});

describe('LDAP Error Detection', () => {
  it('has at least 15 error patterns', () => {
    expect(LDAP_ERROR_PATTERNS.length).toBeGreaterThanOrEqual(15);
  });

  it('detects Java LDAP errors', () => {
    expect(detectLdapError('javax.naming.NamingException: foo').detected).toBe(true);
    expect(detectLdapError('com.sun.jndi.ldap.LdapCtx').detected).toBe(true);
  });

  it('detects Active Directory errors', () => {
    expect(detectLdapError('LdapErr: DSID-0C0906E8').detected).toBe(true);
  });

  it('detects PHP LDAP errors', () => {
    expect(detectLdapError('Warning: ldap_search(): bad filter').detected).toBe(true);
    expect(detectLdapError('ldap_bind failed').detected).toBe(true);
  });

  it('detects Python LDAP errors', () => {
    expect(detectLdapError('ldap3.core.exceptions').detected).toBe(true);
    expect(detectLdapError('python-ldap error').detected).toBe(true);
  });

  it('detects generic LDAP errors', () => {
    expect(detectLdapError('Invalid DN syntax').detected).toBe(true);
    expect(detectLdapError('bad search filter').detected).toBe(true);
    expect(detectLdapError('operations error').detected).toBe(true);
  });

  it('returns the matching pattern source', () => {
    const result = detectLdapError('javax.naming.NamingException');
    expect(result.detected).toBe(true);
    expect(result.pattern).toBeTruthy();
  });

  it('returns false for clean responses', () => {
    expect(detectLdapError('Login successful').detected).toBe(false);
    expect(detectLdapError('<html>Welcome</html>').detected).toBe(false);
    expect(detectLdapError('Invalid username or password').detected).toBe(false);
  });
});

describe('LDAP Parameter Patterns', () => {
  it('matches common LDAP auth param names', () => {
    expect(LDAP_PARAM_PATTERNS.test('username')).toBe(true);
    expect(LDAP_PARAM_PATTERNS.test('uid')).toBe(true);
    expect(LDAP_PARAM_PATTERNS.test('cn')).toBe(true);
    expect(LDAP_PARAM_PATTERNS.test('sn')).toBe(true);
    expect(LDAP_PARAM_PATTERNS.test('dn')).toBe(true);
    expect(LDAP_PARAM_PATTERNS.test('login')).toBe(true);
    expect(LDAP_PARAM_PATTERNS.test('sAMAccountName')).toBe(true);
  });

  it('does not match unrelated param names', () => {
    expect(LDAP_PARAM_PATTERNS.test('page')).toBe(false);
    expect(LDAP_PARAM_PATTERNS.test('sort')).toBe(false);
    expect(LDAP_PARAM_PATTERNS.test('limit')).toBe(false);
    expect(LDAP_PARAM_PATTERNS.test('offset')).toBe(false);
  });
});

describe('LDAP Injection Check Registration', () => {
  it('exports the check module', async () => {
    const mod = await import('../../src/scanner/active/ldap-injection.js');
    expect(mod.ldapInjectionCheck).toBeDefined();
    expect(mod.ldapInjectionCheck.name).toBe('ldap-injection');
    expect(mod.ldapInjectionCheck.category).toBe('ldap-injection');
  });

  it('is registered in CHECK_REGISTRY', async () => {
    const { CHECK_REGISTRY } = await import('../../src/scanner/active/index.js');
    const check = CHECK_REGISTRY.find((c) => c.name === 'ldap-injection');
    expect(check).toBeDefined();
  });

  it('is included in ALL_PLANNER_CHECKS', async () => {
    const { ALL_PLANNER_CHECKS } = await import('../../src/ai/prompts.js');
    expect(ALL_PLANNER_CHECKS).toContain('ldap-injection');
  });

  it('has fallback OWASP mapping', async () => {
    const { mapToOwasp } = await import('../../src/ai/fallback.js');
    expect(mapToOwasp('ldap-injection')).toBe('A03:2021 - Injection');
  });

  it('has fallback impact description', async () => {
    const { getGenericImpact } = await import('../../src/ai/fallback.js');
    const impact = getGenericImpact('ldap-injection');
    expect(impact).toContain('LDAP');
    expect(impact).not.toBe('Unknown impact.');
  });

  it('has fallback fix recommendation', async () => {
    const { getGenericFix } = await import('../../src/ai/fallback.js');
    const fix = getGenericFix('ldap-injection');
    expect(fix).toContain('LDAP');
    expect(fix).not.toBe('Review and fix the identified vulnerability.');
  });
});

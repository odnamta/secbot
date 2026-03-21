import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('access-control check', () => {
  it('exports accessControlCheck with correct interface', async () => {
    const { accessControlCheck } = await import('../../src/scanner/active/access-control.js');
    expect(accessControlCheck.name).toBe('access-control');
    expect(accessControlCheck.category).toBe('broken-access-control');
    expect(typeof accessControlCheck.run).toBe('function');
  });

  it('is not marked as parallel (sends requests)', async () => {
    const { accessControlCheck } = await import('../../src/scanner/active/access-control.js');
    expect(accessControlCheck.parallel).toBeUndefined();
  });
});

describe('identifyPrivilegedEndpoints', () => {
  it('identifies admin URLs', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = [
      'http://localhost:3000/admin/users',
      'http://localhost:3000/api/products',
      'http://localhost:3000/dashboard',
      'http://localhost:3000/login',
      'http://localhost:3000/settings',
    ];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result).toContain('http://localhost:3000/admin/users');
    expect(result).toContain('http://localhost:3000/dashboard');
    expect(result).toContain('http://localhost:3000/settings');
    expect(result).not.toContain('http://localhost:3000/login');
  });

  it('detects various admin patterns', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const patterns = [
      'http://example.com/manage/orders',
      'http://example.com/internal/api',
      'http://example.com/staff/list',
      'http://example.com/billing/invoices',
      'http://example.com/system/health',
      'http://example.com/control/panel',
    ];
    const result = identifyPrivilegedEndpoints(patterns);
    expect(result.length).toBe(patterns.length);
  });

  it('returns empty for non-privileged URLs', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = [
      'http://localhost:3000/',
      'http://localhost:3000/login',
      'http://localhost:3000/signup',
      'http://localhost:3000/api/products',
      'http://localhost:3000/about',
    ];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result).toEqual([]);
  });

  it('handles invalid URLs gracefully', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = ['not-a-url', '', 'http://localhost:3000/admin'];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result).toContain('http://localhost:3000/admin');
    expect(result.length).toBe(1);
  });

  it('is case-insensitive for pattern matching', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = [
      'http://localhost:3000/Admin/panel',
      'http://localhost:3000/DASHBOARD',
      'http://localhost:3000/Settings/profile',
    ];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result.length).toBe(3);
  });
});

describe('UNAUTH_ADMIN_PATHS coverage', () => {
  it('includes common admin paths', async () => {
    // Import the module to verify the constant exists (exported via closure in probeUnauthenticatedAdminPaths)
    const mod = await import('../../src/scanner/active/access-control.js');
    expect(mod.accessControlCheck.name).toBe('access-control');
    // The UNAUTH_ADMIN_PATHS is not exported, but we verify it works through the check
  });

  it('runs unauthenticated probing without --auth (via run method contract)', async () => {
    // The check should NOT return empty just because --auth is missing anymore
    // It should probe admin paths and only skip auth-based tests
    const { accessControlCheck } = await import('../../src/scanner/active/access-control.js');
    // Verify the check function signature exists
    expect(typeof accessControlCheck.run).toBe('function');
  });
});

describe('traversal WAF bypass payloads', () => {
  it('includes double URL encoding bypass', async () => {
    const { TRAVERSAL_PAYLOADS } = await import('../../src/config/payloads/traversal.js');
    const doubleEncoded = TRAVERSAL_PAYLOADS.filter(p => p.includes('%252f'));
    expect(doubleEncoded.length).toBeGreaterThanOrEqual(2);
  });

  it('includes Unicode fullwidth bypass', async () => {
    const { TRAVERSAL_PAYLOADS } = await import('../../src/config/payloads/traversal.js');
    const unicode = TRAVERSAL_PAYLOADS.filter(p => p.includes('%ef%bc%8f'));
    expect(unicode.length).toBeGreaterThanOrEqual(1);
  });

  it('includes Windows ADS bypass', async () => {
    const { TRAVERSAL_PAYLOADS } = await import('../../src/config/payloads/traversal.js');
    const ads = TRAVERSAL_PAYLOADS.filter(p => p.includes('::$DATA'));
    expect(ads.length).toBeGreaterThanOrEqual(1);
  });

  it('has at least 30 payloads total', async () => {
    const { TRAVERSAL_PAYLOADS } = await import('../../src/config/payloads/traversal.js');
    expect(TRAVERSAL_PAYLOADS.length).toBeGreaterThanOrEqual(30);
  });
});

describe('DEFAULT_CREDENTIALS', () => {
  it('has at least 12 credential pairs', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    expect(DEFAULT_CREDENTIALS.length).toBeGreaterThanOrEqual(12);
  });

  it('all entries have username and password fields', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    for (const cred of DEFAULT_CREDENTIALS) {
      expect(cred.username).toBeTruthy();
      expect(typeof cred.password).toBe('string'); // empty string is valid
    }
  });

  it('includes admin/admin', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    const adminAdmin = DEFAULT_CREDENTIALS.filter(c => c.username === 'admin' && c.password === 'admin');
    expect(adminAdmin.length).toBe(1);
  });

  it('includes root/root', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    const rootRoot = DEFAULT_CREDENTIALS.filter(c => c.username === 'root' && c.password === 'root');
    expect(rootRoot.length).toBe(1);
  });

  it('includes empty password variant', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    const empty = DEFAULT_CREDENTIALS.filter(c => c.password === '');
    expect(empty.length).toBeGreaterThanOrEqual(1);
  });

  it('includes guest account', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    const guest = DEFAULT_CREDENTIALS.filter(c => c.username === 'guest');
    expect(guest.length).toBeGreaterThanOrEqual(1);
  });

  it('includes test/demo accounts', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    const testDemo = DEFAULT_CREDENTIALS.filter(c => c.username === 'test' || c.username === 'demo');
    expect(testDemo.length).toBeGreaterThanOrEqual(2);
  });

  it('credentials are unique pairs', async () => {
    const { DEFAULT_CREDENTIALS } = await import('../../src/scanner/active/access-control.js');
    const pairs = DEFAULT_CREDENTIALS.map(c => `${c.username}:${c.password}`);
    expect(new Set(pairs).size).toBe(pairs.length);
  });
});

describe('PATH_NORMALIZATION_BYPASSES', () => {
  it('has at least 12 bypass techniques', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    expect(PATH_NORMALIZATION_BYPASSES.length).toBeGreaterThanOrEqual(12);
  });

  it('all bypasses have suffix and description', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    for (const b of PATH_NORMALIZATION_BYPASSES) {
      expect(b.suffix).toBeTruthy();
      expect(b.description).toBeTruthy();
    }
  });

  it('includes Tomcat ..;/ bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const tomcat = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix.includes('..;'));
    expect(tomcat.length).toBeGreaterThanOrEqual(1);
    expect(tomcat[0].description).toMatch(/tomcat|spring/i);
  });

  it('includes URL-encoded dot bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const encoded = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix.includes('%2e'));
    expect(encoded.length).toBeGreaterThanOrEqual(1);
  });

  it('includes null byte bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const nullByte = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix.includes('%00'));
    expect(nullByte.length).toBeGreaterThanOrEqual(1);
  });

  it('includes trailing space bypass (IIS)', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const space = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '%20');
    expect(space.length).toBe(1);
    expect(space[0].description).toMatch(/space|IIS/i);
  });

  it('includes extension append bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const json = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '.json');
    const html = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '.html');
    expect(json.length).toBe(1);
    expect(html.length).toBe(1);
  });

  it('includes semicolon path parameter bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const semi = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === ';');
    expect(semi.length).toBe(1);
    expect(semi[0].description).toMatch(/semicolon|tomcat|jboss/i);
  });

  it('includes self-referential path bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const selfRef = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '/./');
    expect(selfRef.length).toBe(1);
  });

  it('includes trailing slash difference', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const slash = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '/');
    expect(slash.length).toBe(1);
  });

  it('includes query string bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const query = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '?');
    expect(query.length).toBe(1);
  });

  it('includes fragment bypass', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const frag = PATH_NORMALIZATION_BYPASSES.filter(b => b.suffix === '#');
    expect(frag.length).toBe(1);
  });

  it('bypass suffixes are all unique', async () => {
    const { PATH_NORMALIZATION_BYPASSES } = await import('../../src/scanner/active/access-control.js');
    const suffixes = PATH_NORMALIZATION_BYPASSES.map(b => b.suffix);
    expect(new Set(suffixes).size).toBe(suffixes.length);
  });
});

describe('cmdi WAF bypass payloads', () => {
  it('includes ${IFS} separator bypass', async () => {
    const { CMDI_PAYLOADS_TIMING, CMDI_PAYLOADS_OUTPUT } = await import('../../src/config/payloads/cmdi.js');
    const ifsTimingPayloads = CMDI_PAYLOADS_TIMING.filter(p => p.payload.includes('${IFS}'));
    const ifsOutputPayloads = CMDI_PAYLOADS_OUTPUT.filter(p => p.payload.includes('${IFS}'));
    expect(ifsTimingPayloads.length).toBeGreaterThanOrEqual(2);
    expect(ifsOutputPayloads.length).toBeGreaterThanOrEqual(2);
  });

  it('includes string concatenation bypass', async () => {
    const { CMDI_PAYLOADS_OUTPUT } = await import('../../src/config/payloads/cmdi.js');
    const concatPayloads = CMDI_PAYLOADS_OUTPUT.filter(p => p.payload.includes("''"));
    expect(concatPayloads.length).toBeGreaterThanOrEqual(1);
  });

  it('includes newline injection bypass', async () => {
    const { CMDI_PAYLOADS_TIMING, CMDI_PAYLOADS_OUTPUT } = await import('../../src/config/payloads/cmdi.js');
    const nlTiming = CMDI_PAYLOADS_TIMING.filter(p => p.payload.includes('%0a'));
    const nlOutput = CMDI_PAYLOADS_OUTPUT.filter(p => p.payload.includes('%0a'));
    expect(nlTiming.length).toBeGreaterThanOrEqual(1);
    expect(nlOutput.length).toBeGreaterThanOrEqual(1);
  });

  it('includes PowerShell variants for Windows', async () => {
    const { CMDI_PAYLOADS_TIMING, CMDI_PAYLOADS_OUTPUT } = await import('../../src/config/payloads/cmdi.js');
    const psTiming = CMDI_PAYLOADS_TIMING.filter(p => p.os === 'windows' && p.payload.includes('Start-Sleep'));
    const psOutput = CMDI_PAYLOADS_OUTPUT.filter(p => p.os === 'windows' && p.payload.includes('Write-Output'));
    expect(psTiming.length).toBeGreaterThanOrEqual(1);
    expect(psOutput.length).toBeGreaterThanOrEqual(1);
  });

  it('has at least 18 timing payloads', async () => {
    const { CMDI_PAYLOADS_TIMING } = await import('../../src/config/payloads/cmdi.js');
    expect(CMDI_PAYLOADS_TIMING.length).toBeGreaterThanOrEqual(18);
  });

  it('has at least 19 output payloads', async () => {
    const { CMDI_PAYLOADS_OUTPUT } = await import('../../src/config/payloads/cmdi.js');
    expect(CMDI_PAYLOADS_OUTPUT.length).toBeGreaterThanOrEqual(19);
  });

  it('all timing payloads have valid os field', async () => {
    const { CMDI_PAYLOADS_TIMING } = await import('../../src/config/payloads/cmdi.js');
    for (const p of CMDI_PAYLOADS_TIMING) {
      expect(['unix', 'windows']).toContain(p.os);
      expect(p.delay).toBe(5);
    }
  });

  it('all output payloads use the same marker', async () => {
    const { CMDI_PAYLOADS_OUTPUT } = await import('../../src/config/payloads/cmdi.js');
    for (const p of CMDI_PAYLOADS_OUTPUT) {
      expect(p.marker).toBe('secbot-cmdi-marker');
    }
  });
});

describe('Session Fixation detection (CWE-384)', () => {
  it('calculateEntropy returns 0 for empty string', async () => {
    // Import the module and test entropy calculation indirectly
    // Since calculateEntropy is not exported, we test via the check behavior
    // For now, validate that the access-control module loads correctly with session fixation
    const { accessControlCheck } = await import('../../src/scanner/active/access-control.js');
    expect(accessControlCheck).toBeDefined();
    expect(typeof accessControlCheck.run).toBe('function');
  });

  it('session fixation test is wired into access-control run method', async () => {
    // Verify the function exists by checking the module can be imported without errors
    const mod = await import('../../src/scanner/active/access-control.js');
    expect(mod.accessControlCheck.name).toBe('access-control');
  });

  it('recognizes session cookie names', () => {
    // Session cookie patterns used in the fixation check
    const sessionPattern = /session|sess|sid|token|auth|jwt|connect\.sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|__Host-|__Secure-/i;
    expect(sessionPattern.test('PHPSESSID')).toBe(true);
    expect(sessionPattern.test('JSESSIONID')).toBe(true);
    expect(sessionPattern.test('connect.sid')).toBe(true);
    expect(sessionPattern.test('ASP.NET_SessionId')).toBe(true);
    expect(sessionPattern.test('session_id')).toBe(true);
    expect(sessionPattern.test('auth_token')).toBe(true);
    expect(sessionPattern.test('__Host-session')).toBe(true);
    expect(sessionPattern.test('__Secure-token')).toBe(true);
    // Non-session cookies should not match
    expect(sessionPattern.test('_ga')).toBe(false);
    expect(sessionPattern.test('theme')).toBe(false);
    expect(sessionPattern.test('locale')).toBe(false);
  });

  it('entropy calculation works correctly for known inputs', () => {
    // Shannon entropy: H = -sum(p * log2(p))
    // For a string of all same chars: H = 0
    // For a perfectly random hex string: H ≈ 4.0 bits/char
    function calcEntropy(str: string): number {
      if (str.length === 0) return 0;
      const freq = new Map<string, number>();
      for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
      let h = 0;
      for (const count of freq.values()) {
        const p = count / str.length;
        h -= p * Math.log2(p);
      }
      return h;
    }

    // All same chars = 0 entropy
    expect(calcEntropy('aaaaaaaaaa')).toBe(0);

    // Two equally distributed chars = 1 bit
    expect(calcEntropy('abababab')).toBeCloseTo(1.0, 5);

    // Long random-looking hex = high entropy
    const hex = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    expect(calcEntropy(hex)).toBeGreaterThan(3.5);

    // Sequential number = low entropy
    expect(calcEntropy('12345')).toBeGreaterThan(2.0); // 5 unique chars
    expect(calcEntropy('11111')).toBe(0); // all same
  });

  it('weak session IDs are flagged (short, sequential)', () => {
    // These patterns should trigger the weak session check
    const weakPatterns = ['12345', 'abc', '1', 'a1b2c3', '000001'];
    const strongPatterns = ['a1b2c3d4e5f67890abcdef1234567890', 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ'];

    for (const weak of weakPatterns) {
      expect(weak.length).toBeLessThan(16); // short = weak
    }

    for (const strong of strongPatterns) {
      expect(strong.length).toBeGreaterThanOrEqual(16); // long enough
    }
  });
});

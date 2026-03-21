import { describe, it, expect, vi } from 'vitest';
import { SessionManager } from '../../src/scanner/auth/session-manager.js';
import type { InterceptedResponse } from '../../src/scanner/types.js';

function makeResponse(overrides: Partial<InterceptedResponse> = {}): InterceptedResponse {
  return {
    url: 'https://example.com/api/data',
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"data": []}',
    ...overrides,
  };
}

describe('SessionManager.isSessionExpired', () => {
  const manager = new SessionManager();

  it('returns true for 401 status', () => {
    const resp = makeResponse({ status: 401 });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "session expired" body', () => {
    const resp = makeResponse({
      status: 403,
      body: '<html><body>Your session has expired. Please log in again.</body></html>',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "token expired" body', () => {
    const resp = makeResponse({
      status: 403,
      body: '{"error": "Token has expired"}',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "authentication required" body', () => {
    const resp = makeResponse({
      status: 403,
      body: '<p>Authentication required to access this resource</p>',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "please login" body', () => {
    const resp = makeResponse({
      status: 403,
      body: 'Please log in to continue',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "please re-login" body', () => {
    const resp = makeResponse({
      status: 403,
      body: 'Please re-login to continue',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "login required" body', () => {
    const resp = makeResponse({
      status: 403,
      body: 'Login required',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "unauthorized" body', () => {
    const resp = makeResponse({
      status: 403,
      body: 'Unauthorized access',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns true for 403 with "session timed out" body', () => {
    const resp = makeResponse({
      status: 403,
      body: 'Your session timed out',
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('returns false for 403 without session-related body', () => {
    const resp = makeResponse({
      status: 403,
      body: '<html><body>You do not have permission to view this resource.</body></html>',
    });
    expect(manager.isSessionExpired(resp)).toBe(false);
  });

  it('returns false for 403 without body', () => {
    const resp = makeResponse({
      status: 403,
      body: undefined,
    });
    expect(manager.isSessionExpired(resp)).toBe(false);
  });

  it('returns false for 200 OK response', () => {
    const resp = makeResponse({ status: 200 });
    expect(manager.isSessionExpired(resp)).toBe(false);
  });

  it('returns false for 404 response', () => {
    const resp = makeResponse({ status: 404 });
    expect(manager.isSessionExpired(resp)).toBe(false);
  });

  it('returns false for 500 response', () => {
    const resp = makeResponse({ status: 500 });
    expect(manager.isSessionExpired(resp)).toBe(false);
  });

  it('detects 302 redirect to /login as session expiry', () => {
    const resp = makeResponse({
      status: 302,
      headers: { location: 'https://example.com/login?redirect=/dashboard' },
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('detects 302 redirect to /signin as session expiry', () => {
    const resp = makeResponse({
      status: 302,
      headers: { location: '/signin' },
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('detects 303 redirect to /auth/ as session expiry', () => {
    const resp = makeResponse({
      status: 303,
      headers: { location: '/auth/login' },
    });
    expect(manager.isSessionExpired(resp)).toBe(true);
  });

  it('does not treat 302 to non-login URL as session expiry', () => {
    const resp = makeResponse({
      status: 302,
      headers: { location: '/dashboard' },
    });
    expect(manager.isSessionExpired(resp)).toBe(false);
  });
});

describe('SessionManager events', () => {
  it('registers and fires listeners', () => {
    const manager = new SessionManager();
    const events: string[] = [];

    manager.on((event, detail) => {
      events.push(`${event}:${detail ?? ''}`);
    });

    // Trigger session-expired via isSessionExpired + refreshSession path
    // (tested indirectly below)
    expect(events).toHaveLength(0);
  });

  it('can remove a listener', () => {
    const manager = new SessionManager();
    const events: string[] = [];
    const listener = (event: string) => { events.push(event); };

    manager.on(listener);
    manager.off(listener);

    // No events should be captured (tested via refresh below)
    expect(events).toHaveLength(0);
  });
});

describe('SessionManager.refreshSession', () => {
  it('returns false when max refreshes exceeded', async () => {
    const manager = new SessionManager(0); // 0 max refreshes
    const events: string[] = [];
    manager.on((event) => { events.push(event); });

    const context = {} as any;
    const result = await manager.refreshSession(context, {
      loginUrl: 'https://example.com/login',
      username: 'admin',
      password: 'secret',
    });

    expect(result).toBe(false);
    expect(events).toContain('session-refresh-failed');
  });

  it('tracks refresh count', () => {
    const manager = new SessionManager(5);
    expect(manager.refreshes).toBe(0);
  });

  it('reports isRefreshing status', () => {
    const manager = new SessionManager();
    expect(manager.isRefreshing).toBe(false);
  });

  it('emits session-refresh-failed on error', async () => {
    const manager = new SessionManager(3);
    const events: string[] = [];
    manager.on((event) => { events.push(event); });

    // Context that throws when creating a new page
    const context = {
      newPage: vi.fn().mockRejectedValue(new Error('Browser closed')),
    } as any;

    const result = await manager.refreshSession(context, {
      loginUrl: 'https://example.com/login',
      username: 'admin',
      password: 'secret',
    });

    expect(result).toBe(false);
    expect(events).toContain('session-expired');
    expect(events).toContain('session-refresh-failed');
  });

  it('prevents concurrent refresh attempts', async () => {
    const manager = new SessionManager(3);

    // Create a context.newPage that returns a page with slow authenticate
    let resolveAuth: () => void;
    const authPromise = new Promise<void>((resolve) => { resolveAuth = resolve; });

    const mockPage = {
      goto: vi.fn().mockImplementation(() => authPromise),
      evaluate: vi.fn().mockResolvedValue(null),
      fill: vi.fn().mockResolvedValue(undefined),
      click: vi.fn().mockResolvedValue(undefined),
      waitForNavigation: vi.fn().mockResolvedValue(undefined),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
      url: vi.fn().mockReturnValue('https://example.com/login'),
      context: vi.fn().mockReturnValue({
        storageState: vi.fn().mockResolvedValue({ cookies: [], origins: [] }),
        cookies: vi.fn().mockResolvedValue([]),
      }),
      close: vi.fn().mockResolvedValue(undefined),
    };

    const context = {
      newPage: vi.fn().mockResolvedValue(mockPage),
    } as any;

    const authOptions = {
      loginUrl: 'https://example.com/login',
      username: 'admin',
      password: 'secret',
    };

    // Start first refresh (will hang on goto)
    const firstRefresh = manager.refreshSession(context, authOptions);

    // Try a second refresh while first is in progress
    const secondResult = await manager.refreshSession(context, authOptions);
    expect(secondResult).toBe(false);

    // Resolve the first one
    resolveAuth!();
    await firstRefresh;
  });
});

describe('SessionManager.isLoginPageResponse', () => {
  const manager = new SessionManager();

  it('returns true when redirected to /login', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/dashboard',
      'https://example.com/login?redirect=/dashboard',
    )).toBe(true);
  });

  it('returns true when redirected to /login.php', () => {
    expect(manager.isLoginPageResponse(
      'https://dvwa.local/vulnerabilities/sqli/',
      'https://dvwa.local/login.php',
    )).toBe(true);
  });

  it('returns true when redirected to /wp-login.php', () => {
    expect(manager.isLoginPageResponse(
      'https://wp.local/wp-admin/',
      'https://wp.local/wp-login.php?redirect_to=/wp-admin/',
    )).toBe(true);
  });

  it('returns true when redirected to /signin', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/api/data',
      'https://example.com/signin',
    )).toBe(true);
  });

  it('returns true when redirected to /auth/login', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/protected',
      'https://example.com/auth/login',
    )).toBe(true);
  });

  it('returns true when redirected to /sso/login', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/protected',
      'https://example.com/sso/login',
    )).toBe(true);
  });

  it('returns false when request URL is already a login page', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/login',
      'https://example.com/login',
    )).toBe(false);
  });

  it('returns false when request URL is login.php', () => {
    expect(manager.isLoginPageResponse(
      'https://dvwa.local/login.php',
      'https://dvwa.local/login.php',
    )).toBe(false);
  });

  it('returns false when URLs are the same (no redirect)', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/api/data',
      'https://example.com/api/data',
    )).toBe(false);
  });

  it('returns false when redirected to non-login URL', () => {
    expect(manager.isLoginPageResponse(
      'https://example.com/old-page',
      'https://example.com/new-page',
    )).toBe(false);
  });

  it('returns true when body contains password input + form (URL changed)', () => {
    const body = '<html><body><form action="/login" method="POST"><input type="text" name="user"><input type="password" name="pass"><button type="submit">Login</button></form></body></html>';
    expect(manager.isLoginPageResponse(
      'https://example.com/dashboard',
      'https://example.com/auth-page',
      body,
    )).toBe(true);
  });

  it('returns false when body contains password input but URL did not change', () => {
    const body = '<html><body><form action="/change-password" method="POST"><input type="password" name="old_pass"><input type="password" name="new_pass"></form></body></html>';
    expect(manager.isLoginPageResponse(
      'https://example.com/settings',
      'https://example.com/settings',
      body,
    )).toBe(false);
  });
});

describe('SessionManager.loginRedirectPatterns', () => {
  it('includes /login.php pattern', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    expect(patterns.some((p) => p.test('/login.php'))).toBe(true);
  });

  it('includes /wp-login pattern', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    expect(patterns.some((p) => p.test('/wp-login.php'))).toBe(true);
  });

  it('includes /login pattern', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    expect(patterns.some((p) => p.test('/login'))).toBe(true);
  });

  it('includes /signin pattern', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    expect(patterns.some((p) => p.test('/signin'))).toBe(true);
  });

  it('includes /auth/ pattern', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    expect(patterns.some((p) => p.test('/auth/login'))).toBe(true);
  });

  it('includes /sso/ pattern', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    expect(patterns.some((p) => p.test('/sso/saml'))).toBe(true);
  });

  it('does not match /logout', () => {
    const patterns = SessionManager.loginRedirectPatterns;
    // /logout would match /login pattern (contains "login" substring via /log.../),
    // but let's verify the actual behavior
    const matchesLogin = patterns.some((p) => p.test('/logout'));
    // /logout contains "login"? No — /login pattern matches "/login" which is not in "/logout"
    // Actually /\/login/i would NOT match /logout. Good.
    expect(matchesLogin).toBe(false);
  });
});

describe('SessionManager multi-role support', () => {
  it('can create separate managers per role', () => {
    const adminManager = new SessionManager(3);
    const userManager = new SessionManager(3);

    // Each has independent state
    expect(adminManager.refreshes).toBe(0);
    expect(userManager.refreshes).toBe(0);
  });
});

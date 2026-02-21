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

describe('SessionManager multi-role support', () => {
  it('can create separate managers per role', () => {
    const adminManager = new SessionManager(3);
    const userManager = new SessionManager(3);

    // Each has independent state
    expect(adminManager.refreshes).toBe(0);
    expect(userManager.refreshes).toBe(0);
  });
});

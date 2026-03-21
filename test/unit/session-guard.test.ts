import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SessionGuard } from '../../src/scanner/auth/session-guard.js';
import { SessionManager } from '../../src/scanner/auth/session-manager.js';

/**
 * Create a mock BrowserContext with on/off event methods.
 */
function mockContext() {
  const listeners = new Map<string, Set<Function>>();
  return {
    on: vi.fn((event: string, handler: Function) => {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(handler);
    }),
    off: vi.fn((event: string, handler: Function) => {
      listeners.get(event)?.delete(handler);
    }),
    /** Simulate emitting a response event */
    _emit: async (event: string, ...args: unknown[]) => {
      const handlers = listeners.get(event);
      if (handlers) {
        for (const handler of handlers) {
          await handler(...args);
        }
      }
    },
    _listenerCount: (event: string) => listeners.get(event)?.size ?? 0,
    // Minimal BrowserContext mock for refreshSession
    newPage: vi.fn().mockRejectedValue(new Error('mock: no page')),
  } as any;
}

/**
 * Create a mock Playwright Response object.
 */
function mockResponse(opts: {
  requestUrl: string;
  responseUrl?: string;
  status: number;
  headers?: Record<string, string>;
  body?: string;
}) {
  return {
    request: () => ({ url: () => opts.requestUrl }),
    url: () => opts.responseUrl ?? opts.requestUrl,
    status: () => opts.status,
    headers: () => opts.headers ?? {},
    text: vi.fn().mockResolvedValue(opts.body ?? ''),
  } as any;
}

describe('SessionGuard', () => {
  let context: ReturnType<typeof mockContext>;
  let sessionManager: SessionManager;

  beforeEach(() => {
    context = mockContext();
    sessionManager = new SessionManager(3);
  });

  describe('attach/detach', () => {
    it('registers a response listener on attach', () => {
      const guard = new SessionGuard(context, sessionManager);
      guard.attach();

      expect(context.on).toHaveBeenCalledWith('response', expect.any(Function));
      expect(context._listenerCount('response')).toBe(1);
    });

    it('unregisters the listener on detach', () => {
      const guard = new SessionGuard(context, sessionManager);
      guard.attach();
      guard.detach();

      expect(context.off).toHaveBeenCalledWith('response', expect.any(Function));
      expect(context._listenerCount('response')).toBe(0);
    });

    it('does not register twice on double attach', () => {
      const guard = new SessionGuard(context, sessionManager);
      guard.attach();
      guard.attach();

      expect(context._listenerCount('response')).toBe(1);
    });

    it('is safe to detach without attach', () => {
      const guard = new SessionGuard(context, sessionManager);
      guard.detach(); // should not throw
      expect(context.off).not.toHaveBeenCalled();
    });
  });

  describe('threshold behavior', () => {
    it('single 401 does NOT trigger refresh', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession');
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      await context._emit('response', mockResponse({
        requestUrl: 'https://example.com/api/data',
        status: 401,
      }));

      expect(refreshSpy).not.toHaveBeenCalled();
    });

    it('two consecutive 401s do NOT trigger refresh (threshold=3)', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession');
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      await context._emit('response', mockResponse({
        requestUrl: 'https://example.com/api/data',
        status: 401,
      }));
      await context._emit('response', mockResponse({
        requestUrl: 'https://example.com/api/other',
        status: 401,
      }));

      expect(refreshSpy).not.toHaveBeenCalled();
    });

    it('3 consecutive login redirects trigger refresh', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      for (let i = 0; i < 3; i++) {
        await context._emit('response', mockResponse({
          requestUrl: `https://example.com/api/resource${i}`,
          status: 302,
          headers: { location: '/login?redirect=/api/resource' },
        }));
      }

      expect(refreshSpy).toHaveBeenCalledOnce();
      expect(refreshSpy).toHaveBeenCalledWith(context, authOptions);
    });

    it('3 consecutive 401s trigger refresh', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      for (let i = 0; i < 3; i++) {
        await context._emit('response', mockResponse({
          requestUrl: `https://example.com/api/resource${i}`,
          status: 401,
        }));
      }

      expect(refreshSpy).toHaveBeenCalledOnce();
    });

    it('200 response resets counter', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      // Two 401s
      await context._emit('response', mockResponse({ requestUrl: 'https://example.com/a', status: 401 }));
      await context._emit('response', mockResponse({ requestUrl: 'https://example.com/b', status: 401 }));

      // Successful response resets
      await context._emit('response', mockResponse({ requestUrl: 'https://example.com/c', status: 200 }));

      // Two more 401s — should NOT trigger (only 2, not 3)
      await context._emit('response', mockResponse({ requestUrl: 'https://example.com/d', status: 401 }));
      await context._emit('response', mockResponse({ requestUrl: 'https://example.com/e', status: 401 }));

      expect(refreshSpy).not.toHaveBeenCalled();
    });
  });

  describe('login URL filtering', () => {
    it('ignores responses to login URLs', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      // 5 consecutive 401s on login URL — should all be ignored
      for (let i = 0; i < 5; i++) {
        await context._emit('response', mockResponse({
          requestUrl: 'https://example.com/login',
          status: 401,
        }));
      }

      expect(refreshSpy).not.toHaveBeenCalled();
    });

    it('ignores responses to login.php URLs', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://dvwa.local/login.php', username: 'admin', password: 'password' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      for (let i = 0; i < 5; i++) {
        await context._emit('response', mockResponse({
          requestUrl: 'https://dvwa.local/login.php',
          status: 401,
        }));
      }

      expect(refreshSpy).not.toHaveBeenCalled();
    });

    it('ignores responses to wp-login URLs', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://wp.local/wp-login.php', username: 'admin', password: 'admin' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      for (let i = 0; i < 5; i++) {
        await context._emit('response', mockResponse({
          requestUrl: 'https://wp.local/wp-login.php',
          status: 302,
          headers: { location: '/wp-login.php?redirect_to=/wp-admin/' },
        }));
      }

      expect(refreshSpy).not.toHaveBeenCalled();
    });
  });

  describe('URL-based expiry detection', () => {
    it('detects redirect to login.php via response URL mismatch', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://dvwa.local/login.php', username: 'admin', password: 'password' };
      const guard = new SessionGuard(context, sessionManager, authOptions);
      guard.attach();

      for (let i = 0; i < 3; i++) {
        await context._emit('response', mockResponse({
          requestUrl: `https://dvwa.local/vulnerabilities/sqli/?id=${i}`,
          responseUrl: 'https://dvwa.local/login.php',
          status: 200,
        }));
      }

      expect(refreshSpy).toHaveBeenCalledOnce();
    });
  });

  describe('warn-only mode (no credentials)', () => {
    it('warns once instead of refreshing when no credentials available', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession');
      // No authOptions — warn-only mode
      const guard = new SessionGuard(context, sessionManager);
      guard.attach();

      for (let i = 0; i < 6; i++) {
        await context._emit('response', mockResponse({
          requestUrl: `https://example.com/api/resource${i}`,
          status: 401,
        }));
      }

      // Should NOT call refreshSession at all
      expect(refreshSpy).not.toHaveBeenCalled();
    });
  });

  describe('refreshCount', () => {
    it('starts at 0', () => {
      const guard = new SessionGuard(context, sessionManager);
      expect(guard.refreshCount).toBe(0);
    });

    it('reflects session manager refresh count after successful refresh', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      // Manually increment the internal count by simulating a successful refresh
      Object.defineProperty(sessionManager, 'refreshCount', { value: 1, writable: true });

      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions);

      expect(guard.refreshCount).toBe(1);
    });
  });

  describe('custom threshold', () => {
    it('respects custom consecutiveThreshold', async () => {
      const refreshSpy = vi.spyOn(sessionManager, 'refreshSession').mockResolvedValue(true);
      const authOptions = { loginUrl: 'https://example.com/login', username: 'admin', password: 'secret' };
      const guard = new SessionGuard(context, sessionManager, authOptions, { consecutiveThreshold: 5 });
      guard.attach();

      // 4 consecutive 401s — should NOT trigger with threshold 5
      for (let i = 0; i < 4; i++) {
        await context._emit('response', mockResponse({
          requestUrl: `https://example.com/api/r${i}`,
          status: 401,
        }));
      }
      expect(refreshSpy).not.toHaveBeenCalled();

      // 5th triggers it
      await context._emit('response', mockResponse({
        requestUrl: 'https://example.com/api/r4',
        status: 401,
      }));
      expect(refreshSpy).toHaveBeenCalledOnce();
    });
  });
});

import type { BrowserContext } from 'playwright';
import type { AuthOptions, InterceptedResponse } from '../types.js';
import { authenticate } from './authenticator.js';
import { log } from '../../utils/logger.js';

type SessionEvent = 'session-expired' | 'session-refreshed' | 'session-refresh-failed';
type SessionListener = (event: SessionEvent, detail?: string) => void;

/**
 * Monitors responses during a scan for session expiry signals
 * and automatically re-authenticates when needed.
 */
export class SessionManager {
  private listeners: SessionListener[] = [];
  private refreshInProgress = false;
  private refreshCount = 0;
  private readonly maxRefreshes: number;

  /** HTTP status codes that indicate session expiry */
  private static readonly EXPIRY_STATUSES = new Set([401, 403]);

  /** Response body patterns that indicate session expiry (case-insensitive) */
  private static readonly EXPIRY_PATTERNS: RegExp[] = [
    /session\s*(has\s*)?expired/i,
    /token\s*(has\s*)?expired/i,
    /please\s*(re-?)?log\s*in/i,
    /authentication\s*required/i,
    /unauthorized/i,
    /not\s*authenticated/i,
    /login\s*required/i,
    /invalid\s*session/i,
    /session\s*timed?\s*out/i,
  ];

  /** URL path patterns that suggest a redirect to login */
  private static readonly LOGIN_REDIRECT_PATTERNS: RegExp[] = [
    /\/login/i,
    /\/signin/i,
    /\/sign-in/i,
    /\/auth\//i,
    /\/sso\//i,
    /\/login\.php/i,
    /\/wp-login/i,
  ];

  constructor(maxRefreshes = 3) {
    this.maxRefreshes = maxRefreshes;
  }

  /**
   * Check if a response indicates the browser was redirected to a login page.
   *
   * This handles the common case where Playwright follows redirects automatically,
   * so the response status is 200 but the final URL is a login page.
   *
   * Returns false if the original request was already to a login URL (to avoid
   * false positives when checks intentionally probe login pages).
   */
  isLoginPageResponse(requestUrl: string, responseUrl: string, body?: string): boolean {
    // If the request was already targeting a login page, ignore it
    if (SessionManager.LOGIN_REDIRECT_PATTERNS.some((p) => p.test(requestUrl))) {
      return false;
    }

    // If the response URL differs from request URL and matches a login pattern
    if (requestUrl !== responseUrl && SessionManager.LOGIN_REDIRECT_PATTERNS.some((p) => p.test(responseUrl))) {
      return true;
    }

    // Heuristic: response body contains a password input inside a form
    // (catches cases where redirect was followed and we got a 200 with login HTML)
    if (body && /<form\b/i.test(body) && /<input[^>]+type\s*=\s*["']password["']/i.test(body)) {
      // Only flag this if the URL also changed (otherwise we might be on a page
      // that legitimately has a form with a password field)
      if (requestUrl !== responseUrl) {
        return true;
      }
    }

    return false;
  }

  /** Expose login redirect patterns for use by SessionGuard */
  static get loginRedirectPatterns(): readonly RegExp[] {
    return SessionManager.LOGIN_REDIRECT_PATTERNS;
  }

  /** Expose expiry patterns for use by SessionGuard */
  static get expiryPatterns(): readonly RegExp[] {
    return SessionManager.EXPIRY_PATTERNS;
  }

  /**
   * Register a listener for session events.
   */
  on(listener: SessionListener): void {
    this.listeners.push(listener);
  }

  /**
   * Remove a previously-registered listener.
   */
  off(listener: SessionListener): void {
    this.listeners = this.listeners.filter((l) => l !== listener);
  }

  /**
   * Check if a response indicates the session has expired.
   */
  isSessionExpired(response: InterceptedResponse): boolean {
    // Check status code
    if (!SessionManager.EXPIRY_STATUSES.has(response.status)) {
      // Also check for 302/303 redirects to login pages
      if (response.status === 301 || response.status === 302 || response.status === 303) {
        const location = response.headers['location'] ?? '';
        if (SessionManager.LOGIN_REDIRECT_PATTERNS.some((p) => p.test(location))) {
          return true;
        }
      }
      return false;
    }

    // For 401, it's almost always session expiry
    if (response.status === 401) {
      return true;
    }

    // For 403, check body for session-expiry language (vs. regular authorization denial)
    if (response.body) {
      return SessionManager.EXPIRY_PATTERNS.some((p) => p.test(response.body!));
    }

    return false;
  }

  /**
   * Attempt to refresh the session by re-authenticating.
   *
   * Returns true if the refresh succeeded, false otherwise.
   * Emits 'session-refreshed' or 'session-refresh-failed' events.
   */
  async refreshSession(
    context: BrowserContext,
    authOptions: AuthOptions,
  ): Promise<boolean> {
    // Prevent concurrent refresh attempts
    if (this.refreshInProgress) {
      log.debug('Session refresh already in progress, skipping');
      return false;
    }

    // Enforce max refresh count
    if (this.refreshCount >= this.maxRefreshes) {
      log.warn(`Max session refreshes (${this.maxRefreshes}) reached — giving up`);
      this.emit('session-refresh-failed', 'Max refresh limit reached');
      return false;
    }

    this.refreshInProgress = true;

    try {
      log.info('Session expired — attempting re-authentication...');
      this.emit('session-expired');

      const page = await context.newPage();
      try {
        const result = await authenticate(page, authOptions);

        if (result.success) {
          this.refreshCount++;
          log.info(`Session refreshed successfully (refresh #${this.refreshCount})`);
          this.emit('session-refreshed', `Refresh #${this.refreshCount}`);
          return true;
        }

        log.warn(`Session refresh failed: ${result.error}`);
        this.emit('session-refresh-failed', result.error);
        return false;
      } finally {
        await page.close();
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log.error(`Session refresh error: ${message}`);
      this.emit('session-refresh-failed', message);
      return false;
    } finally {
      this.refreshInProgress = false;
    }
  }

  /** Number of times the session has been refreshed */
  get refreshes(): number {
    return this.refreshCount;
  }

  /** Whether a refresh is currently in progress */
  get isRefreshing(): boolean {
    return this.refreshInProgress;
  }

  private emit(event: SessionEvent, detail?: string): void {
    for (const listener of this.listeners) {
      try {
        listener(event, detail);
      } catch (err) {
        log.debug(`Session event listener error: ${(err as Error).message}`);
      }
    }
  }
}

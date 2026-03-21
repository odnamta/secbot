import type { BrowserContext, Response } from 'playwright';
import type { AuthOptions } from '../types.js';
import { SessionManager } from './session-manager.js';
import { log } from '../../utils/logger.js';

/**
 * SessionGuard monitors all browser responses during active scanning
 * and triggers re-authentication when session expiry is detected.
 *
 * It uses a consecutive-signal threshold to avoid false positives from
 * security checks that intentionally probe 401/403 endpoints.
 */
export class SessionGuard {
  private readonly context: BrowserContext;
  private readonly sessionManager: SessionManager;
  private readonly authOptions: AuthOptions | undefined;
  private readonly consecutiveThreshold: number;
  private consecutiveExpiryCount = 0;
  private responseHandler: ((response: Response) => void) | undefined;
  private warnedOnce = false;

  constructor(
    context: BrowserContext,
    sessionManager: SessionManager,
    authOptions?: AuthOptions,
    options?: { consecutiveThreshold?: number },
  ) {
    this.context = context;
    this.sessionManager = sessionManager;
    this.authOptions = authOptions;
    this.consecutiveThreshold = options?.consecutiveThreshold ?? 3;
  }

  /**
   * Attach the response listener to the browser context.
   * All responses will be monitored for session expiry signals.
   */
  attach(): void {
    if (this.responseHandler) {
      log.debug('SessionGuard already attached');
      return;
    }

    this.responseHandler = (response: Response) => {
      // Fire-and-forget — do not block the response pipeline
      this.handleResponse(response).catch((err) => {
        log.debug(`SessionGuard handler error: ${(err as Error).message}`);
      });
    };

    this.context.on('response', this.responseHandler);
    log.debug('SessionGuard attached — monitoring responses for session expiry');
  }

  /**
   * Detach the response listener from the browser context.
   */
  detach(): void {
    if (this.responseHandler) {
      this.context.off('response', this.responseHandler);
      this.responseHandler = undefined;
      log.debug('SessionGuard detached');
    }
  }

  /** Number of times the session has been refreshed */
  get refreshCount(): number {
    return this.sessionManager.refreshes;
  }

  private async handleResponse(response: Response): Promise<void> {
    const requestUrl = response.request().url();
    const responseUrl = response.url();
    const status = response.status();

    // Ignore responses to login URLs — these are expected
    if (SessionManager.loginRedirectPatterns.some((p) => p.test(requestUrl))) {
      return;
    }

    // Check for session expiry signals
    let isExpiry = false;

    // 1. Status-based: 401 or redirect to login page
    if (status === 401) {
      isExpiry = true;
    } else if (status === 302 || status === 303 || status === 301) {
      const location = response.headers()['location'] ?? '';
      if (SessionManager.loginRedirectPatterns.some((p) => p.test(location))) {
        isExpiry = true;
      }
    } else if (status === 403) {
      // For 403, only treat as expiry if body matches expiry patterns
      // (avoid false positives from authorization checks)
      try {
        const body = await response.text().catch(() => '');
        if (body && SessionManager.expiryPatterns.some((p) => p.test(body))) {
          isExpiry = true;
        }
      } catch {
        // Body not available — skip
      }
    }

    // 2. URL-based: response URL differs from request URL and matches login pattern
    if (!isExpiry && requestUrl !== responseUrl) {
      if (SessionManager.loginRedirectPatterns.some((p) => p.test(responseUrl))) {
        isExpiry = true;
      }
    }

    if (isExpiry) {
      this.consecutiveExpiryCount++;
      log.debug(`SessionGuard: expiry signal ${this.consecutiveExpiryCount}/${this.consecutiveThreshold} (${status} ${requestUrl})`);

      if (this.consecutiveExpiryCount >= this.consecutiveThreshold) {
        this.consecutiveExpiryCount = 0;
        await this.triggerRefresh();
      }
    } else if (status >= 200 && status < 300) {
      // Successful response — reset counter
      if (this.consecutiveExpiryCount > 0) {
        log.debug('SessionGuard: counter reset on successful response');
      }
      this.consecutiveExpiryCount = 0;
    }
  }

  private async triggerRefresh(): Promise<void> {
    if (!this.authOptions) {
      // No credentials available — warn once
      if (!this.warnedOnce) {
        log.warn('SessionGuard: session appears expired but no credentials available for re-authentication. Provide --login-url + --credentials for automatic session refresh.');
        this.warnedOnce = true;
      }
      return;
    }

    if (this.sessionManager.isRefreshing) {
      log.debug('SessionGuard: refresh already in progress, skipping');
      return;
    }

    log.info('SessionGuard: session expiry detected — triggering re-authentication...');
    const success = await this.sessionManager.refreshSession(this.context, this.authOptions);
    if (success) {
      log.info('SessionGuard: session refreshed successfully');
    } else {
      log.warn('SessionGuard: session refresh failed — subsequent requests may fail');
    }
  }
}

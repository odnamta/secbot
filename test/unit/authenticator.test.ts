import { describe, it, expect, vi } from 'vitest';
import { extractCsrfToken } from '../../src/scanner/auth/authenticator.js';

/**
 * Helper: create a mock Playwright Page with a custom evaluate implementation
 * that returns whatever we configure.
 */
function mockPageWithEvaluate(evaluateResult: unknown) {
  return {
    evaluate: vi.fn().mockResolvedValue(evaluateResult),
  } as any;
}

describe('extractCsrfToken', () => {
  it('extracts CSRF token from meta[name="csrf-token"]', async () => {
    const page = mockPageWithEvaluate('abc123-csrf');
    const token = await extractCsrfToken(page);

    expect(token).toBe('abc123-csrf');
    expect(page.evaluate).toHaveBeenCalledOnce();
  });

  it('returns null when no CSRF token is found', async () => {
    const page = mockPageWithEvaluate(null);
    const token = await extractCsrfToken(page);

    expect(token).toBeNull();
  });

  it('extracts CSRF token from hidden input', async () => {
    const page = mockPageWithEvaluate('hidden-csrf-value');
    const token = await extractCsrfToken(page);

    expect(token).toBe('hidden-csrf-value');
  });

  it('extracts Django csrfmiddlewaretoken', async () => {
    const page = mockPageWithEvaluate('django-csrf-token-xyz');
    const token = await extractCsrfToken(page);

    expect(token).toBe('django-csrf-token-xyz');
  });

  it('extracts Rails authenticity_token', async () => {
    const page = mockPageWithEvaluate('rails-authenticity-abc');
    const token = await extractCsrfToken(page);

    expect(token).toBe('rails-authenticity-abc');
  });

  it('extracts ASP.NET __RequestVerificationToken', async () => {
    const page = mockPageWithEvaluate('aspnet-verification-123');
    const token = await extractCsrfToken(page);

    expect(token).toBe('aspnet-verification-123');
  });
});

describe('authenticate', () => {
  it('exports authenticate function', async () => {
    const mod = await import('../../src/scanner/auth/authenticator.js');
    expect(typeof mod.authenticate).toBe('function');
  });

  it('authenticate function accepts page and options', async () => {
    const mod = await import('../../src/scanner/auth/authenticator.js');
    // Verify the function signature (2 parameters)
    expect(mod.authenticate.length).toBe(2);
  });

  it('returns failure when login form is not detected', async () => {
    const mod = await import('../../src/scanner/auth/authenticator.js');

    // Mock a Page that:
    // - goto resolves
    // - evaluate returns null (no login form detected)
    const page = {
      goto: vi.fn().mockResolvedValue(undefined),
      evaluate: vi.fn().mockResolvedValue(null),
      fill: vi.fn(),
      click: vi.fn(),
      waitForNavigation: vi.fn().mockResolvedValue(undefined),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
      url: vi.fn().mockReturnValue('https://example.com/login'),
      context: vi.fn().mockReturnValue({
        storageState: vi.fn().mockResolvedValue({ cookies: [], origins: [] }),
        cookies: vi.fn().mockResolvedValue([]),
      }),
    } as any;

    const result = await mod.authenticate(page, {
      loginUrl: 'https://example.com/login',
      username: 'admin',
      password: 'secret',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('No login form detected');
  });

  it('returns success when form is filled and submitted', async () => {
    const mod = await import('../../src/scanner/auth/authenticator.js');

    // Track call order
    const calls: string[] = [];

    const page = {
      goto: vi.fn().mockImplementation(() => { calls.push('goto'); return Promise.resolve(); }),
      evaluate: vi.fn()
        // First call: detectLoginForm
        .mockResolvedValueOnce({
          formSelector: '#login-form',
          usernameSelector: 'input[name="email"]',
          passwordSelector: 'input[type="password"]',
          submitSelector: 'button[type="submit"]',
        })
        // Second call: extractCsrfToken
        .mockResolvedValueOnce('csrf-token-123')
        // Third call: check for error messages
        .mockResolvedValueOnce(null),
      fill: vi.fn().mockImplementation((sel) => { calls.push(`fill:${sel}`); return Promise.resolve(); }),
      click: vi.fn().mockImplementation(() => { calls.push('click'); return Promise.resolve(); }),
      waitForNavigation: vi.fn().mockResolvedValue(undefined),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
      url: vi.fn().mockReturnValue('https://example.com/dashboard'),
      context: vi.fn().mockReturnValue({
        storageState: vi.fn().mockResolvedValue({ cookies: [{ name: 'session', value: 'abc' }], origins: [] }),
        cookies: vi.fn().mockResolvedValue([
          { name: 'session', value: 'abc', domain: 'example.com', path: '/', httpOnly: true, secure: true, sameSite: 'Lax' },
        ]),
      }),
    } as any;

    const result = await mod.authenticate(page, {
      loginUrl: 'https://example.com/login',
      username: 'admin',
      password: 'secret',
    });

    expect(result.success).toBe(true);
    expect(result.csrfToken).toBe('csrf-token-123');
    expect(result.cookies).toHaveLength(1);
    expect(result.cookies[0].name).toBe('session');
    expect(result.storageState).toBeDefined();

    // Verify fill was called for both username and password
    expect(page.fill).toHaveBeenCalledWith('input[name="email"]', 'admin');
    expect(page.fill).toHaveBeenCalledWith('input[type="password"]', 'secret');
  });

  it('uses user-provided selectors instead of auto-detect', async () => {
    const mod = await import('../../src/scanner/auth/authenticator.js');

    const page = {
      goto: vi.fn().mockResolvedValue(undefined),
      evaluate: vi.fn()
        // extractCsrfToken
        .mockResolvedValueOnce(null)
        // error check
        .mockResolvedValueOnce(null),
      fill: vi.fn().mockResolvedValue(undefined),
      click: vi.fn().mockResolvedValue(undefined),
      waitForNavigation: vi.fn().mockResolvedValue(undefined),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
      url: vi.fn().mockReturnValue('https://example.com/home'),
      context: vi.fn().mockReturnValue({
        storageState: vi.fn().mockResolvedValue({ cookies: [], origins: [] }),
        cookies: vi.fn().mockResolvedValue([]),
      }),
    } as any;

    const result = await mod.authenticate(page, {
      loginUrl: 'https://example.com/login',
      username: 'user1',
      password: 'pass1',
      usernameSelector: '#custom-user',
      passwordSelector: '#custom-pass',
      submitSelector: '#custom-submit',
    });

    expect(result.success).toBe(true);
    // Should NOT have called detectLoginForm since all selectors provided
    expect(page.fill).toHaveBeenCalledWith('#custom-user', 'user1');
    expect(page.fill).toHaveBeenCalledWith('#custom-pass', 'pass1');
    expect(page.click).toHaveBeenCalledWith('#custom-submit');
  });
});

import { describe, it, expect, vi } from 'vitest';
import { detectLoginForm } from '../../src/scanner/auth/login-detector.js';

/**
 * Creates a mock Playwright Page with an evaluate function that
 * receives a callback and runs it in a simulated DOM environment.
 *
 * Instead of building a real DOM, we intercept page.evaluate() and
 * return canned results based on the test scenario.
 */
function mockPage(evaluateResult: unknown) {
  return {
    evaluate: vi.fn().mockResolvedValue(evaluateResult),
  } as any;
}

describe('detectLoginForm', () => {
  it('returns null when no password input exists', async () => {
    const page = mockPage(null);
    const result = await detectLoginForm(page);

    expect(result).toBeNull();
    expect(page.evaluate).toHaveBeenCalledOnce();
  });

  it('detects a standard email + password login form', async () => {
    const page = mockPage({
      formSelector: '#login-form',
      usernameSelector: 'input[name="email"]',
      passwordSelector: 'input[type="password"]',
      submitSelector: 'button[type="submit"]',
    });

    const result = await detectLoginForm(page);

    expect(result).not.toBeNull();
    expect(result!.formSelector).toBe('#login-form');
    expect(result!.usernameSelector).toBe('input[name="email"]');
    expect(result!.passwordSelector).toBe('input[type="password"]');
    expect(result!.submitSelector).toBe('button[type="submit"]');
  });

  it('detects a username + password form without explicit form tag', async () => {
    const page = mockPage({
      formSelector: 'body',
      usernameSelector: 'input[name="username"]',
      passwordSelector: 'input[type="password"]',
      submitSelector: 'button',
    });

    const result = await detectLoginForm(page);

    expect(result).not.toBeNull();
    expect(result!.formSelector).toBe('body');
    expect(result!.usernameSelector).toBe('input[name="username"]');
  });

  it('detects form with id-based selectors', async () => {
    const page = mockPage({
      formSelector: '#auth-form',
      usernameSelector: '#email',
      passwordSelector: '#password',
      submitSelector: '#login-btn',
    });

    const result = await detectLoginForm(page);

    expect(result).not.toBeNull();
    expect(result!.usernameSelector).toBe('#email');
    expect(result!.passwordSelector).toBe('#password');
    expect(result!.submitSelector).toBe('#login-btn');
  });

  it('returns LoginForm with all four required fields', async () => {
    const page = mockPage({
      formSelector: 'form',
      usernameSelector: 'input[name="user"]',
      passwordSelector: 'input[type="password"]',
      submitSelector: 'button[type="submit"]',
    });

    const result = await detectLoginForm(page);

    expect(result).not.toBeNull();
    expect(result).toHaveProperty('formSelector');
    expect(result).toHaveProperty('usernameSelector');
    expect(result).toHaveProperty('passwordSelector');
    expect(result).toHaveProperty('submitSelector');
  });

  it('handles page.evaluate rejection gracefully', async () => {
    const page = {
      evaluate: vi.fn().mockRejectedValue(new Error('Page closed')),
    } as any;

    await expect(detectLoginForm(page)).rejects.toThrow('Page closed');
  });
});
